//! Metadata-only 1Password inventory for Agent Browser custom plugin calls.
//!
//! Return strictly allowlisted fields, never raw CLI JSON.

use super::{https_origin, op_output};
use serde_json::{json, Map, Value};
use std::time::Duration;

const INVENTORY_TIMEOUT: Duration = Duration::from_secs(12);
const MAX_INVENTORY_BYTES: usize = 4 * 1024 * 1024;
const MAX_PAGE_SIZE: usize = 200;
const MAX_OFFSET: usize = 100_000;
const MAX_QUERY_CHARS: usize = 120;
const MAX_LABEL_CHARS: usize = 200;

struct Page {
    limit: usize,
    offset: usize,
}

fn request_fields<'a>(
    request: &'a Value,
    allowed: &[&str],
) -> Result<&'a Map<String, Value>, ()> {
    let fields = request.as_object().ok_or(())?;
    if !fields.keys().all(|key| allowed.contains(&key.as_str())) {
        return Err(());
    }
    Ok(fields)
}

fn page(fields: &Map<String, Value>) -> Result<Page, ()> {
    let limit = match fields.get("limit") {
        Some(value) => usize::try_from(value.as_u64().ok_or(())?).map_err(|_| ())?,
        None => 50,
    };
    let offset = match fields.get("offset") {
        Some(value) => usize::try_from(value.as_u64().ok_or(())?).map_err(|_| ())?,
        None => 0,
    };
    if limit == 0 || limit > MAX_PAGE_SIZE || offset > MAX_OFFSET {
        return Err(());
    }
    Ok(Page { limit, offset })
}

fn query(fields: &Map<String, Value>) -> Result<Option<String>, ()> {
    match fields.get("query") {
        None => Ok(None),
        Some(value) => {
            let raw = value.as_str().ok_or(())?.trim();
            if raw.is_empty() || raw.chars().count() > MAX_QUERY_CHARS {
                return Err(());
            }
            Ok(Some(raw.to_lowercase()))
        }
    }
}

fn optional_vault_id(fields: &Map<String, Value>) -> Result<Option<&str>, ()> {
    match fields.get("vaultId") {
        None => Ok(None),
        Some(value) => {
            let id = value.as_str().ok_or(())?;
            if !valid_id(id) {
                return Err(());
            }
            Ok(Some(id))
        }
    }
}

fn optional_category(fields: &Map<String, Value>) -> Result<Option<String>, ()> {
    match fields.get("category") {
        None => Ok(None),
        Some(value) => {
            let cat = value.as_str().ok_or(())?.trim();
            if cat.is_empty()
                || cat.len() > 64
                || !cat
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
            {
                return Err(());
            }
            Ok(Some(cat.to_ascii_lowercase()))
        }
    }
}

fn optional_origin(fields: &Map<String, Value>) -> Result<Option<String>, ()> {
    fields
        .get("origin")
        .map(|value| https_origin(value.as_str().ok_or(())?))
        .transpose()
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

fn label(value: Option<&str>) -> String {
    value
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_LABEL_CHARS)
        .collect()
}

fn inventory(args: &[&str]) -> Result<Vec<Value>, ()> {
    let output = op_output(args, INVENTORY_TIMEOUT, MAX_INVENTORY_BYTES)?;
    serde_json::from_slice::<Value>(&output)
        .map_err(|_| ())?
        .as_array()
        .cloned()
        .ok_or(())
}

fn finish(mut rows: Vec<Value>, paging: Page, kind: &str) -> Value {
    rows.sort_by(|left, right| {
        let left_title = left.get("name").or_else(|| left.get("title"));
        let right_title = right.get("name").or_else(|| right.get("title"));
        let key = |title: Option<&Value>, row: &Value| {
            (
                title
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_lowercase(),
                row.get("id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
            )
        };
        key(left_title, left).cmp(&key(right_title, right))
    });
    let total = rows.len();
    let next = paging.offset.saturating_add(paging.limit);
    let next_offset = (next < total).then_some(next);
    let selected: Vec<Value> = rows
        .into_iter()
        .skip(paging.offset)
        .take(paging.limit)
        .collect();
    let mut data = json!({
        "total": total,
        "limit": paging.limit,
        "offset": paging.offset,
        "nextOffset": next_offset
    });
    data[kind] = json!(selected);
    json!({
        "protocol": "agent-browser.plugin.v1",
        "success": true,
        "data": data
    })
}

pub fn list_vaults(request: &Value) -> Result<Value, ()> {
    let fields = request_fields(request, &["limit", "offset", "query"])?;
    let paging = page(fields)?;
    let query = query(fields)?;
    let rows = inventory(&["vault", "list", "--format", "json"])?;
    let safe = rows
        .iter()
        .filter_map(|row| {
            let id = row.get("id")?.as_str()?;
            if !valid_id(id) {
                return None;
            }
            let name = label(row.get("name").and_then(Value::as_str));
            if query
                .as_ref()
                .is_some_and(|term| !name.to_lowercase().contains(term))
            {
                return None;
            }
            Some(json!({
                "id": id,
                "name": name,
                "type": label(row.get("type").and_then(Value::as_str))
            }))
        })
        .collect();
    Ok(finish(safe, paging, "vaults"))
}

fn origins(row: &Value) -> Vec<String> {
    let mut found: Vec<String> = row
        .get("urls")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.get("href").and_then(Value::as_str))
        .filter_map(|url| https_origin(url).ok())
        .collect();
    found.sort();
    found.dedup();
    found
}

pub fn list_items(request: &Value) -> Result<Value, ()> {
    let fields = request_fields(
        request,
        &["vaultId", "category", "origin", "query", "limit", "offset"],
    )?;
    let paging = page(fields)?;
    let vault_id = optional_vault_id(fields)?;
    let category = optional_category(fields)?;
    let origin = optional_origin(fields)?;
    let query = query(fields)?;
    // Item list returns metadata; this path NEVER calls item get.
    let rows = inventory(&["item", "list", "--format", "json"])?;
    let safe = rows
        .iter()
        .filter_map(|row| {
            let id = row.get("id")?.as_str()?;
            if !valid_id(id) {
                return None;
            }
            let vault = row.get("vault")?;
            let item_vault_id = vault.get("id")?.as_str()?;
            if !valid_id(item_vault_id) || vault_id.is_some_and(|v| v != item_vault_id) {
                return None;
            }
            let item_category = label(row.get("category").and_then(Value::as_str));
            if category
                .as_ref()
                .is_some_and(|expected| item_category.to_ascii_lowercase() != *expected)
            {
                return None;
            }
            let title = label(row.get("title").and_then(Value::as_str));
            if query
                .as_ref()
                .is_some_and(|term| !title.to_lowercase().contains(term))
            {
                return None;
            }
            let website_origins = origins(row);
            if origin
                .as_ref()
                .is_some_and(|expected| !website_origins.contains(expected))
            {
                return None;
            }
            Some(json!({
                "id": id,
                "title": title,
                "category": item_category,
                "vault": {
                    "id": item_vault_id,
                    "name": label(vault.get("name").and_then(Value::as_str))
                },
                "websiteOrigins": website_origins
            }))
        })
        .collect();
    Ok(finish(safe, paging, "items"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_inventory_requests() {
        for request in [
            json!({"limit": 0}),
            json!({"limit": 201}),
            json!({"offset": -1}),
            json!({"query": ""}),
            json!({"vaultId": "not a vault"}),
            json!({"origin": "http://example.org"}),
            json!({"extra": "not allowed"}),
        ] {
            let result = if request.get("vaultId").is_some()
                || request.get("origin").is_some()
                || request.get("extra").is_some()
            {
                list_items(&request)
            } else {
                list_vaults(&request)
            };
            assert!(result.is_err());
        }
    }

    #[test]
    fn never_include_query_strings_in_website_origins() {
        let item = json!({"urls":[
            {"href":"https://EXAMPLE.com/login?secret=FAKE-NEVER-LEAK"},
            {"href":"https://example.com/other"},
            {"href":"http://example.org/private"}
        ]});
        assert_eq!(origins(&item), vec!["https://example.com"]);
    }
}
