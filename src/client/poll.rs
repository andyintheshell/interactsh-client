use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct RegisterRequest {
    #[serde(rename = "public-key")]
    pub public_key: String,
    #[serde(rename = "secret-key")]
    pub secret_key: String,
    #[serde(rename = "correlation-id")]
    pub correlation_id: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PollResponse {
    #[serde(default, deserialize_with = "deserialize_default_vec")]
    pub interactions: Vec<RawInteraction>,
    #[serde(default, deserialize_with = "deserialize_default_vec")]
    pub data: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_raw_interactions")]
    pub extra: Vec<RawInteraction>,
    #[serde(
        default,
        rename = "tlddata",
        deserialize_with = "deserialize_raw_interactions"
    )]
    pub tld_data: Vec<RawInteraction>,
    #[serde(default)]
    pub aes_key: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RawInteraction {
    #[serde(rename = "full-id")]
    pub full_id: String,
    pub protocol: String,
    #[serde(rename = "unique-id")]
    pub unique_id: String,
    pub timestamp: String,
    #[serde(rename = "raw-request")]
    pub raw_request: Option<String>,
    #[serde(rename = "raw-response")]
    pub raw_response: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawOrString {
    Raw(RawInteraction),
    Str(String),
}

pub(crate) fn deserialize_raw_interactions<'de, D>(
    deserializer: D,
) -> std::result::Result<Vec<RawInteraction>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let values = Option::<Vec<RawOrString>>::deserialize(deserializer)?.unwrap_or_default();
    values
        .into_iter()
        .map(|item| match item {
            RawOrString::Raw(raw) => Ok(raw),
            RawOrString::Str(s) => serde_json::from_str(&s).map_err(serde::de::Error::custom),
        })
        .collect()
}

pub(crate) fn deserialize_default_vec<'de, D, T>(
    deserializer: D,
) -> std::result::Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(deserializer)?.unwrap_or_default())
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poll_response_deserializes_extra_objects_and_strings() {
        let raw_obj = r#"{"full-id":"cid123","protocol":"http","unique-id":"cid123","timestamp":"2026-08-07T00:00:00Z"}"#;
        let json = format!(
            r#"{{"interactions":[],"extra":[{},"{}"],"tlddata":[{}]}}"#,
            raw_obj,
            raw_obj.replace('"', "\\\""),
            raw_obj
        );
        let resp: PollResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(resp.extra.len(), 2);
        assert_eq!(resp.tld_data.len(), 1);
        assert_eq!(resp.extra[0].full_id, "cid123");
        assert_eq!(resp.extra[1].full_id, "cid123");
        assert_eq!(resp.tld_data[0].full_id, "cid123");
    }
}
