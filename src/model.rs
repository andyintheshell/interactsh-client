#![allow(missing_docs)]
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Logical metadata attached to a generated interactsh URL.
///
/// # Thread Safety
/// `InteractionContext` is `Send` and `Sync`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InteractionContext {
    pub label: String,
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
}

impl InteractionContext {
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            attributes: BTreeMap::new(),
        }
    }

    pub fn builder(label: impl Into<String>) -> InteractionContextBuilder {
        InteractionContextBuilder::new(label)
    }

    pub fn with_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }
}

impl std::fmt::Display for InteractionContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.label, self.attributes.len())
    }
}

impl From<&str> for InteractionContext {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for InteractionContext {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

/// Builder for [`InteractionContext`].
///
/// # Thread Safety
/// `InteractionContextBuilder` is `Send` and `Sync`.
pub struct InteractionContextBuilder {
    context: InteractionContext,
}

impl InteractionContextBuilder {
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            context: InteractionContext::new(label),
        }
    }

    pub fn attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.context.attributes.insert(key.into(), value.into());
        self
    }

    pub fn build(self) -> InteractionContext {
        self.context
    }
}

impl std::fmt::Display for InteractionContextBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "InteractionContextBuilder({})", self.context)
    }
}

/// Generated interactsh URL plus the local nonce used for correlation.
///
/// # Thread Safety
/// `GeneratedUrl` is `Send` and `Sync`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratedUrl {
    pub url: String,
    pub nonce: String,
}

impl std::fmt::Display for GeneratedUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.url)
    }
}

/// A raw interaction event returned by the interactsh service.
///
/// # Thread Safety
/// `InteractionEvent` is `Send` and `Sync`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InteractionEvent {
    pub full_id: String,
    pub protocol: String,
    pub unique_id: String,
    pub timestamp: String,
    pub raw_request: Option<String>,
    pub raw_response: Option<String>,
}

impl std::fmt::Display for InteractionEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.protocol, self.full_id)
    }
}

/// An interactsh event correlated back to the user-provided request context.
///
/// # Thread Safety
/// `CorrelatedInteraction` is `Send` and `Sync`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorrelatedInteraction {
    pub context: InteractionContext,
    pub event: InteractionEvent,
}

impl std::fmt::Display for CorrelatedInteraction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} -> {}", self.context, self.event)
    }
}
