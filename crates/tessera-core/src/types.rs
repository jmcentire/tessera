use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A complete Tessera document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Document {
    /// Format version string (e.g. "0.1")
    pub tessera: String,

    /// Schema: field definitions, mutation rules, guards
    pub schema: Schema,

    /// API: what operations the engine exposes
    pub api: ApiSpec,

    /// Current application state
    pub state: State,

    /// Mutation history (embedded chain mode)
    #[serde(default)]
    pub chain: Vec<Mutation>,

    /// How history is stored
    pub chain_mode: ChainMode,

    /// Ed25519 public key of the document authority (hex-encoded)
    pub pubkey: String,

    /// Ed25519 signature over the canonical document (hex-encoded)
    pub signature: String,
}

/// How the document's history is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChainMode {
    /// Self-contained, no history
    Stateless,
    /// Contains prev_hash only; history lives elsewhere
    Referenced,
    /// Full history included in the document
    Embedded,
}

/// Schema: declares the document's structure and rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Schema {
    /// Field definitions: name -> type descriptor
    pub fields: BTreeMap<String, FieldDef>,

    /// Mutation definitions: name -> mutation descriptor
    #[serde(default)]
    pub mutations: BTreeMap<String, MutationDef>,

    /// Embedded validator code (readable, signed with the document).
    /// Contains function definitions callable by mutation validators.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

/// Definition of a single field in the schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldDef {
    /// Type of this field
    #[serde(rename = "type")]
    pub field_type: FieldType,

    /// Default value (optional)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<Value>,
}

/// Supported field types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FieldType {
    Bool,
    U64,
    I64,
    String,
    Bytes,
    Array(Box<FieldType>),
    Map(Box<FieldType>, Box<FieldType>),
    Object(BTreeMap<String, FieldDef>),
}

/// A value in the document state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Value {
    Bool(bool),
    U64(u64),
    I64(i64),
    String(String),
    Bytes(Vec<u8>),
    Array(Vec<Value>),
    Map(BTreeMap<String, Value>),
}

impl Value {
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Bool(_) => "bool",
            Value::U64(_) => "u64",
            Value::I64(_) => "i64",
            Value::String(_) => "string",
            Value::Bytes(_) => "bytes",
            Value::Array(_) => "array",
            Value::Map(_) => "map",
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::U64(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::I64(v) => Some(*v),
            // u64 values that fit in i64
            Value::U64(v) => i64::try_from(*v).ok(),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(v) => Some(v),
            _ => None,
        }
    }
}

/// Application state: a map of field names to values.
pub type State = BTreeMap<String, Value>;

/// Definition of a mutation type in the schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutationDef {
    /// Guard expressions that must evaluate to true for this mutation to apply
    #[serde(default)]
    pub guards: Vec<String>,

    /// Effects: how state changes when this mutation is applied.
    /// Used for simple mutations. Ignored when `validator` is set.
    #[serde(default)]
    pub effects: BTreeMap<String, String>,

    /// Arguments this mutation accepts
    #[serde(default)]
    pub args: BTreeMap<String, FieldType>,

    /// Name of the validator function in schema.code to call.
    /// When set, the validator computes the new state instead of effects.
    /// The function signature is: fn name(state, args) -> new_state
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validator: Option<String>,
}

/// A single mutation in the chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mutation {
    /// SHA-256 of the state before this mutation (hex-encoded)
    pub prev_hash: String,

    /// The operation performed
    pub op: Operation,

    /// SHA-256 of the state after this mutation (hex-encoded)
    pub next_hash: String,

    /// Ed25519 public key of the actor (hex-encoded)
    pub actor: String,

    /// Ed25519 signature by the actor (hex-encoded)
    pub sig: String,

    /// Unix epoch seconds (informational, not trusted for security)
    pub timestamp: u64,
}

/// An operation within a mutation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Operation {
    /// Mutation type name (must match a key in schema.mutations)
    #[serde(rename = "type")]
    pub op_type: String,

    /// Arguments to the mutation
    #[serde(default)]
    pub args: BTreeMap<String, Value>,
}

/// API specification: what the engine exposes to presentation layers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiSpec {
    /// Fields available for reading
    #[serde(default)]
    pub read: Vec<String>,

    /// Mutation names available for writing
    #[serde(default)]
    pub write: Vec<String>,
}

/// A checkpoint: signed state snapshot at a specific point in the chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Index in the chain where this checkpoint was taken
    pub chain_index: usize,

    /// SHA-256 of the state at this point (hex-encoded)
    pub state_hash: String,

    /// The state at this point
    pub state: State,

    /// Ed25519 public key of the checkpoint signer (hex-encoded)
    pub signer: String,

    /// Ed25519 signature over (chain_index || state_hash) (hex-encoded)
    pub sig: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_mode_serializes_lowercase() {
        let json = serde_json::to_string(&ChainMode::Embedded).unwrap();
        assert_eq!(json, "\"embedded\"");

        let json = serde_json::to_string(&ChainMode::Stateless).unwrap();
        assert_eq!(json, "\"stateless\"");

        let json = serde_json::to_string(&ChainMode::Referenced).unwrap();
        assert_eq!(json, "\"referenced\"");
    }

    #[test]
    fn chain_mode_deserializes() {
        let mode: ChainMode = serde_json::from_str("\"embedded\"").unwrap();
        assert_eq!(mode, ChainMode::Embedded);
    }

    #[test]
    fn value_type_names() {
        assert_eq!(Value::Bool(true).type_name(), "bool");
        assert_eq!(Value::U64(42).type_name(), "u64");
        assert_eq!(Value::I64(-1).type_name(), "i64");
        assert_eq!(Value::String("hi".into()).type_name(), "string");
    }

    #[test]
    fn value_conversions() {
        assert_eq!(Value::U64(42).as_u64(), Some(42));
        assert_eq!(Value::U64(42).as_i64(), Some(42));
        assert_eq!(Value::I64(-5).as_i64(), Some(-5));
        assert_eq!(Value::Bool(true).as_bool(), Some(true));
        assert_eq!(Value::String("hi".into()).as_str(), Some("hi"));
        assert_eq!(Value::Bool(true).as_u64(), None);
    }

    #[test]
    fn schema_round_trip() {
        let schema = Schema {
            fields: {
                let mut m = BTreeMap::new();
                m.insert(
                    "count".into(),
                    FieldDef {
                        field_type: FieldType::U64,
                        default: Some(Value::U64(0)),
                    },
                );
                m
            },
            mutations: {
                let mut m = BTreeMap::new();
                m.insert(
                    "increment".into(),
                    MutationDef {
                        guards: vec!["count < 1000".into()],
                        effects: {
                            let mut e = BTreeMap::new();
                            e.insert("count".into(), "count + 1".into());
                            e
                        },
                        args: BTreeMap::new(),
                        validator: None,
                    },
                );
                m
            },
            code: None,
        };

        let json = serde_json::to_string_pretty(&schema).unwrap();
        let parsed: Schema = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.fields.len(), 1);
        assert_eq!(parsed.mutations.len(), 1);
        assert!(parsed.mutations.contains_key("increment"));
    }

    #[test]
    fn operation_round_trip() {
        let op = Operation {
            op_type: "increment".into(),
            args: BTreeMap::new(),
        };
        let json = serde_json::to_string(&op).unwrap();
        let parsed: Operation = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.op_type, "increment");
    }

    #[test]
    fn api_spec_round_trip() {
        let api = ApiSpec {
            read: vec!["count".into()],
            write: vec!["increment".into(), "decrement".into()],
        };
        let json = serde_json::to_string(&api).unwrap();
        let parsed: ApiSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.read, vec!["count"]);
        assert_eq!(parsed.write.len(), 2);
    }
}
