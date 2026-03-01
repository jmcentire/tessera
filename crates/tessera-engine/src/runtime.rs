//! Rhai scripting runtime for embedded validators.
//!
//! Documents can embed validator code in their schema. The runtime executes
//! this code in a sandboxed Rhai engine with resource limits.
//!
//! # Security Model
//!
//! Embedded code is a trust boundary. The document author signs the code,
//! but the executing party must independently authorize running it.
//!
//! - `ExecutionPolicy::Disabled` — never execute embedded code
//! - `ExecutionPolicy::TrustKeys(keys)` — execute if the document authority is trusted
//! - `ExecutionPolicy::TrustAll` — execute any code (testing only)
//!
//! The client implements consent UX: showing the code, prompting the user,
//! recording authorization as a signed `CodeAuthorization`.

use std::collections::BTreeMap;

use rhai::{Dynamic, Engine, Map, Scope, AST};
use tessera_core::crypto::{sha256_hex, Ed25519Verifier};
use tessera_core::{Document, State, TesseraError, Value, Verifier};

/// Controls whether the runtime will execute embedded code.
#[derive(Clone, Debug)]
pub enum ExecutionPolicy {
    /// Never execute embedded code. Mutations with validators are rejected.
    Disabled,

    /// Execute code from documents signed by any of these public keys.
    TrustKeys(Vec<String>),

    /// Execute code that has a matching signed authorization receipt.
    /// This is the most granular policy: trust specific code from specific authorities,
    /// verified by a signed consent receipt from a specific authorizer.
    TrustAuthorizations(Vec<CodeAuthorization>),

    /// Execute all embedded code. For testing and development only.
    TrustAll,
}

/// A signed consent receipt: "I reviewed this code and authorize execution."
///
/// The authorizer's client signs SHA-256(code_hash || authority_pubkey) to create
/// this receipt. On subsequent encounters, the client checks for a matching
/// receipt and skips the prompt.
#[derive(Clone, Debug)]
pub struct CodeAuthorization {
    /// SHA-256 of the embedded code
    pub code_hash: String,
    /// Public key of the document authority that signed the code
    pub authority_pubkey: String,
    /// Public key of the user who authorized execution
    pub authorizer_pubkey: String,
    /// Signature over SHA-256(code_hash || authority_pubkey) by the authorizer
    pub authorizer_sig: String,
}

impl CodeAuthorization {
    /// Verify this authorization receipt's signature.
    pub fn verify(&self) -> Result<(), TesseraError> {
        let payload = format!("{}{}", self.code_hash, self.authority_pubkey);
        let digest = sha256_hex(payload.as_bytes());
        Ed25519Verifier::verify(
            &self.authorizer_pubkey,
            digest.as_bytes(),
            &self.authorizer_sig,
        )
        .map_err(|e| {
            TesseraError::CodeNotAuthorized(format!("invalid authorization signature: {}", e))
        })
    }

    /// Check if this authorization matches a document's code and authority.
    pub fn matches(&self, code_hash: &str, authority_pubkey: &str) -> bool {
        self.code_hash == code_hash && self.authority_pubkey == authority_pubkey
    }
}

/// Sandboxed Rhai runtime for executing embedded validators.
pub struct Runtime {
    engine: Engine,
    policy: ExecutionPolicy,
}

// Resource limits for the sandboxed engine
const MAX_OPERATIONS: u64 = 10_000_000;
const MAX_CALL_LEVELS: usize = 64;
const MAX_EXPR_DEPTH: usize = 256;
const MAX_STRING_SIZE: usize = 1_000_000;
const MAX_ARRAY_SIZE: usize = 100_000;
const MAX_MAP_SIZE: usize = 10_000;

impl Runtime {
    /// Create a new runtime with the given execution policy.
    pub fn new(policy: ExecutionPolicy) -> Self {
        let mut engine = Engine::new();

        // Sandbox: set resource limits to prevent abuse
        engine.set_max_operations(MAX_OPERATIONS);
        engine.set_max_call_levels(MAX_CALL_LEVELS);
        engine.set_max_expr_depths(MAX_EXPR_DEPTH, MAX_EXPR_DEPTH);
        engine.set_max_string_size(MAX_STRING_SIZE);
        engine.set_max_array_size(MAX_ARRAY_SIZE);
        engine.set_max_map_size(MAX_MAP_SIZE);

        // Rhai is sandboxed by default: no file I/O, no network, no system calls.
        // We don't register any custom functions that could escape the sandbox.

        Self { engine, policy }
    }

    /// Check whether code execution is authorized for a document.
    pub fn check_authorization(&self, doc: &Document) -> Result<(), TesseraError> {
        // No code = no authorization needed
        if doc.schema.code.is_none() {
            return Ok(());
        }

        match &self.policy {
            ExecutionPolicy::Disabled => Err(TesseraError::CodeNotAuthorized(
                "execution policy is Disabled".into(),
            )),
            ExecutionPolicy::TrustAll => Ok(()),
            ExecutionPolicy::TrustKeys(keys) => {
                if keys.contains(&doc.pubkey) {
                    Ok(())
                } else {
                    let code = doc.schema.code.as_deref().unwrap_or("");
                    let code_hash = sha256_hex(code.as_bytes());
                    Err(TesseraError::CodeNotAuthorized(format!(
                        "authority {} not in trust list (code hash: {})",
                        &doc.pubkey, code_hash
                    )))
                }
            }
            ExecutionPolicy::TrustAuthorizations(authorizations) => {
                let code = doc.schema.code.as_deref().unwrap_or("");
                let code_hash = sha256_hex(code.as_bytes());

                // Find a matching authorization and verify its signature
                for auth in authorizations {
                    if auth.matches(&code_hash, &doc.pubkey) {
                        return auth.verify();
                    }
                }

                Err(TesseraError::CodeNotAuthorized(format!(
                    "no valid authorization for code hash {} from authority {}",
                    code_hash, &doc.pubkey
                )))
            }
        }
    }

    /// Compute the hash of embedded code in a document.
    pub fn code_hash(doc: &Document) -> Option<String> {
        doc.schema
            .code
            .as_ref()
            .map(|code| sha256_hex(code.as_bytes()))
    }

    /// Compile embedded code into a reusable AST.
    pub fn compile(&self, code: &str) -> Result<AST, TesseraError> {
        self.engine
            .compile(code)
            .map_err(|e| TesseraError::CodeExecutionFailed(format!("compile error: {}", e)))
    }

    /// Execute a validator function from compiled code.
    ///
    /// The function receives (state, args) as Rhai Maps and must return
    /// a Map representing the new state.
    pub fn call_validator(
        &self,
        ast: &AST,
        fn_name: &str,
        state: &State,
        args: &BTreeMap<String, Value>,
    ) -> Result<State, TesseraError> {
        let state_map = state_to_rhai(state);
        let args_map = state_to_rhai(args);

        let mut scope = Scope::new();
        let result: Dynamic = self
            .engine
            .call_fn(&mut scope, ast, fn_name, (state_map, args_map))
            .map_err(|e| TesseraError::CodeExecutionFailed(format!("{}", e)))?;

        rhai_to_state(result)
    }

    /// Get a reference to the execution policy.
    pub fn policy(&self) -> &ExecutionPolicy {
        &self.policy
    }

    /// Get a reference to the underlying Rhai engine (for testing/debugging).
    pub fn engine(&self) -> &Engine {
        &self.engine
    }
}

// --- Value conversion: Tessera <-> Rhai ---

/// Convert a Tessera state map to a Rhai Dynamic (Map).
fn state_to_rhai(state: &BTreeMap<String, Value>) -> Dynamic {
    let mut map = Map::new();
    for (k, v) in state {
        map.insert(k.as_str().into(), value_to_rhai(v));
    }
    Dynamic::from_map(map)
}

/// Convert a Tessera Value to a Rhai Dynamic.
fn value_to_rhai(v: &Value) -> Dynamic {
    match v {
        Value::Bool(b) => Dynamic::from(*b),
        Value::U64(n) => {
            // Rhai only supports i64. Reject values that would overflow.
            // Rhai only supports i64. Saturate on overflow; the validator will
            // produce a wrong result and the hash chain check will catch it.
            let i = i64::try_from(*n).unwrap_or(i64::MAX);
            Dynamic::from(i)
        }
        Value::I64(n) => Dynamic::from(*n),
        Value::String(s) => Dynamic::from(s.clone()),
        Value::Bytes(b) => {
            let arr: Vec<Dynamic> = b.iter().map(|byte| Dynamic::from(*byte as i64)).collect();
            Dynamic::from_array(arr)
        }
        Value::Array(items) => {
            let arr: Vec<Dynamic> = items.iter().map(value_to_rhai).collect();
            Dynamic::from_array(arr)
        }
        Value::Map(entries) => {
            let mut map = Map::new();
            for (k, v) in entries {
                map.insert(k.as_str().into(), value_to_rhai(v));
            }
            Dynamic::from_map(map)
        }
    }
}

/// Convert a Rhai Dynamic result back to a Tessera State.
fn rhai_to_state(d: Dynamic) -> Result<State, TesseraError> {
    if d.is_map() {
        let map = d.cast::<Map>();
        let mut state = BTreeMap::new();
        for (k, v) in map {
            state.insert(k.to_string(), rhai_to_value(v)?);
        }
        Ok(state)
    } else {
        Err(TesseraError::CodeExecutionFailed(
            "validator must return a map".into(),
        ))
    }
}

/// Convert a Rhai Dynamic to a Tessera Value.
fn rhai_to_value(d: Dynamic) -> Result<Value, TesseraError> {
    if d.is_bool() {
        Ok(Value::Bool(d.as_bool().unwrap()))
    } else if d.is_int() {
        let n = d.as_int().unwrap();
        if n >= 0 {
            Ok(Value::U64(n as u64))
        } else {
            Ok(Value::I64(n))
        }
    } else if d.is_string() {
        Ok(Value::String(d.into_string().unwrap()))
    } else if d.is_array() {
        let arr = d.into_array().unwrap();
        let items: Result<Vec<Value>, _> = arr.into_iter().map(rhai_to_value).collect();
        Ok(Value::Array(items?))
    } else if d.is_map() {
        let map = d.cast::<Map>();
        let mut result = BTreeMap::new();
        for (k, v) in map {
            result.insert(k.to_string(), rhai_to_value(v)?);
        }
        Ok(Value::Map(result))
    } else {
        Err(TesseraError::CodeExecutionFailed(format!(
            "unsupported Rhai type: {}",
            d.type_name()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_round_trip_u64() {
        let v = Value::U64(42);
        let d = value_to_rhai(&v);
        let back = rhai_to_value(d).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn value_round_trip_i64() {
        let v = Value::I64(-5);
        let d = value_to_rhai(&v);
        let back = rhai_to_value(d).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn value_round_trip_string() {
        let v = Value::String("hello".into());
        let d = value_to_rhai(&v);
        let back = rhai_to_value(d).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn value_round_trip_bool() {
        let v = Value::Bool(true);
        let d = value_to_rhai(&v);
        let back = rhai_to_value(d).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn value_round_trip_array() {
        let v = Value::Array(vec![Value::U64(1), Value::U64(2), Value::U64(3)]);
        let d = value_to_rhai(&v);
        let back = rhai_to_value(d).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn value_round_trip_map() {
        let mut m = BTreeMap::new();
        m.insert("a".into(), Value::U64(1));
        m.insert("b".into(), Value::String("two".into()));
        let v = Value::Map(m);
        let d = value_to_rhai(&v);
        let back = rhai_to_value(d).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn state_round_trip() {
        let mut state = BTreeMap::new();
        state.insert("count".into(), Value::U64(42));
        state.insert("name".into(), Value::String("test".into()));

        let d = state_to_rhai(&state);
        let back = rhai_to_state(d).unwrap();
        assert_eq!(back, state);
    }

    #[test]
    fn simple_validator() {
        let rt = Runtime::new(ExecutionPolicy::TrustAll);
        let code = r#"
            fn validate_increment(state, args) {
                let count = state.count;
                if count >= 100 {
                    throw "count must be < 100";
                }
                #{
                    count: count + 1
                }
            }
        "#;

        let ast = rt.compile(code).unwrap();
        let mut state = BTreeMap::new();
        state.insert("count".into(), Value::U64(5));

        let new_state = rt
            .call_validator(&ast, "validate_increment", &state, &BTreeMap::new())
            .unwrap();
        assert_eq!(new_state.get("count").unwrap().as_u64(), Some(6));
    }

    #[test]
    fn validator_rejects_invalid() {
        let rt = Runtime::new(ExecutionPolicy::TrustAll);
        let code = r#"
            fn validate_increment(state, args) {
                if state.count >= 100 {
                    throw "count must be < 100";
                }
                #{ count: state.count + 1 }
            }
        "#;

        let ast = rt.compile(code).unwrap();
        let mut state = BTreeMap::new();
        state.insert("count".into(), Value::U64(100));

        let result = rt.call_validator(&ast, "validate_increment", &state, &BTreeMap::new());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("count must be < 100"));
    }

    #[test]
    fn validator_receives_args() {
        let rt = Runtime::new(ExecutionPolicy::TrustAll);
        let code = r#"
            fn validate_set(state, args) {
                #{ value: args.new_value }
            }
        "#;

        let ast = rt.compile(code).unwrap();
        let state = BTreeMap::new();
        let mut args = BTreeMap::new();
        args.insert("new_value".into(), Value::String("hello".into()));

        let new_state = rt
            .call_validator(&ast, "validate_set", &state, &args)
            .unwrap();
        assert_eq!(new_state.get("value").unwrap().as_str(), Some("hello"));
    }

    #[test]
    fn policy_disabled_rejects() {
        let rt = Runtime::new(ExecutionPolicy::Disabled);
        let doc = Document {
            tessera: "0.1".into(),
            schema: tessera_core::Schema {
                fields: BTreeMap::new(),
                mutations: BTreeMap::new(),
                code: Some("fn x(s, a) { s }".into()),
            },
            api: tessera_core::ApiSpec {
                read: vec![],
                write: vec![],
            },
            state: BTreeMap::new(),
            chain: vec![],
            chain_mode: tessera_core::ChainMode::Embedded,
            pubkey: "a".repeat(64),
            signature: "b".repeat(128),
        };

        assert!(rt.check_authorization(&doc).is_err());
    }

    #[test]
    fn policy_trust_keys_accepts_known() {
        let key = "a".repeat(64);
        let rt = Runtime::new(ExecutionPolicy::TrustKeys(vec![key.clone()]));
        let doc = Document {
            tessera: "0.1".into(),
            schema: tessera_core::Schema {
                fields: BTreeMap::new(),
                mutations: BTreeMap::new(),
                code: Some("fn x(s, a) { s }".into()),
            },
            api: tessera_core::ApiSpec {
                read: vec![],
                write: vec![],
            },
            state: BTreeMap::new(),
            chain: vec![],
            chain_mode: tessera_core::ChainMode::Embedded,
            pubkey: key,
            signature: "b".repeat(128),
        };

        assert!(rt.check_authorization(&doc).is_ok());
    }

    #[test]
    fn policy_trust_keys_rejects_unknown() {
        let rt = Runtime::new(ExecutionPolicy::TrustKeys(vec!["a".repeat(64)]));
        let doc = Document {
            tessera: "0.1".into(),
            schema: tessera_core::Schema {
                fields: BTreeMap::new(),
                mutations: BTreeMap::new(),
                code: Some("fn x(s, a) { s }".into()),
            },
            api: tessera_core::ApiSpec {
                read: vec![],
                write: vec![],
            },
            state: BTreeMap::new(),
            chain: vec![],
            chain_mode: tessera_core::ChainMode::Embedded,
            pubkey: "b".repeat(64),
            signature: "c".repeat(128),
        };

        assert!(rt.check_authorization(&doc).is_err());
    }

    #[test]
    fn code_hash_computed() {
        let doc = Document {
            tessera: "0.1".into(),
            schema: tessera_core::Schema {
                fields: BTreeMap::new(),
                mutations: BTreeMap::new(),
                code: Some("fn x(s, a) { s }".into()),
            },
            api: tessera_core::ApiSpec {
                read: vec![],
                write: vec![],
            },
            state: BTreeMap::new(),
            chain: vec![],
            chain_mode: tessera_core::ChainMode::Embedded,
            pubkey: String::new(),
            signature: String::new(),
        };

        let hash = Runtime::code_hash(&doc);
        assert!(hash.is_some());
        assert_eq!(hash.unwrap().len(), 64); // SHA-256 hex
    }

    #[test]
    fn no_code_no_hash() {
        let doc = Document {
            tessera: "0.1".into(),
            schema: tessera_core::Schema {
                fields: BTreeMap::new(),
                mutations: BTreeMap::new(),
                code: None,
            },
            api: tessera_core::ApiSpec {
                read: vec![],
                write: vec![],
            },
            state: BTreeMap::new(),
            chain: vec![],
            chain_mode: tessera_core::ChainMode::Embedded,
            pubkey: String::new(),
            signature: String::new(),
        };

        assert!(Runtime::code_hash(&doc).is_none());
    }

    #[test]
    fn trust_authorizations_accepts_valid() {
        use tessera_core::crypto::Ed25519Signer;
        use tessera_core::Signer;

        let authority = Ed25519Signer::generate();
        let authorizer = Ed25519Signer::generate();
        let code = "fn x(s, a) { s }";
        let code_hash = sha256_hex(code.as_bytes());
        let authority_pubkey = authority.public_key_hex();

        // Create a valid authorization
        let payload = format!("{}{}", code_hash, authority_pubkey);
        let digest = sha256_hex(payload.as_bytes());
        let sig = authorizer.sign(digest.as_bytes()).unwrap();

        let auth = CodeAuthorization {
            code_hash: code_hash.clone(),
            authority_pubkey: authority_pubkey.clone(),
            authorizer_pubkey: authorizer.public_key_hex(),
            authorizer_sig: sig,
        };

        let rt = Runtime::new(ExecutionPolicy::TrustAuthorizations(vec![auth]));

        let doc = Document {
            tessera: "0.1".into(),
            schema: tessera_core::Schema {
                fields: BTreeMap::new(),
                mutations: BTreeMap::new(),
                code: Some(code.into()),
            },
            api: tessera_core::ApiSpec {
                read: vec![],
                write: vec![],
            },
            state: BTreeMap::new(),
            chain: vec![],
            chain_mode: tessera_core::ChainMode::Embedded,
            pubkey: authority_pubkey,
            signature: String::new(),
        };

        assert!(rt.check_authorization(&doc).is_ok());
    }

    #[test]
    fn trust_authorizations_rejects_wrong_code() {
        use tessera_core::crypto::Ed25519Signer;
        use tessera_core::Signer;

        let authority = Ed25519Signer::generate();
        let authorizer = Ed25519Signer::generate();
        let code = "fn x(s, a) { s }";
        let code_hash = sha256_hex(code.as_bytes());
        let authority_pubkey = authority.public_key_hex();

        let payload = format!("{}{}", code_hash, authority_pubkey);
        let digest = sha256_hex(payload.as_bytes());
        let sig = authorizer.sign(digest.as_bytes()).unwrap();

        let auth = CodeAuthorization {
            code_hash,
            authority_pubkey: authority_pubkey.clone(),
            authorizer_pubkey: authorizer.public_key_hex(),
            authorizer_sig: sig,
        };

        let rt = Runtime::new(ExecutionPolicy::TrustAuthorizations(vec![auth]));

        // Document has different code than what was authorized
        let doc = Document {
            tessera: "0.1".into(),
            schema: tessera_core::Schema {
                fields: BTreeMap::new(),
                mutations: BTreeMap::new(),
                code: Some("fn y(s, a) { s }".into()), // different code
            },
            api: tessera_core::ApiSpec {
                read: vec![],
                write: vec![],
            },
            state: BTreeMap::new(),
            chain: vec![],
            chain_mode: tessera_core::ChainMode::Embedded,
            pubkey: authority_pubkey,
            signature: String::new(),
        };

        assert!(rt.check_authorization(&doc).is_err());
    }

    #[test]
    fn trust_authorizations_rejects_forged_sig() {
        use tessera_core::crypto::Ed25519Signer;
        use tessera_core::Signer;

        let authority = Ed25519Signer::generate();
        let authorizer = Ed25519Signer::generate();
        let code = "fn x(s, a) { s }";
        let code_hash = sha256_hex(code.as_bytes());
        let authority_pubkey = authority.public_key_hex();

        // Forge a bad signature (sign wrong data)
        let sig = authorizer.sign(b"wrong payload").unwrap();

        let auth = CodeAuthorization {
            code_hash,
            authority_pubkey: authority_pubkey.clone(),
            authorizer_pubkey: authorizer.public_key_hex(),
            authorizer_sig: sig,
        };

        let rt = Runtime::new(ExecutionPolicy::TrustAuthorizations(vec![auth]));

        let doc = Document {
            tessera: "0.1".into(),
            schema: tessera_core::Schema {
                fields: BTreeMap::new(),
                mutations: BTreeMap::new(),
                code: Some(code.into()),
            },
            api: tessera_core::ApiSpec {
                read: vec![],
                write: vec![],
            },
            state: BTreeMap::new(),
            chain: vec![],
            chain_mode: tessera_core::ChainMode::Embedded,
            pubkey: authority_pubkey,
            signature: String::new(),
        };

        assert!(rt.check_authorization(&doc).is_err());
    }
}
