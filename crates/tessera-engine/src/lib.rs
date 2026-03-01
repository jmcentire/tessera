pub mod eval;
pub mod runtime;
pub mod validate;

use std::collections::BTreeMap;
use tessera_chain::{
    apply_mutation_with_state, create_genesis, sign_document, validate_chain,
    verify_document_signature,
};
use tessera_core::crypto::{hash_state, Ed25519Signer};
use tessera_core::{ApiSpec, ChainMode, Document, Operation, Schema, TesseraError, Value};

use eval::evaluate_expr;
use runtime::Runtime;
use validate::{normalize_state_to_schema, validate_state_against_schema};

/// Load and validate a document from bytes (auto-detecting format).
pub fn load_document(data: &[u8]) -> Result<Document, TesseraError> {
    let doc = tessera_format::from_bytes(data)?;
    verify_document(&doc)?;
    Ok(doc)
}

/// Verify a document's integrity: signature + chain.
pub fn verify_document(doc: &Document) -> Result<(), TesseraError> {
    verify_document_signature(doc)?;
    validate_chain(doc)?;
    validate_state_against_schema(&doc.state, &doc.schema)?;
    Ok(())
}

/// Create a new document from a schema definition.
pub fn create_document(
    schema: Schema,
    api: ApiSpec,
    chain_mode: ChainMode,
    signer: &Ed25519Signer,
) -> Result<Document, TesseraError> {
    let mut doc = Document {
        tessera: "0.1".into(),
        schema,
        api,
        state: BTreeMap::new(),
        chain: vec![],
        chain_mode,
        pubkey: String::new(),
        signature: String::new(),
    };

    create_genesis(&mut doc, signer)?;
    validate_state_against_schema(&doc.state, &doc.schema)?;
    Ok(doc)
}

/// Apply a mutation to a document with full validation.
///
/// 1. Checks the mutation type exists in the schema
/// 2. Evaluates guard expressions against current state
/// 3. Computes new state by evaluating effect expressions
/// 4. Validates new state against schema
/// 5. Extends the chain with the signed mutation
/// 6. Re-signs the document
pub fn mutate(
    doc: &mut Document,
    op_type: &str,
    args: BTreeMap<String, Value>,
    actor: &Ed25519Signer,
    authority: &Ed25519Signer,
) -> Result<(), TesseraError> {
    // 1. Check mutation exists
    let mutation_def = doc
        .schema
        .mutations
        .get(op_type)
        .ok_or_else(|| TesseraError::UnknownMutation(op_type.into()))?
        .clone();

    // 2. Evaluate guards
    for guard in &mutation_def.guards {
        let result = evaluate_expr(guard, &doc.state, &args)?;
        match result {
            Value::Bool(true) => {}
            Value::Bool(false) => {
                return Err(TesseraError::GuardFailed(format!(
                    "guard '{}' evaluated to false",
                    guard
                )));
            }
            other => {
                return Err(TesseraError::GuardFailed(format!(
                    "guard '{}' must evaluate to bool, got {}",
                    guard,
                    other.type_name()
                )));
            }
        }
    }

    // 3. Compute new state from effects
    let mut new_state = doc.state.clone();
    for (field, expr) in &mutation_def.effects {
        let value = evaluate_expr(expr, &doc.state, &args)?;
        new_state.insert(field.clone(), value);
    }

    // 4. Validate new state
    validate_state_against_schema(&new_state, &doc.schema)?;

    // 5. Extend chain
    let op = Operation {
        op_type: op_type.into(),
        args,
    };
    apply_mutation_with_state(doc, op, new_state, actor)?;

    // 6. Re-sign document
    sign_document(doc, authority)?;

    Ok(())
}

/// Convenience: apply a mutation where the actor is also the authority.
pub fn mutate_self(
    doc: &mut Document,
    op_type: &str,
    args: BTreeMap<String, Value>,
    signer: &Ed25519Signer,
) -> Result<(), TesseraError> {
    mutate(doc, op_type, args, signer, signer)
}

/// Apply a mutation with embedded code execution support.
///
/// If the mutation has a `validator` field, the runtime executes the
/// corresponding function from the document's embedded code. The validator
/// receives (state, args) and returns the new state. Guards and effects
/// are skipped when a validator is present — the code IS the logic.
///
/// If no validator is set, falls back to the standard guard+effect path.
pub fn mutate_with_runtime(
    doc: &mut Document,
    op_type: &str,
    args: BTreeMap<String, Value>,
    actor: &Ed25519Signer,
    authority: &Ed25519Signer,
    rt: &Runtime,
) -> Result<(), TesseraError> {
    let mutation_def = doc
        .schema
        .mutations
        .get(op_type)
        .ok_or_else(|| TesseraError::UnknownMutation(op_type.into()))?
        .clone();

    let new_state = if let Some(ref validator_fn) = mutation_def.validator {
        // Validator path: check authorization, compile, execute
        rt.check_authorization(doc)?;

        let code = doc.schema.code.as_deref().ok_or_else(|| {
            TesseraError::CodeExecutionRequired(format!(
                "mutation '{}' has validator '{}' but document has no embedded code",
                op_type, validator_fn
            ))
        })?;

        let ast = rt.compile(code)?;
        let mut state = rt.call_validator(&ast, validator_fn, &doc.state, &args)?;
        // Normalize types to match schema (Rhai only has i64, coerce to U64 etc.)
        normalize_state_to_schema(&mut state, &doc.schema);
        state
    } else {
        // Standard path: guards + effects
        for guard in &mutation_def.guards {
            let result = evaluate_expr(guard, &doc.state, &args)?;
            match result {
                Value::Bool(true) => {}
                Value::Bool(false) => {
                    return Err(TesseraError::GuardFailed(format!(
                        "guard '{}' evaluated to false",
                        guard
                    )));
                }
                other => {
                    return Err(TesseraError::GuardFailed(format!(
                        "guard '{}' must evaluate to bool, got {}",
                        guard,
                        other.type_name()
                    )));
                }
            }
        }

        let mut new_state = doc.state.clone();
        for (field, expr) in &mutation_def.effects {
            let value = evaluate_expr(expr, &doc.state, &args)?;
            new_state.insert(field.clone(), value);
        }
        new_state
    };

    validate_state_against_schema(&new_state, &doc.schema)?;

    let op = Operation {
        op_type: op_type.into(),
        args,
    };
    apply_mutation_with_state(doc, op, new_state, actor)?;
    sign_document(doc, authority)?;

    Ok(())
}

/// Convenience: apply a mutation with runtime where the actor is also the authority.
pub fn mutate_self_with_runtime(
    doc: &mut Document,
    op_type: &str,
    args: BTreeMap<String, Value>,
    signer: &Ed25519Signer,
    rt: &Runtime,
) -> Result<(), TesseraError> {
    mutate_with_runtime(doc, op_type, args, signer, signer, rt)
}

/// Read a field from the document state.
pub fn read_field<'a>(doc: &'a Document, field: &str) -> Result<&'a Value, TesseraError> {
    // Check that the field is in the API's read list
    if !doc.api.read.contains(&field.to_string()) {
        return Err(TesseraError::UnknownField(format!(
            "'{}' is not in the API read list",
            field
        )));
    }

    doc.state
        .get(field)
        .ok_or_else(|| TesseraError::UnknownField(field.into()))
}

/// Get the content-addressable version (hash of current state).
pub fn version(doc: &Document) -> Result<String, TesseraError> {
    hash_state(&doc.state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tessera_core::*;

    fn counter_schema() -> Schema {
        let mut fields = BTreeMap::new();
        fields.insert(
            "count".into(),
            FieldDef {
                field_type: FieldType::U64,
                default: Some(Value::U64(0)),
            },
        );

        let mut inc_effects = BTreeMap::new();
        inc_effects.insert("count".into(), "count + 1".into());

        let mut dec_effects = BTreeMap::new();
        dec_effects.insert("count".into(), "count - 1".into());

        let mut mutations = BTreeMap::new();
        mutations.insert(
            "increment".into(),
            MutationDef {
                guards: vec!["count < 100".into()],
                effects: inc_effects,
                args: BTreeMap::new(),
                validator: None,
            },
        );
        mutations.insert(
            "decrement".into(),
            MutationDef {
                guards: vec!["count > 0".into()],
                effects: dec_effects,
                args: BTreeMap::new(),
                validator: None,
            },
        );

        Schema {
            fields,
            mutations,
            code: None,
        }
    }

    fn counter_api() -> ApiSpec {
        ApiSpec {
            read: vec!["count".into()],
            write: vec!["increment".into(), "decrement".into()],
        }
    }

    #[test]
    fn create_and_verify_document() {
        let signer = Ed25519Signer::generate();
        let doc = create_document(
            counter_schema(),
            counter_api(),
            ChainMode::Embedded,
            &signer,
        )
        .unwrap();

        assert_eq!(doc.state.get("count").unwrap().as_u64(), Some(0));
        verify_document(&doc).unwrap();
    }

    #[test]
    fn mutate_increments_count() {
        let signer = Ed25519Signer::generate();
        let mut doc = create_document(
            counter_schema(),
            counter_api(),
            ChainMode::Embedded,
            &signer,
        )
        .unwrap();

        mutate_self(&mut doc, "increment", BTreeMap::new(), &signer).unwrap();

        assert_eq!(doc.state.get("count").unwrap().as_u64(), Some(1));
        assert_eq!(doc.chain.len(), 1);
        verify_document(&doc).unwrap();
    }

    #[test]
    fn multiple_mutations() {
        let signer = Ed25519Signer::generate();
        let mut doc = create_document(
            counter_schema(),
            counter_api(),
            ChainMode::Embedded,
            &signer,
        )
        .unwrap();

        for _ in 0..5 {
            mutate_self(&mut doc, "increment", BTreeMap::new(), &signer).unwrap();
        }
        mutate_self(&mut doc, "decrement", BTreeMap::new(), &signer).unwrap();

        assert_eq!(doc.state.get("count").unwrap().as_u64(), Some(4));
        assert_eq!(doc.chain.len(), 6);
        verify_document(&doc).unwrap();
    }

    #[test]
    fn guard_prevents_invalid_mutation() {
        let signer = Ed25519Signer::generate();
        let mut doc = create_document(
            counter_schema(),
            counter_api(),
            ChainMode::Embedded,
            &signer,
        )
        .unwrap();

        // count is 0, decrement guard says "count > 0"
        let result = mutate_self(&mut doc, "decrement", BTreeMap::new(), &signer);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("guard"));
    }

    #[test]
    fn unknown_mutation_rejected() {
        let signer = Ed25519Signer::generate();
        let mut doc = create_document(
            counter_schema(),
            counter_api(),
            ChainMode::Embedded,
            &signer,
        )
        .unwrap();

        let result = mutate_self(&mut doc, "nonexistent", BTreeMap::new(), &signer);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("nonexistent"));
    }

    #[test]
    fn read_field_works() {
        let signer = Ed25519Signer::generate();
        let doc = create_document(
            counter_schema(),
            counter_api(),
            ChainMode::Embedded,
            &signer,
        )
        .unwrap();

        let val = read_field(&doc, "count").unwrap();
        assert_eq!(val.as_u64(), Some(0));
    }

    #[test]
    fn read_field_not_in_api_rejected() {
        let signer = Ed25519Signer::generate();
        let doc = create_document(
            counter_schema(),
            ApiSpec {
                read: vec![],
                write: vec![],
            },
            ChainMode::Embedded,
            &signer,
        )
        .unwrap();

        let result = read_field(&doc, "count");
        assert!(result.is_err());
    }

    #[test]
    fn version_changes_with_state() {
        let signer = Ed25519Signer::generate();
        let mut doc = create_document(
            counter_schema(),
            counter_api(),
            ChainMode::Embedded,
            &signer,
        )
        .unwrap();

        let v1 = version(&doc).unwrap();

        mutate_self(&mut doc, "increment", BTreeMap::new(), &signer).unwrap();

        let v2 = version(&doc).unwrap();
        assert_ne!(v1, v2);
    }

    #[test]
    fn tampered_document_fails_verification() {
        let signer = Ed25519Signer::generate();
        let mut doc = create_document(
            counter_schema(),
            counter_api(),
            ChainMode::Embedded,
            &signer,
        )
        .unwrap();

        mutate_self(&mut doc, "increment", BTreeMap::new(), &signer).unwrap();

        // Tamper
        doc.state.insert("count".into(), Value::U64(999));

        let result = verify_document(&doc);
        assert!(result.is_err());
    }

    #[test]
    fn json_round_trip_preserves_integrity() {
        let signer = Ed25519Signer::generate();
        let mut doc = create_document(
            counter_schema(),
            counter_api(),
            ChainMode::Embedded,
            &signer,
        )
        .unwrap();

        mutate_self(&mut doc, "increment", BTreeMap::new(), &signer).unwrap();
        mutate_self(&mut doc, "increment", BTreeMap::new(), &signer).unwrap();

        // Serialize to JSON and back
        let bytes = tessera_format::to_json(&doc).unwrap();
        let loaded = load_document(&bytes).unwrap();

        assert_eq!(loaded.state.get("count").unwrap().as_u64(), Some(2));
        assert_eq!(loaded.chain.len(), 2);
    }

    #[test]
    fn cbor_round_trip_preserves_integrity() {
        let signer = Ed25519Signer::generate();
        let mut doc = create_document(
            counter_schema(),
            counter_api(),
            ChainMode::Embedded,
            &signer,
        )
        .unwrap();

        mutate_self(&mut doc, "increment", BTreeMap::new(), &signer).unwrap();

        // Serialize to CBOR and back
        let bytes = tessera_format::to_cbor(&doc).unwrap();
        let loaded = load_document(&bytes).unwrap();

        assert_eq!(loaded.state.get("count").unwrap().as_u64(), Some(1));
    }

    #[test]
    fn multi_actor_mutations() {
        let authority = Ed25519Signer::generate();
        let player = Ed25519Signer::generate();

        let mut doc = create_document(
            counter_schema(),
            counter_api(),
            ChainMode::Embedded,
            &authority,
        )
        .unwrap();

        // Authority increments
        mutate(
            &mut doc,
            "increment",
            BTreeMap::new(),
            &authority,
            &authority,
        )
        .unwrap();

        // Player increments
        mutate(&mut doc, "increment", BTreeMap::new(), &player, &authority).unwrap();

        assert_eq!(doc.state.get("count").unwrap().as_u64(), Some(2));
        assert_eq!(doc.chain.len(), 2);
        assert_ne!(doc.chain[0].actor, doc.chain[1].actor);
        verify_document(&doc).unwrap();
    }

    #[test]
    fn mutate_with_runtime_uses_validator() {
        use runtime::ExecutionPolicy;

        let signer = Ed25519Signer::generate();

        // Schema with embedded code and a validator
        let mut fields = BTreeMap::new();
        fields.insert(
            "count".into(),
            FieldDef {
                field_type: FieldType::U64,
                default: Some(Value::U64(0)),
            },
        );

        let mut mutations = BTreeMap::new();
        mutations.insert(
            "increment".into(),
            MutationDef {
                guards: vec![],
                effects: BTreeMap::new(),
                args: BTreeMap::new(),
                validator: Some("validate_increment".into()),
            },
        );

        let code = r#"
            fn validate_increment(state, args) {
                let count = state.count;
                if count >= 10 {
                    throw "count must be < 10";
                }
                #{ count: count + 1 }
            }
        "#;

        let schema = Schema {
            fields,
            mutations,
            code: Some(code.into()),
        };

        let api = ApiSpec {
            read: vec!["count".into()],
            write: vec!["increment".into()],
        };

        let mut doc = create_document(schema, api, ChainMode::Embedded, &signer).unwrap();

        let rt = Runtime::new(ExecutionPolicy::TrustAll);

        // Apply three increments via runtime
        for _ in 0..3 {
            mutate_self_with_runtime(&mut doc, "increment", BTreeMap::new(), &signer, &rt).unwrap();
        }

        assert_eq!(doc.state.get("count").unwrap().as_u64(), Some(3));
        assert_eq!(doc.chain.len(), 3);
        verify_document(&doc).unwrap();
    }

    #[test]
    fn mutate_with_runtime_validator_rejects() {
        use runtime::ExecutionPolicy;

        let signer = Ed25519Signer::generate();

        let mut fields = BTreeMap::new();
        fields.insert(
            "count".into(),
            FieldDef {
                field_type: FieldType::U64,
                default: Some(Value::U64(0)),
            },
        );

        let mut mutations = BTreeMap::new();
        mutations.insert(
            "increment".into(),
            MutationDef {
                guards: vec![],
                effects: BTreeMap::new(),
                args: BTreeMap::new(),
                validator: Some("validate_increment".into()),
            },
        );

        let code = r#"
            fn validate_increment(state, args) {
                if state.count >= 2 {
                    throw "count must be < 2";
                }
                #{ count: state.count + 1 }
            }
        "#;

        let schema = Schema {
            fields,
            mutations,
            code: Some(code.into()),
        };

        let api = ApiSpec {
            read: vec!["count".into()],
            write: vec!["increment".into()],
        };

        let mut doc = create_document(schema, api, ChainMode::Embedded, &signer).unwrap();
        let rt = Runtime::new(ExecutionPolicy::TrustAll);

        // Two increments succeed
        mutate_self_with_runtime(&mut doc, "increment", BTreeMap::new(), &signer, &rt).unwrap();
        mutate_self_with_runtime(&mut doc, "increment", BTreeMap::new(), &signer, &rt).unwrap();

        // Third should fail (count >= 2)
        let result = mutate_self_with_runtime(&mut doc, "increment", BTreeMap::new(), &signer, &rt);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("count must be < 2"));
    }

    #[test]
    fn mutate_with_runtime_falls_back_to_effects() {
        use runtime::ExecutionPolicy;

        let signer = Ed25519Signer::generate();
        let rt = Runtime::new(ExecutionPolicy::TrustAll);

        // Standard counter schema (no validators)
        let mut doc = create_document(
            counter_schema(),
            counter_api(),
            ChainMode::Embedded,
            &signer,
        )
        .unwrap();

        // Should work via the standard guard+effect path
        mutate_self_with_runtime(&mut doc, "increment", BTreeMap::new(), &signer, &rt).unwrap();
        assert_eq!(doc.state.get("count").unwrap().as_u64(), Some(1));
        verify_document(&doc).unwrap();
    }

    #[test]
    fn mutate_with_runtime_policy_blocks_untrusted() {
        use runtime::ExecutionPolicy;

        let signer = Ed25519Signer::generate();

        let mut fields = BTreeMap::new();
        fields.insert(
            "count".into(),
            FieldDef {
                field_type: FieldType::U64,
                default: Some(Value::U64(0)),
            },
        );

        let mut mutations = BTreeMap::new();
        mutations.insert(
            "increment".into(),
            MutationDef {
                guards: vec![],
                effects: BTreeMap::new(),
                args: BTreeMap::new(),
                validator: Some("validate_increment".into()),
            },
        );

        let schema = Schema {
            fields,
            mutations,
            code: Some("fn validate_increment(s, a) { s }".into()),
        };

        let api = ApiSpec {
            read: vec!["count".into()],
            write: vec!["increment".into()],
        };

        let mut doc = create_document(schema, api, ChainMode::Embedded, &signer).unwrap();

        // Disabled policy should reject
        let rt = Runtime::new(ExecutionPolicy::Disabled);
        let result = mutate_self_with_runtime(&mut doc, "increment", BTreeMap::new(), &signer, &rt);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not authorized"));
    }
}
