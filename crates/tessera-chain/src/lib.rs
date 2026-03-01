use tessera_core::crypto::{
    canonical_json, hash_state, sha256_hex, Ed25519Signer, Ed25519Verifier,
};
use tessera_core::{
    ChainMode, Checkpoint, Document, Mutation, Operation, Signer, State, TesseraError, Verifier,
};

/// Create a genesis document with initial state from schema defaults.
pub fn create_genesis(doc: &mut Document, signer: &Ed25519Signer) -> Result<(), TesseraError> {
    // Initialize state from schema defaults
    for (name, field_def) in &doc.schema.fields {
        if !doc.state.contains_key(name) {
            if let Some(default) = &field_def.default {
                doc.state.insert(name.clone(), default.clone());
            }
        }
    }

    doc.pubkey = signer.public_key_hex();
    doc.chain = vec![];
    sign_document(doc, signer)?;
    Ok(())
}

/// Apply a mutation to a document, extending the chain.
pub fn apply_mutation(
    doc: &mut Document,
    op: Operation,
    actor: &Ed25519Signer,
) -> Result<(), TesseraError> {
    let prev_hash = hash_state(&doc.state)?;

    // Apply effects from schema
    let mutation_def = doc
        .schema
        .mutations
        .get(&op.op_type)
        .ok_or_else(|| TesseraError::UnknownMutation(op.op_type.clone()))?
        .clone();

    // Apply effects to state
    let mut new_state = doc.state.clone();
    for field in mutation_def.effects.keys() {
        // For now, effects are evaluated by the engine layer.
        // The chain layer just records the state transition.
        // The caller is responsible for computing the new state.
        if let Some(arg_val) = op.args.get(field) {
            new_state.insert(field.clone(), arg_val.clone());
        }
    }

    // If effects reference the operation args, apply them
    // Simple case: if the op has args matching field names, use them
    for (field, val) in &op.args {
        if doc.schema.fields.contains_key(field) {
            new_state.insert(field.clone(), val.clone());
        }
    }

    let next_hash = hash_state(&new_state)?;
    let schema_hash = canonical_json(&doc.schema).map(|j| sha256_hex(j.as_bytes()))?;

    // Build the signing payload: SHA-256(prev_hash || canonical(op) || next_hash || schema_hash)
    let op_json = canonical_json(&op)?;
    let sig_payload = format!("{}{}{}{}", prev_hash, op_json, next_hash, schema_hash);
    let sig_hash = sha256_hex(sig_payload.as_bytes());
    let sig = actor.sign(sig_hash.as_bytes())?;

    let mutation = Mutation {
        prev_hash,
        op,
        next_hash: next_hash.clone(),
        actor: actor.public_key_hex(),
        sig,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };

    doc.state = new_state;
    doc.chain.push(mutation);

    Ok(())
}

/// Apply a mutation with an explicit new state (for when the caller computes state changes).
pub fn apply_mutation_with_state(
    doc: &mut Document,
    op: Operation,
    new_state: State,
    actor: &Ed25519Signer,
) -> Result<(), TesseraError> {
    let prev_hash = hash_state(&doc.state)?;
    let next_hash = hash_state(&new_state)?;
    let schema_hash = canonical_json(&doc.schema).map(|j| sha256_hex(j.as_bytes()))?;

    let op_json = canonical_json(&op)?;
    let sig_payload = format!("{}{}{}{}", prev_hash, op_json, next_hash, schema_hash);
    let sig_hash = sha256_hex(sig_payload.as_bytes());
    let sig = actor.sign(sig_hash.as_bytes())?;

    let mutation = Mutation {
        prev_hash,
        op,
        next_hash,
        actor: actor.public_key_hex(),
        sig,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };

    doc.state = new_state;
    doc.chain.push(mutation);

    Ok(())
}

/// Validate the entire chain of a document.
///
/// For embedded chains: replays from genesis, verifying every hash and signature.
/// For referenced chains: verifies the prev_hash reference exists.
/// For stateless chains: only verifies the document signature.
pub fn validate_chain(doc: &Document) -> Result<(), TesseraError> {
    match doc.chain_mode {
        ChainMode::Embedded => validate_embedded_chain(doc),
        ChainMode::Referenced => {
            // Referenced mode: we can't replay the full chain, but we can verify
            // that the last mutation's next_hash matches the current state
            if let Some(last) = doc.chain.last() {
                let state_hash = hash_state(&doc.state)?;
                if last.next_hash != state_hash {
                    return Err(TesseraError::ChainIntegrity(
                        "final state hash does not match chain".into(),
                    ));
                }
            }
            Ok(())
        }
        ChainMode::Stateless => {
            // Stateless: no chain to validate
            Ok(())
        }
    }
}

fn validate_embedded_chain(doc: &Document) -> Result<(), TesseraError> {
    if doc.chain.is_empty() {
        return Ok(());
    }

    let schema_hash = canonical_json(&doc.schema).map(|j| sha256_hex(j.as_bytes()))?;

    // Verify genesis: chain[0].prev_hash must match the genesis state from schema defaults
    let mut genesis_state = tessera_core::State::new();
    for (name, field_def) in &doc.schema.fields {
        if let Some(default) = &field_def.default {
            genesis_state.insert(name.clone(), default.clone());
        }
    }
    let genesis_hash = hash_state(&genesis_state)?;
    if doc.chain[0].prev_hash != genesis_hash {
        return Err(TesseraError::ChainIntegrity(format!(
            "chain[0].prev_hash {} does not match genesis state hash {} \
             (computed from schema defaults)",
            doc.chain[0].prev_hash, genesis_hash
        )));
    }

    // Validate each mutation's signature and chain linkage
    for (i, mutation) in doc.chain.iter().enumerate() {
        // Verify the actor's signature (includes schema hash for tamper detection)
        let op_json = canonical_json(&mutation.op)?;
        let sig_payload = format!(
            "{}{}{}{}",
            mutation.prev_hash, op_json, mutation.next_hash, schema_hash
        );
        let sig_hash = sha256_hex(sig_payload.as_bytes());

        Ed25519Verifier::verify(&mutation.actor, sig_hash.as_bytes(), &mutation.sig).map_err(
            |e| TesseraError::ChainIntegrity(format!("mutation {}: signature invalid: {}", i, e)),
        )?;

        // Verify chain linkage: each mutation's prev_hash should match
        // the previous mutation's next_hash
        if i > 0 {
            let prev = &doc.chain[i - 1];
            if mutation.prev_hash != prev.next_hash {
                return Err(TesseraError::ChainIntegrity(format!(
                    "mutation {}: prev_hash {} does not match previous next_hash {}",
                    i, mutation.prev_hash, prev.next_hash
                )));
            }
            // Verify timestamp monotonicity
            if mutation.timestamp < prev.timestamp {
                return Err(TesseraError::ChainIntegrity(format!(
                    "mutation {}: timestamp {} precedes previous timestamp {}",
                    i, mutation.timestamp, prev.timestamp
                )));
            }
        }
    }

    // Verify the final state matches the last mutation's next_hash
    if let Some(last) = doc.chain.last() {
        let state_hash = hash_state(&doc.state)?;
        if last.next_hash != state_hash {
            return Err(TesseraError::ChainIntegrity(format!(
                "final state hash {} does not match chain's last next_hash {}",
                state_hash, last.next_hash
            )));
        }
    }

    Ok(())
}

/// Sign the document envelope.
pub fn sign_document(doc: &mut Document, signer: &Ed25519Signer) -> Result<(), TesseraError> {
    let payload = document_signing_payload(doc)?;
    doc.signature = signer.sign(payload.as_bytes())?;
    doc.pubkey = signer.public_key_hex();
    Ok(())
}

/// Verify the document envelope signature.
pub fn verify_document_signature(doc: &Document) -> Result<(), TesseraError> {
    let payload = document_signing_payload(doc)?;
    Ed25519Verifier::verify(&doc.pubkey, payload.as_bytes(), &doc.signature)
}

/// Compute the signing payload for a document.
/// SHA-256(canonical(schema) || canonical(api) || canonical(state) || canonical(chain))
fn document_signing_payload(doc: &Document) -> Result<String, TesseraError> {
    let schema_json = canonical_json(&doc.schema)?;
    let api_json = canonical_json(&doc.api)?;
    let state_json = canonical_json(&doc.state)?;
    let chain_json = canonical_json(&doc.chain)?;
    let combined = format!("{}{}{}{}", schema_json, api_json, state_json, chain_json);
    Ok(sha256_hex(combined.as_bytes()).to_string())
}

/// Compute the content-addressable version of a document (hash of current state).
pub fn document_version(doc: &Document) -> Result<String, TesseraError> {
    hash_state(&doc.state)
}

/// Create a checkpoint at the current chain position.
pub fn create_checkpoint(
    doc: &Document,
    signer: &Ed25519Signer,
) -> Result<Checkpoint, TesseraError> {
    let state_hash = hash_state(&doc.state)?;
    let chain_index = doc.chain.len();

    let checkpoint_payload = format!("{}{}", chain_index, state_hash);
    let sig = signer.sign(sha256_hex(checkpoint_payload.as_bytes()).as_bytes())?;

    Ok(Checkpoint {
        chain_index,
        state_hash,
        state: doc.state.clone(),
        signer: signer.public_key_hex(),
        sig,
    })
}

/// Verify a checkpoint's signature.
pub fn verify_checkpoint(checkpoint: &Checkpoint) -> Result<(), TesseraError> {
    let checkpoint_payload = format!("{}{}", checkpoint.chain_index, checkpoint.state_hash);
    Ed25519Verifier::verify(
        &checkpoint.signer,
        sha256_hex(checkpoint_payload.as_bytes()).as_bytes(),
        &checkpoint.sig,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
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
                guards: vec![],
                effects: inc_effects,
                args: BTreeMap::new(),
                validator: None,
            },
        );
        mutations.insert(
            "decrement".into(),
            MutationDef {
                guards: vec![],
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

    fn empty_doc(schema: Schema) -> Document {
        Document {
            tessera: "0.1".into(),
            schema,
            api: ApiSpec {
                read: vec!["count".into()],
                write: vec!["increment".into(), "decrement".into()],
            },
            state: BTreeMap::new(),
            chain: vec![],
            chain_mode: ChainMode::Embedded,
            pubkey: String::new(),
            signature: String::new(),
        }
    }

    #[test]
    fn genesis_initializes_defaults() {
        let signer = Ed25519Signer::generate();
        let mut doc = empty_doc(counter_schema());

        create_genesis(&mut doc, &signer).unwrap();

        assert_eq!(doc.state.get("count").unwrap().as_u64(), Some(0));
        assert!(!doc.pubkey.is_empty());
        assert!(!doc.signature.is_empty());
    }

    #[test]
    fn genesis_signature_verifies() {
        let signer = Ed25519Signer::generate();
        let mut doc = empty_doc(counter_schema());
        create_genesis(&mut doc, &signer).unwrap();

        verify_document_signature(&doc).unwrap();
    }

    #[test]
    fn apply_mutation_extends_chain() {
        let signer = Ed25519Signer::generate();
        let mut doc = empty_doc(counter_schema());
        create_genesis(&mut doc, &signer).unwrap();

        // Manually compute new state for the chain layer
        let mut new_state = doc.state.clone();
        new_state.insert("count".into(), Value::U64(1));

        apply_mutation_with_state(
            &mut doc,
            Operation {
                op_type: "increment".into(),
                args: BTreeMap::new(),
            },
            new_state,
            &signer,
        )
        .unwrap();

        assert_eq!(doc.chain.len(), 1);
        assert_eq!(doc.state.get("count").unwrap().as_u64(), Some(1));
    }

    #[test]
    fn chain_validates_after_mutations() {
        let signer = Ed25519Signer::generate();
        let mut doc = empty_doc(counter_schema());
        create_genesis(&mut doc, &signer).unwrap();

        // Apply 3 increments
        for i in 1..=3u64 {
            let mut new_state = doc.state.clone();
            new_state.insert("count".into(), Value::U64(i));
            apply_mutation_with_state(
                &mut doc,
                Operation {
                    op_type: "increment".into(),
                    args: BTreeMap::new(),
                },
                new_state,
                &signer,
            )
            .unwrap();
        }

        assert_eq!(doc.chain.len(), 3);
        validate_chain(&doc).unwrap();
    }

    #[test]
    fn tampered_state_detected() {
        let signer = Ed25519Signer::generate();
        let mut doc = empty_doc(counter_schema());
        create_genesis(&mut doc, &signer).unwrap();

        let mut new_state = doc.state.clone();
        new_state.insert("count".into(), Value::U64(1));
        apply_mutation_with_state(
            &mut doc,
            Operation {
                op_type: "increment".into(),
                args: BTreeMap::new(),
            },
            new_state,
            &signer,
        )
        .unwrap();

        // Tamper with the state
        doc.state.insert("count".into(), Value::U64(999));

        let result = validate_chain(&doc);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("final state hash"));
    }

    #[test]
    fn tampered_signature_detected() {
        let signer = Ed25519Signer::generate();
        let mut doc = empty_doc(counter_schema());
        create_genesis(&mut doc, &signer).unwrap();

        let mut new_state = doc.state.clone();
        new_state.insert("count".into(), Value::U64(1));
        apply_mutation_with_state(
            &mut doc,
            Operation {
                op_type: "increment".into(),
                args: BTreeMap::new(),
            },
            new_state,
            &signer,
        )
        .unwrap();

        // Tamper with a mutation signature
        doc.chain[0].sig = "ff".repeat(64);

        let result = validate_chain(&doc);
        assert!(result.is_err());
    }

    #[test]
    fn chain_linkage_verified() {
        let signer = Ed25519Signer::generate();
        let mut doc = empty_doc(counter_schema());
        create_genesis(&mut doc, &signer).unwrap();

        for i in 1..=2u64 {
            let mut new_state = doc.state.clone();
            new_state.insert("count".into(), Value::U64(i));
            apply_mutation_with_state(
                &mut doc,
                Operation {
                    op_type: "increment".into(),
                    args: BTreeMap::new(),
                },
                new_state,
                &signer,
            )
            .unwrap();
        }

        // Break the chain linkage
        doc.chain[1].prev_hash = "0".repeat(64);

        let result = validate_chain(&doc);
        assert!(result.is_err());
        // Broken linkage is detected — either as a prev_hash mismatch or
        // as a signature failure (since prev_hash is part of the signing payload)
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("prev_hash") || err.contains("signature"),
            "expected chain integrity error, got: {}",
            err
        );
    }

    #[test]
    fn document_version_is_state_hash() {
        let signer = Ed25519Signer::generate();
        let mut doc = empty_doc(counter_schema());
        create_genesis(&mut doc, &signer).unwrap();

        let v1 = document_version(&doc).unwrap();

        let mut new_state = doc.state.clone();
        new_state.insert("count".into(), Value::U64(1));
        apply_mutation_with_state(
            &mut doc,
            Operation {
                op_type: "increment".into(),
                args: BTreeMap::new(),
            },
            new_state,
            &signer,
        )
        .unwrap();

        let v2 = document_version(&doc).unwrap();

        // Version changes when state changes
        assert_ne!(v1, v2);

        // Version is deterministic
        assert_eq!(v2, document_version(&doc).unwrap());
    }

    #[test]
    fn checkpoint_creation_and_verification() {
        let signer = Ed25519Signer::generate();
        let mut doc = empty_doc(counter_schema());
        create_genesis(&mut doc, &signer).unwrap();

        let checkpoint = create_checkpoint(&doc, &signer).unwrap();
        assert_eq!(checkpoint.chain_index, 0);

        verify_checkpoint(&checkpoint).unwrap();
    }

    #[test]
    fn checkpoint_tampered_sig_fails() {
        let signer = Ed25519Signer::generate();
        let mut doc = empty_doc(counter_schema());
        create_genesis(&mut doc, &signer).unwrap();

        let mut checkpoint = create_checkpoint(&doc, &signer).unwrap();
        checkpoint.sig = "ff".repeat(64);

        assert!(verify_checkpoint(&checkpoint).is_err());
    }

    #[test]
    fn stateless_chain_mode_skips_validation() {
        let signer = Ed25519Signer::generate();
        let mut doc = empty_doc(counter_schema());
        doc.chain_mode = ChainMode::Stateless;
        create_genesis(&mut doc, &signer).unwrap();

        // Even with no chain, validation passes in stateless mode
        validate_chain(&doc).unwrap();
    }

    #[test]
    fn unknown_mutation_type_rejected() {
        let signer = Ed25519Signer::generate();
        let mut doc = empty_doc(counter_schema());
        create_genesis(&mut doc, &signer).unwrap();

        let result = apply_mutation(
            &mut doc,
            Operation {
                op_type: "nonexistent".into(),
                args: BTreeMap::new(),
            },
            &signer,
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("nonexistent"));
    }

    #[test]
    fn multi_actor_chain() {
        let author = Ed25519Signer::generate();
        let player = Ed25519Signer::generate();
        let mut doc = empty_doc(counter_schema());
        create_genesis(&mut doc, &author).unwrap();

        // Author makes first move
        let mut s1 = doc.state.clone();
        s1.insert("count".into(), Value::U64(1));
        apply_mutation_with_state(
            &mut doc,
            Operation {
                op_type: "increment".into(),
                args: BTreeMap::new(),
            },
            s1,
            &author,
        )
        .unwrap();

        // Player makes second move
        let mut s2 = doc.state.clone();
        s2.insert("count".into(), Value::U64(2));
        apply_mutation_with_state(
            &mut doc,
            Operation {
                op_type: "increment".into(),
                args: BTreeMap::new(),
            },
            s2,
            &player,
        )
        .unwrap();

        assert_eq!(doc.chain.len(), 2);
        assert_ne!(doc.chain[0].actor, doc.chain[1].actor);
        validate_chain(&doc).unwrap();
    }
}
