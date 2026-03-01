//! Contract Negotiation on Tessera — self-validating multi-party agreement.
//!
//! Two parties negotiate a contract. Every edit, proposal, counter, and
//! acceptance is recorded in the Tessera chain with cryptographic signatures.
//! The final document IS the proof of negotiation — no external authority,
//! no server, no database. Anyone can verify the complete history.

#![allow(dead_code)]

mod validator;

use std::collections::BTreeMap;
use tessera_core::crypto::Ed25519Signer;
use tessera_core::{
    ApiSpec, ChainMode, Document, FieldDef, FieldType, MutationDef, Schema, TesseraError, Value,
};
use tessera_engine::runtime::{ExecutionPolicy, Runtime};
use tessera_engine::{create_document, mutate_with_runtime, verify_document, version};

use validator::CONTRACT_VALIDATOR_CODE;

fn contract_schema() -> Schema {
    let mut fields = BTreeMap::new();
    fields.insert(
        "clauses".into(),
        FieldDef {
            field_type: FieldType::Map(Box::new(FieldType::String), Box::new(FieldType::String)),
            default: Some(Value::Map(BTreeMap::new())),
        },
    );
    fields.insert(
        "status".into(),
        FieldDef {
            field_type: FieldType::String,
            default: Some(Value::String("draft".into())),
        },
    );
    fields.insert(
        "version".into(),
        FieldDef {
            field_type: FieldType::U64,
            default: Some(Value::U64(0)),
        },
    );
    fields.insert(
        "proposer".into(),
        FieldDef {
            field_type: FieldType::String,
            default: Some(Value::String(String::new())),
        },
    );
    fields.insert(
        "last_action".into(),
        FieldDef {
            field_type: FieldType::String,
            default: Some(Value::String(String::new())),
        },
    );

    let mut mutations = BTreeMap::new();
    for name in [
        "edit_clause",
        "remove_clause",
        "propose",
        "accept",
        "counter",
        "withdraw",
    ] {
        mutations.insert(
            name.into(),
            MutationDef {
                guards: vec![],
                effects: BTreeMap::new(),
                args: BTreeMap::new(),
                validator: Some(format!("validate_{}", name)),
            },
        );
    }

    Schema {
        fields,
        mutations,
        code: Some(CONTRACT_VALIDATOR_CODE.into()),
    }
}

fn contract_api() -> ApiSpec {
    ApiSpec {
        read: vec![
            "clauses".into(),
            "status".into(),
            "version".into(),
            "proposer".into(),
            "last_action".into(),
        ],
        write: vec![
            "edit_clause".into(),
            "remove_clause".into(),
            "propose".into(),
            "accept".into(),
            "counter".into(),
            "withdraw".into(),
        ],
    }
}

fn new_contract(authority: &Ed25519Signer) -> Result<Document, TesseraError> {
    create_document(
        contract_schema(),
        contract_api(),
        ChainMode::Embedded,
        authority,
    )
}

fn edit_clause(
    doc: &mut Document,
    party: &str,
    clause_id: &str,
    text: &str,
    actor: &Ed25519Signer,
    authority: &Ed25519Signer,
    rt: &Runtime,
) -> Result<(), String> {
    let mut args = BTreeMap::new();
    args.insert("party".into(), Value::String(party.into()));
    args.insert("clause_id".into(), Value::String(clause_id.into()));
    args.insert("text".into(), Value::String(text.into()));
    mutate_with_runtime(doc, "edit_clause", args, actor, authority, rt).map_err(|e| e.to_string())
}

fn remove_clause(
    doc: &mut Document,
    party: &str,
    clause_id: &str,
    actor: &Ed25519Signer,
    authority: &Ed25519Signer,
    rt: &Runtime,
) -> Result<(), String> {
    let mut args = BTreeMap::new();
    args.insert("party".into(), Value::String(party.into()));
    args.insert("clause_id".into(), Value::String(clause_id.into()));
    mutate_with_runtime(doc, "remove_clause", args, actor, authority, rt).map_err(|e| e.to_string())
}

fn propose(
    doc: &mut Document,
    party: &str,
    actor: &Ed25519Signer,
    authority: &Ed25519Signer,
    rt: &Runtime,
) -> Result<(), String> {
    let mut args = BTreeMap::new();
    args.insert("party".into(), Value::String(party.into()));
    mutate_with_runtime(doc, "propose", args, actor, authority, rt).map_err(|e| e.to_string())
}

fn accept(
    doc: &mut Document,
    party: &str,
    actor: &Ed25519Signer,
    authority: &Ed25519Signer,
    rt: &Runtime,
) -> Result<(), String> {
    let mut args = BTreeMap::new();
    args.insert("party".into(), Value::String(party.into()));
    mutate_with_runtime(doc, "accept", args, actor, authority, rt).map_err(|e| e.to_string())
}

fn counter(
    doc: &mut Document,
    party: &str,
    actor: &Ed25519Signer,
    authority: &Ed25519Signer,
    rt: &Runtime,
) -> Result<(), String> {
    let mut args = BTreeMap::new();
    args.insert("party".into(), Value::String(party.into()));
    mutate_with_runtime(doc, "counter", args, actor, authority, rt).map_err(|e| e.to_string())
}

fn withdraw(
    doc: &mut Document,
    party: &str,
    actor: &Ed25519Signer,
    authority: &Ed25519Signer,
    rt: &Runtime,
) -> Result<(), String> {
    let mut args = BTreeMap::new();
    args.insert("party".into(), Value::String(party.into()));
    mutate_with_runtime(doc, "withdraw", args, actor, authority, rt).map_err(|e| e.to_string())
}

fn get_status(doc: &Document) -> &str {
    doc.state
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
}

fn get_last_action(doc: &Document) -> &str {
    doc.state
        .get("last_action")
        .and_then(|v| v.as_str())
        .unwrap_or("")
}

fn get_version(doc: &Document) -> u64 {
    doc.state
        .get("version")
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
}

fn print_clauses(doc: &Document) {
    if let Some(Value::Map(clauses)) = doc.state.get("clauses") {
        for (id, text) in clauses {
            let text_str = text.as_str().unwrap_or("?");
            let preview = if text_str.len() > 60 {
                format!("{}...", &text_str[..57])
            } else {
                text_str.to_string()
            };
            println!("    {}: {}", id, preview);
        }
    }
}

fn main() {
    println!("=== Contract Negotiation on Tessera ===");
    println!("Self-validating agreement with embedded rules.\n");

    let authority = Ed25519Signer::generate();
    let party_a = Ed25519Signer::generate();
    let party_b = Ed25519Signer::generate();
    let rt = Runtime::new(ExecutionPolicy::TrustAll);

    println!("Parties:");
    println!(
        "  Party A (Vendor):  {}...",
        &tessera_core::Signer::public_key_hex(&party_a)[..16]
    );
    println!(
        "  Party B (Client):  {}...",
        &tessera_core::Signer::public_key_hex(&party_b)[..16]
    );
    println!(
        "  Authority:         {}...\n",
        &tessera_core::Signer::public_key_hex(&authority)[..16]
    );

    let mut doc = new_contract(&authority).expect("failed to create contract");
    println!("Contract created. Status: {}\n", get_status(&doc));

    // --- Round 1: Party A drafts initial terms ---
    println!("--- Round 1: Party A Drafts Terms ---\n");

    edit_clause(
        &mut doc,
        "a",
        "scope",
        "Vendor grants Client a non-exclusive license to use the Software for internal business operations.",
        &party_a,
        &authority,
        &rt,
    ).unwrap();

    edit_clause(
        &mut doc,
        "a",
        "payment",
        "Client shall pay $50,000 per year, due annually on the anniversary of the effective date.",
        &party_a,
        &authority,
        &rt,
    )
    .unwrap();

    edit_clause(
        &mut doc,
        "a",
        "term",
        "This agreement is effective for 3 years from the date of acceptance.",
        &party_a,
        &authority,
        &rt,
    )
    .unwrap();

    edit_clause(
        &mut doc,
        "a",
        "termination",
        "Either party may terminate with 90 days written notice.",
        &party_a,
        &authority,
        &rt,
    )
    .unwrap();

    println!("  Party A added 4 clauses (v{}):", get_version(&doc));
    print_clauses(&doc);

    // Party A proposes
    propose(&mut doc, "a", &party_a, &authority, &rt).unwrap();
    println!("\n  Party A proposed terms. Status: {}", get_status(&doc));

    // --- Round 2: Party B counters ---
    println!("\n--- Round 2: Party B Counters ---\n");

    counter(&mut doc, "b", &party_b, &authority, &rt).unwrap();
    println!("  Party B countered. Status: {}", get_status(&doc));

    // Party B modifies payment and adds a clause
    edit_clause(
        &mut doc,
        "b",
        "payment",
        "Client shall pay $35,000 per year, due quarterly ($8,750 per quarter).",
        &party_b,
        &authority,
        &rt,
    )
    .unwrap();

    edit_clause(
        &mut doc,
        "b",
        "sla",
        "Vendor guarantees 99.9% uptime. Failure to meet SLA entitles Client to pro-rated credits.",
        &party_b,
        &authority,
        &rt,
    )
    .unwrap();

    edit_clause(
        &mut doc,
        "b",
        "term",
        "This agreement is effective for 2 years from the date of acceptance, with option to renew.",
        &party_b,
        &authority,
        &rt,
    )
    .unwrap();

    println!(
        "\n  Party B modified payment, term, and added SLA clause (v{}):",
        get_version(&doc)
    );
    print_clauses(&doc);

    // Party B proposes
    propose(&mut doc, "b", &party_b, &authority, &rt).unwrap();
    println!("\n  Party B proposed terms. Status: {}", get_status(&doc));

    // --- Round 3: Party A accepts ---
    println!("\n--- Round 3: Party A Accepts ---\n");

    accept(&mut doc, "a", &party_a, &authority, &rt).unwrap();
    println!("  Party A accepted! Status: {}", get_status(&doc));
    println!("  Action: {}", get_last_action(&doc));

    // --- Final State ---
    println!("\n--- Agreed Terms ---\n");
    print_clauses(&doc);

    // --- Verification ---
    println!("\n--- Integrity Verification ---\n");
    verify_document(&doc).expect("verification failed");
    println!("  Document VALID. Full negotiation history intact.");
    println!("  Chain entries: {}", doc.chain.len());
    println!("  Final version: {}", version(&doc).unwrap());

    // --- Demonstrate post-acceptance immutability ---
    println!("\n--- Post-Acceptance Guard ---\n");

    let result = edit_clause(
        &mut doc,
        "a",
        "payment",
        "Actually $100,000",
        &party_a,
        &authority,
        &rt,
    );
    match result {
        Ok(_) => println!("  FAIL: edit after acceptance should be rejected!"),
        Err(e) => println!("  Edit rejected: {}", e),
    }

    let result = withdraw(&mut doc, "a", &party_a, &authority, &rt);
    match result {
        Ok(_) => println!("  FAIL: withdrawal after acceptance should be rejected!"),
        Err(e) => println!("  Withdrawal rejected: {}", e),
    }

    // --- Demonstrate self-acceptance guard ---
    println!("\n--- Self-Acceptance Guard ---\n");
    let mut test_doc = new_contract(&authority).expect("create");
    edit_clause(
        &mut test_doc,
        "a",
        "test",
        "Test clause",
        &party_a,
        &authority,
        &rt,
    )
    .unwrap();
    propose(&mut test_doc, "a", &party_a, &authority, &rt).unwrap();

    let result = accept(&mut test_doc, "a", &party_a, &authority, &rt);
    match result {
        Ok(_) => println!("  FAIL: self-acceptance should be rejected!"),
        Err(e) => println!("  Self-acceptance rejected: {}", e),
    }

    // --- Tamper Detection ---
    println!("\n--- Tamper Detection ---\n");
    let mut tampered = doc.clone();
    if let Some(Value::Map(ref mut clauses)) = tampered.state.get_mut("clauses") {
        clauses.insert(
            "payment".into(),
            Value::String("Client shall pay $1 per year.".into()),
        );
    }
    match verify_document(&tampered) {
        Ok(()) => println!("  FAIL: tamper not detected!"),
        Err(e) => println!("  Tamper detected: {}", e),
    }

    // --- Serialization ---
    println!("\n--- Serialization ---\n");
    let json = tessera_format::to_json(&doc).expect("json");
    let cbor = tessera_format::to_cbor(&doc).expect("cbor");
    println!("  JSON: {} bytes", json.len());
    println!("  CBOR: {} bytes", cbor.len());

    let reloaded = tessera_engine::load_document(&json).expect("reload");
    verify_document(&reloaded).expect("verify reloaded");
    println!("  JSON round-trip: verified");

    let reloaded_cbor = tessera_engine::load_document(&cbor).expect("reload cbor");
    verify_document(&reloaded_cbor).expect("verify reloaded cbor");
    println!("  CBOR round-trip: verified");

    // --- Chain Detail ---
    println!("\n--- Negotiation History ---\n");
    for (i, entry) in doc.chain.iter().enumerate() {
        println!(
            "  [{}] {} (actor: {}...)",
            i + 1,
            entry.op.op_type,
            &entry.actor[..12],
        );
    }

    println!("\nDone. The contract is self-validating. Share the document; anyone can verify");
    println!("the complete negotiation history and confirm both parties agreed to these terms.");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (Ed25519Signer, Ed25519Signer, Ed25519Signer, Runtime) {
        let authority = Ed25519Signer::generate();
        let a = Ed25519Signer::generate();
        let b = Ed25519Signer::generate();
        let rt = Runtime::new(ExecutionPolicy::TrustAll);
        (authority, a, b, rt)
    }

    #[test]
    fn create_contract() {
        let authority = Ed25519Signer::generate();
        let doc = new_contract(&authority).unwrap();
        assert_eq!(get_status(&doc), "draft");
        assert_eq!(get_version(&doc), 0);
        assert!(doc.schema.code.is_some());
        verify_document(&doc).unwrap();
    }

    #[test]
    fn edit_and_propose() {
        let (authority, a, _b, rt) = setup();
        let mut doc = new_contract(&authority).unwrap();

        edit_clause(&mut doc, "a", "scope", "Test scope", &a, &authority, &rt).unwrap();
        assert_eq!(get_version(&doc), 1);
        assert_eq!(get_status(&doc), "draft");

        propose(&mut doc, "a", &a, &authority, &rt).unwrap();
        assert_eq!(get_status(&doc), "proposed");
        verify_document(&doc).unwrap();
    }

    #[test]
    fn full_negotiation_flow() {
        let (authority, a, b, rt) = setup();
        let mut doc = new_contract(&authority).unwrap();

        // A drafts and proposes
        edit_clause(&mut doc, "a", "payment", "$50,000/yr", &a, &authority, &rt).unwrap();
        propose(&mut doc, "a", &a, &authority, &rt).unwrap();

        // B counters
        counter(&mut doc, "b", &b, &authority, &rt).unwrap();
        assert_eq!(get_status(&doc), "draft");

        edit_clause(&mut doc, "b", "payment", "$35,000/yr", &b, &authority, &rt).unwrap();
        propose(&mut doc, "b", &b, &authority, &rt).unwrap();

        // A accepts
        accept(&mut doc, "a", &a, &authority, &rt).unwrap();
        assert_eq!(get_status(&doc), "accepted");
        verify_document(&doc).unwrap();

        // Check the final clause
        if let Some(Value::Map(clauses)) = doc.state.get("clauses") {
            assert_eq!(
                clauses.get("payment").unwrap().as_str().unwrap(),
                "$35,000/yr"
            );
        }
    }

    #[test]
    fn cannot_accept_own_proposal() {
        let (authority, a, _b, rt) = setup();
        let mut doc = new_contract(&authority).unwrap();

        edit_clause(&mut doc, "a", "test", "Test", &a, &authority, &rt).unwrap();
        propose(&mut doc, "a", &a, &authority, &rt).unwrap();

        let result = accept(&mut doc, "a", &a, &authority, &rt);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("other party must accept"));
    }

    #[test]
    fn cannot_counter_own_proposal() {
        let (authority, a, _b, rt) = setup();
        let mut doc = new_contract(&authority).unwrap();

        edit_clause(&mut doc, "a", "test", "Test", &a, &authority, &rt).unwrap();
        propose(&mut doc, "a", &a, &authority, &rt).unwrap();

        let result = counter(&mut doc, "a", &a, &authority, &rt);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("counter your own proposal"));
    }

    #[test]
    fn cannot_edit_after_acceptance() {
        let (authority, a, b, rt) = setup();
        let mut doc = new_contract(&authority).unwrap();

        edit_clause(&mut doc, "a", "test", "Test", &a, &authority, &rt).unwrap();
        propose(&mut doc, "a", &a, &authority, &rt).unwrap();
        accept(&mut doc, "b", &b, &authority, &rt).unwrap();

        let result = edit_clause(&mut doc, "a", "test", "Changed", &a, &authority, &rt);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already accepted"));
    }

    #[test]
    fn cannot_withdraw_after_acceptance() {
        let (authority, a, b, rt) = setup();
        let mut doc = new_contract(&authority).unwrap();

        edit_clause(&mut doc, "a", "test", "Test", &a, &authority, &rt).unwrap();
        propose(&mut doc, "a", &a, &authority, &rt).unwrap();
        accept(&mut doc, "b", &b, &authority, &rt).unwrap();

        let result = withdraw(&mut doc, "a", &a, &authority, &rt);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already accepted"));
    }

    #[test]
    fn withdraw_before_acceptance() {
        let (authority, a, b, rt) = setup();
        let mut doc = new_contract(&authority).unwrap();

        edit_clause(&mut doc, "a", "test", "Test", &a, &authority, &rt).unwrap();
        propose(&mut doc, "a", &a, &authority, &rt).unwrap();

        withdraw(&mut doc, "b", &b, &authority, &rt).unwrap();
        assert_eq!(get_status(&doc), "withdrawn");
        verify_document(&doc).unwrap();
    }

    #[test]
    fn cannot_propose_empty_contract() {
        let (authority, a, _b, rt) = setup();
        let mut doc = new_contract(&authority).unwrap();

        let result = propose(&mut doc, "a", &a, &authority, &rt);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("no clauses"));
    }

    #[test]
    fn remove_clause_works() {
        let (authority, a, _b, rt) = setup();
        let mut doc = new_contract(&authority).unwrap();

        edit_clause(&mut doc, "a", "keep", "Keep this", &a, &authority, &rt).unwrap();
        edit_clause(&mut doc, "a", "drop", "Drop this", &a, &authority, &rt).unwrap();
        remove_clause(&mut doc, "a", "drop", &a, &authority, &rt).unwrap();

        if let Some(Value::Map(clauses)) = doc.state.get("clauses") {
            assert!(clauses.contains_key("keep"));
            assert!(!clauses.contains_key("drop"));
        }
        verify_document(&doc).unwrap();
    }

    #[test]
    fn tamper_detection() {
        let (authority, a, b, rt) = setup();
        let mut doc = new_contract(&authority).unwrap();

        edit_clause(&mut doc, "a", "test", "Original", &a, &authority, &rt).unwrap();
        propose(&mut doc, "a", &a, &authority, &rt).unwrap();
        accept(&mut doc, "b", &b, &authority, &rt).unwrap();

        let mut tampered = doc.clone();
        tampered
            .state
            .insert("status".into(), Value::String("draft".into()));
        assert!(verify_document(&tampered).is_err());
    }

    #[test]
    fn different_actors_in_chain() {
        let (authority, a, b, rt) = setup();
        let mut doc = new_contract(&authority).unwrap();

        edit_clause(&mut doc, "a", "test", "Test", &a, &authority, &rt).unwrap();
        propose(&mut doc, "a", &a, &authority, &rt).unwrap();
        accept(&mut doc, "b", &b, &authority, &rt).unwrap();

        // Party A and B used different signing keys
        assert_ne!(doc.chain[0].actor, doc.chain[2].actor);
        verify_document(&doc).unwrap();
    }

    #[test]
    fn json_and_cbor_round_trip() {
        let (authority, a, b, rt) = setup();
        let mut doc = new_contract(&authority).unwrap();

        edit_clause(&mut doc, "a", "test", "Test clause", &a, &authority, &rt).unwrap();
        propose(&mut doc, "a", &a, &authority, &rt).unwrap();
        accept(&mut doc, "b", &b, &authority, &rt).unwrap();

        let json = tessera_format::to_json(&doc).unwrap();
        let from_json = tessera_engine::load_document(&json).unwrap();
        verify_document(&from_json).unwrap();
        assert_eq!(from_json.state, doc.state);

        let cbor = tessera_format::to_cbor(&doc).unwrap();
        let from_cbor = tessera_engine::load_document(&cbor).unwrap();
        verify_document(&from_cbor).unwrap();
        assert_eq!(from_cbor.state, doc.state);
    }

    #[test]
    fn disabled_policy_blocks_execution() {
        let authority = Ed25519Signer::generate();
        let a = Ed25519Signer::generate();
        let rt = Runtime::new(ExecutionPolicy::Disabled);
        let mut doc = new_contract(&authority).unwrap();

        let result = edit_clause(&mut doc, "a", "test", "Test", &a, &authority, &rt);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not authorized"));
    }
}
