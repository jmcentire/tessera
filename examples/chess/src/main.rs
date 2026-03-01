//! Chess on Tessera — a complete chess game with cryptographic integrity.
//!
//! This example demonstrates Tessera as a self-validating document format
//! with embedded code execution. The chess rules are written in Rhai and
//! embedded directly in the document. Any party receiving the document
//! can read the validator code, verify its signature, and independently
//! validate every move in the chain.
//!
//! The validator code IS the chess rules. It lives inside the document's
//! schema, signed by the document authority. The Tessera engine executes
//! it in a sandboxed Rhai runtime with resource limits.
//!
//! Two players each have their own signing key. Every move is recorded in
//! the Tessera chain with the player's signature. After the game, anyone
//! can verify the entire chain — no external authority needed.

#[allow(dead_code)]
mod board;
mod validator;

use std::collections::BTreeMap;
use tessera_core::crypto::Ed25519Signer;
use tessera_core::{
    ApiSpec, ChainMode, Document, FieldDef, FieldType, MutationDef, Schema, TesseraError, Value,
};
use tessera_engine::runtime::{ExecutionPolicy, Runtime};
use tessera_engine::{create_document, mutate_with_runtime, verify_document, version};

use board::{Board, Color, Move, STARTING_FEN};
use validator::CHESS_VALIDATOR_CODE;

/// Build the chess schema for Tessera with embedded validator code.
fn chess_schema() -> Schema {
    let mut fields = BTreeMap::new();
    fields.insert(
        "fen".into(),
        FieldDef {
            field_type: FieldType::String,
            default: Some(Value::String(STARTING_FEN.into())),
        },
    );
    fields.insert(
        "status".into(),
        FieldDef {
            field_type: FieldType::String,
            default: Some(Value::String("active".into())),
        },
    );
    fields.insert(
        "move_count".into(),
        FieldDef {
            field_type: FieldType::U64,
            default: Some(Value::U64(0)),
        },
    );
    fields.insert(
        "last_move".into(),
        FieldDef {
            field_type: FieldType::String,
            default: Some(Value::String(String::new())),
        },
    );

    let mut mutations = BTreeMap::new();

    // make_move: validated by embedded Rhai code
    mutations.insert(
        "make_move".into(),
        MutationDef {
            guards: vec![],
            effects: BTreeMap::new(),
            args: BTreeMap::new(),
            validator: Some("validate_make_move".into()),
        },
    );

    // resign: validated by embedded Rhai code
    mutations.insert(
        "resign".into(),
        MutationDef {
            guards: vec![],
            effects: BTreeMap::new(),
            args: BTreeMap::new(),
            validator: Some("validate_resign".into()),
        },
    );

    Schema {
        fields,
        mutations,
        code: Some(CHESS_VALIDATOR_CODE.into()),
    }
}

fn chess_api() -> ApiSpec {
    ApiSpec {
        read: vec![
            "fen".into(),
            "status".into(),
            "move_count".into(),
            "last_move".into(),
        ],
        write: vec!["make_move".into(), "resign".into()],
    }
}

/// Create a new chess game document.
fn new_game(authority: &Ed25519Signer) -> Result<Document, TesseraError> {
    create_document(chess_schema(), chess_api(), ChainMode::Embedded, authority)
}

/// Apply a chess move to the document via embedded validator.
///
/// The application only passes the UCI move string. The embedded Rhai
/// validator handles all chess logic: piece movement, captures, check,
/// castling, en passant, promotion, and game status detection.
fn apply_chess_move(
    doc: &mut Document,
    move_str: &str,
    player: &Ed25519Signer,
    authority: &Ed25519Signer,
    rt: &Runtime,
) -> Result<(), String> {
    let mut args = BTreeMap::new();
    args.insert("move_uci".into(), Value::String(move_str.into()));

    mutate_with_runtime(doc, "make_move", args, player, authority, rt)
        .map_err(|e| e.to_string())?;

    Ok(())
}

fn print_move_header(move_num: u32, color: &str, san: &str, uci: &str) {
    let num_str = if color == "White" {
        format!("{}.", move_num)
    } else {
        format!("{}...", move_num)
    };
    println!("  {} {} {} ({})", num_str, color, san, uci);
}

fn main() {
    println!("=== Chess on Tessera ===");
    println!("Self-validating game state with embedded chess rules.\n");

    // Two players, one authority (the game server / document owner)
    let authority = Ed25519Signer::generate();
    let white_player = Ed25519Signer::generate();
    let black_player = Ed25519Signer::generate();

    // Runtime with TrustAll policy (in production, you'd use TrustKeys)
    let rt = Runtime::new(ExecutionPolicy::TrustAll);

    println!("Players:");
    println!(
        "  White: {}...",
        &tessera_core::Signer::public_key_hex(&white_player)[..16]
    );
    println!(
        "  Black: {}...",
        &tessera_core::Signer::public_key_hex(&black_player)[..16]
    );
    println!(
        "  Authority: {}...\n",
        &tessera_core::Signer::public_key_hex(&authority)[..16]
    );

    // Show embedded code info
    let code_hash =
        Runtime::code_hash(&new_game(&authority).unwrap()).unwrap_or_else(|| "none".into());
    println!(
        "Embedded validator: {} bytes of Rhai code",
        CHESS_VALIDATOR_CODE.len()
    );
    println!("Code hash: {}\n", code_hash);

    // Create new game
    let mut doc = new_game(&authority).expect("failed to create game");
    println!(
        "Game created. Version: {}\n",
        version(&doc).expect("version")
    );

    // Show starting position
    let board = Board::starting();
    println!("{}", board.display());

    // Play Scholar's Mate (4-move checkmate)
    //   1. e4    e5
    //   2. Bc4   Nc6
    //   3. Qh5   Nf6??
    //   4. Qxf7#
    println!("--- Scholar's Mate ---\n");

    let game_moves: Vec<(&str, &Ed25519Signer)> = vec![
        ("e2e4", &white_player),
        ("e7e5", &black_player),
        ("f1c4", &white_player),
        ("b8c6", &black_player),
        ("d1h5", &white_player),
        ("g8f6", &black_player),
        ("h5f7", &white_player),
    ];

    for (move_str, player) in &game_moves {
        let fen = doc.state.get("fen").and_then(|v| v.as_str()).expect("fen");
        let pre_board = Board::from_fen(fen).expect("parse fen");
        let mv = Move::parse(move_str).expect("parse move");
        let san = mv.to_san(&pre_board);
        let move_num = doc
            .state
            .get("move_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32
            / 2
            + 1;
        let color = if pre_board.active == Color::White {
            "White"
        } else {
            "Black"
        };

        apply_chess_move(&mut doc, move_str, player, &authority, &rt).expect("move failed");

        print_move_header(move_num, color, &san, move_str);

        // Check status from document state (set by the validator)
        let status_str = doc
            .state
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        if status_str != "active" {
            let new_fen = doc.state.get("fen").and_then(|v| v.as_str()).unwrap();
            let new_board = Board::from_fen(new_fen).expect("parse new fen");
            println!();
            println!("{}", new_board.display());
            match status_str {
                "white_wins" => println!("  CHECKMATE! White wins."),
                "black_wins" => println!("  CHECKMATE! Black wins."),
                "stalemate" => println!("  STALEMATE! Draw."),
                "draw" => println!("  DRAW (50-move rule)."),
                other => println!("  Game over: {}", other),
            }
        }
    }

    // Show final state
    println!();
    println!("--- Game Summary ---\n");
    println!(
        "Status: {}",
        doc.state
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
    );
    println!(
        "Moves: {}",
        doc.state
            .get("move_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
    );
    println!("Chain entries: {} (one per half-move)", doc.chain.len());
    let ver = version(&doc).expect("version");
    println!("Final version: {}", ver);

    // Verify integrity
    println!("\n--- Integrity Verification ---\n");
    match verify_document(&doc) {
        Ok(()) => println!("  Document VALID. Chain intact, signatures verified."),
        Err(e) => println!("  Document INVALID: {}", e),
    }

    // Demonstrate tamper detection
    println!("\n--- Tamper Detection Demo ---\n");
    let mut tampered = doc.clone();

    // Try to cheat: change the FEN to a different position
    tampered.state.insert(
        "fen".into(),
        Value::String("8/8/8/8/8/8/8/4K2k w - - 0 1".into()),
    );
    println!("  Tampering: changed board position in state...");

    match verify_document(&tampered) {
        Ok(()) => println!("  FAIL: tamper not detected!"),
        Err(e) => println!("  DETECTED: {}", e),
    }

    // Demonstrate that after the game ends, moves are rejected
    println!("\n--- Post-Game Guard ---\n");
    let result = apply_chess_move(&mut doc, "e2e4", &white_player, &authority, &rt);
    match result {
        Ok(_) => println!("  FAIL: move after checkmate should be rejected!"),
        Err(e) => println!("  Correctly rejected: {}", e),
    }

    // Demonstrate disabled policy
    println!("\n--- Execution Policy Demo ---\n");
    let disabled_rt = Runtime::new(ExecutionPolicy::Disabled);
    let mut fresh_doc = new_game(&authority).expect("create game");
    let result = apply_chess_move(
        &mut fresh_doc,
        "e2e4",
        &white_player,
        &authority,
        &disabled_rt,
    );
    match result {
        Ok(_) => println!("  FAIL: disabled policy should reject!"),
        Err(e) => println!("  Disabled policy correctly rejected: {}", e),
    }

    // Serialize and show sizes
    println!("\n--- Serialization ---\n");
    let json_bytes = tessera_format::to_json(&doc).expect("json");
    let cbor_bytes = tessera_format::to_cbor(&doc).expect("cbor");
    println!("  JSON: {} bytes", json_bytes.len());
    println!("  CBOR: {} bytes", cbor_bytes.len());

    // Verify round-trip
    let reloaded = tessera_engine::load_document(&json_bytes).expect("reload json");
    verify_document(&reloaded).expect("verify reloaded");
    println!("  JSON round-trip: verified");

    let reloaded_cbor = tessera_engine::load_document(&cbor_bytes).expect("reload cbor");
    verify_document(&reloaded_cbor).expect("verify reloaded cbor");
    println!("  CBOR round-trip: verified");

    println!("\n--- Chain Detail ---\n");
    for (i, entry) in doc.chain.iter().enumerate() {
        let half_move = i + 1;
        let full_move = (i / 2) + 1;
        let color = if i % 2 == 0 { "W" } else { "B" };
        println!(
            "  [{}] {}.{} {} (actor: {}...)",
            half_move,
            full_move,
            color,
            entry.op.op_type,
            &entry.actor[..12],
        );
    }

    println!("\nDone. The game is fully self-validating with embedded chess rules.");
    println!("Share the document; anyone can read the validator code and verify every move.");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (Ed25519Signer, Ed25519Signer, Ed25519Signer, Runtime) {
        let authority = Ed25519Signer::generate();
        let white = Ed25519Signer::generate();
        let black = Ed25519Signer::generate();
        let rt = Runtime::new(ExecutionPolicy::TrustAll);
        (authority, white, black, rt)
    }

    #[test]
    fn create_chess_game() {
        let authority = Ed25519Signer::generate();
        let doc = new_game(&authority).unwrap();

        assert_eq!(
            doc.state.get("fen").unwrap().as_str().unwrap(),
            STARTING_FEN
        );
        assert_eq!(doc.state.get("status").unwrap().as_str().unwrap(), "active");
        assert_eq!(doc.state.get("move_count").unwrap().as_u64().unwrap(), 0);
        assert!(doc.schema.code.is_some());
        verify_document(&doc).unwrap();
    }

    #[test]
    fn play_and_validate_game() {
        let (authority, white, black, rt) = setup();
        let mut doc = new_game(&authority).unwrap();

        apply_chess_move(&mut doc, "e2e4", &white, &authority, &rt).unwrap();
        apply_chess_move(&mut doc, "e7e5", &black, &authority, &rt).unwrap();

        assert_eq!(doc.state.get("move_count").unwrap().as_u64().unwrap(), 2);
        assert_eq!(doc.chain.len(), 2);
        verify_document(&doc).unwrap();

        // Check FEN reflects the moves
        let fen = doc.state.get("fen").unwrap().as_str().unwrap();
        let board = Board::from_fen(fen).unwrap();
        assert!(board.squares[3][4].is_some()); // e4 has white pawn
        assert!(board.squares[4][4].is_some()); // e5 has black pawn
    }

    #[test]
    fn scholars_mate_ends_game() {
        let (authority, white, black, rt) = setup();
        let mut doc = new_game(&authority).unwrap();

        let moves = [
            ("e2e4", &white),
            ("e7e5", &black),
            ("f1c4", &white),
            ("b8c6", &black),
            ("d1h5", &white),
            ("g8f6", &black),
            ("h5f7", &white),
        ];

        for (m, player) in &moves {
            apply_chess_move(&mut doc, m, player, &authority, &rt).unwrap();
        }

        assert_eq!(
            doc.state.get("status").unwrap().as_str().unwrap(),
            "white_wins"
        );
        verify_document(&doc).unwrap();
    }

    #[test]
    fn illegal_move_rejected_by_validator() {
        let (authority, white, _black, rt) = setup();
        let mut doc = new_game(&authority).unwrap();

        // e2e5 is illegal (pawn can't jump 3 squares)
        let result = apply_chess_move(&mut doc, "e2e5", &white, &authority, &rt);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("illegal move"));
    }

    #[test]
    fn move_after_checkmate_rejected() {
        let (authority, white, black, rt) = setup();
        let mut doc = new_game(&authority).unwrap();

        let moves = [
            ("e2e4", &white),
            ("e7e5", &black),
            ("f1c4", &white),
            ("b8c6", &black),
            ("d1h5", &white),
            ("g8f6", &black),
            ("h5f7", &white),
        ];

        for (m, player) in &moves {
            apply_chess_move(&mut doc, m, player, &authority, &rt).unwrap();
        }

        // Game is over — validator rejects further moves
        let result = apply_chess_move(&mut doc, "a7a6", &black, &authority, &rt);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not active"));
    }

    #[test]
    fn tampered_game_detected() {
        let (authority, white, black, rt) = setup();
        let mut doc = new_game(&authority).unwrap();

        apply_chess_move(&mut doc, "e2e4", &white, &authority, &rt).unwrap();
        apply_chess_move(&mut doc, "e7e5", &black, &authority, &rt).unwrap();

        // Tamper with state
        doc.state.insert("move_count".into(), Value::U64(0));
        assert!(verify_document(&doc).is_err());
    }

    #[test]
    fn different_actors_recorded_in_chain() {
        let (authority, white, black, rt) = setup();
        let mut doc = new_game(&authority).unwrap();

        apply_chess_move(&mut doc, "e2e4", &white, &authority, &rt).unwrap();
        apply_chess_move(&mut doc, "e7e5", &black, &authority, &rt).unwrap();

        assert_ne!(doc.chain[0].actor, doc.chain[1].actor);
        verify_document(&doc).unwrap();
    }

    #[test]
    fn json_and_cbor_round_trip() {
        let (authority, white, black, rt) = setup();
        let mut doc = new_game(&authority).unwrap();
        apply_chess_move(&mut doc, "d2d4", &white, &authority, &rt).unwrap();
        apply_chess_move(&mut doc, "d7d5", &black, &authority, &rt).unwrap();

        // JSON round-trip
        let json = tessera_format::to_json(&doc).unwrap();
        let from_json = tessera_engine::load_document(&json).unwrap();
        verify_document(&from_json).unwrap();
        assert_eq!(from_json.state, doc.state);

        // CBOR round-trip
        let cbor = tessera_format::to_cbor(&doc).unwrap();
        let from_cbor = tessera_engine::load_document(&cbor).unwrap();
        verify_document(&from_cbor).unwrap();
        assert_eq!(from_cbor.state, doc.state);
    }

    #[test]
    fn disabled_policy_blocks_execution() {
        let authority = Ed25519Signer::generate();
        let white = Ed25519Signer::generate();
        let rt = Runtime::new(ExecutionPolicy::Disabled);
        let mut doc = new_game(&authority).unwrap();

        let result = apply_chess_move(&mut doc, "e2e4", &white, &authority, &rt);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not authorized"));
    }

    #[test]
    fn code_hash_is_deterministic() {
        let auth1 = Ed25519Signer::generate();
        let auth2 = Ed25519Signer::generate();
        let doc1 = new_game(&auth1).unwrap();
        let doc2 = new_game(&auth2).unwrap();

        // Same code -> same hash regardless of authority
        let hash1 = Runtime::code_hash(&doc1).unwrap();
        let hash2 = Runtime::code_hash(&doc2).unwrap();
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64);
    }
}
