/// Contract negotiation validator as Rhai source code.
///
/// This is embedded in the Tessera document and signed by the authority.
/// It enforces the rules of a two-party contract negotiation:
///
/// - Either party can edit clauses during drafting
/// - Either party can propose the current terms
/// - Only the non-proposer can accept or counter
/// - Once accepted, the contract is final
/// - Either party can withdraw before acceptance
pub const CONTRACT_VALIDATOR_CODE: &str = r#"
// ===== Contract Negotiation Validator for Tessera =====
//
// Two parties (A and B) negotiate a contract. The document carries
// the clauses, negotiation status, and the full history of changes.
//
// State:
//   clauses     - map of clause_id -> clause text
//   status      - "draft" | "proposed" | "accepted" | "withdrawn"
//   version     - revision counter
//   proposer    - "a" or "b" (who last proposed)
//   last_action - description of the last action taken
//
// Flow:
//   1. Either party edits clauses (status = "draft")
//   2. A party proposes (status = "proposed", proposer = that party)
//   3. The OTHER party can:
//      - accept  -> status = "accepted" (final)
//      - counter -> status = "draft" (back to editing)
//      - withdraw -> status = "withdrawn" (final)
//   4. During draft, either party can edit and re-propose

// ---- Helpers ----

fn other_party(party) {
    if party == "a" { return "b"; }
    if party == "b" { return "a"; }
    throw "invalid party: " + party + " (must be 'a' or 'b')";
}

fn require_active(status) {
    if status == "accepted" {
        throw "contract is already accepted — no further changes allowed";
    }
    if status == "withdrawn" {
        throw "contract has been withdrawn — no further changes allowed";
    }
}

fn require_party(party) {
    if party != "a" && party != "b" {
        throw "invalid party: " + party + " (must be 'a' or 'b')";
    }
}

// ---- Clone a map (Rhai passes by value, but nested maps need care) ----

fn clone_clauses(clauses) {
    let result = #{};
    for key in clauses.keys() {
        result[key] = clauses[key];
    }
    result
}

// ===== VALIDATORS =====

// Edit a clause: add or modify text for a clause_id.
// Args: party, clause_id, text
fn validate_edit_clause(state, args) {
    require_active(state.status);
    require_party(args.party);

    if state.status != "draft" {
        throw "can only edit clauses in draft status (current: " + state.status + ")";
    }

    let clause_id = args.clause_id;
    let text = args.text;
    if clause_id == "" {
        throw "clause_id cannot be empty";
    }
    if text == "" {
        throw "clause text cannot be empty";
    }

    let clauses = clone_clauses(state.clauses);
    clauses[clause_id] = text;

    #{
        clauses: clauses,
        status: "draft",
        version: state.version + 1,
        proposer: state.proposer,
        last_action: "party " + args.party + " edited clause '" + clause_id + "'"
    }
}

// Remove a clause.
// Args: party, clause_id
fn validate_remove_clause(state, args) {
    require_active(state.status);
    require_party(args.party);

    if state.status != "draft" {
        throw "can only remove clauses in draft status (current: " + state.status + ")";
    }

    let clause_id = args.clause_id;
    if !state.clauses.contains(clause_id) {
        throw "clause '" + clause_id + "' does not exist";
    }

    let clauses = clone_clauses(state.clauses);
    clauses.remove(clause_id);

    #{
        clauses: clauses,
        status: "draft",
        version: state.version + 1,
        proposer: state.proposer,
        last_action: "party " + args.party + " removed clause '" + clause_id + "'"
    }
}

// Propose the current terms for acceptance.
// Args: party
fn validate_propose(state, args) {
    require_active(state.status);
    require_party(args.party);

    if state.status != "draft" {
        throw "can only propose from draft status (current: " + state.status + ")";
    }

    if state.clauses.keys().len() == 0 {
        throw "cannot propose with no clauses";
    }

    #{
        clauses: clone_clauses(state.clauses),
        status: "proposed",
        version: state.version,
        proposer: args.party,
        last_action: "party " + args.party + " proposed terms (v" + state.version + ")"
    }
}

// Accept the proposed terms. Only the non-proposer can accept.
// Args: party
fn validate_accept(state, args) {
    require_active(state.status);
    require_party(args.party);

    if state.status != "proposed" {
        throw "can only accept when terms are proposed (current: " + state.status + ")";
    }

    if args.party == state.proposer {
        throw "cannot accept your own proposal — the other party must accept";
    }

    #{
        clauses: clone_clauses(state.clauses),
        status: "accepted",
        version: state.version,
        proposer: state.proposer,
        last_action: "party " + args.party + " accepted terms (v" + state.version + ")"
    }
}

// Counter the proposed terms: reject and return to draft for editing.
// Args: party
fn validate_counter(state, args) {
    require_active(state.status);
    require_party(args.party);

    if state.status != "proposed" {
        throw "can only counter when terms are proposed (current: " + state.status + ")";
    }

    if args.party == state.proposer {
        throw "cannot counter your own proposal";
    }

    #{
        clauses: clone_clauses(state.clauses),
        status: "draft",
        version: state.version,
        proposer: state.proposer,
        last_action: "party " + args.party + " countered proposal (v" + state.version + ")"
    }
}

// Withdraw from negotiation. Either party can withdraw at any time
// before acceptance.
// Args: party
fn validate_withdraw(state, args) {
    require_active(state.status);
    require_party(args.party);

    #{
        clauses: clone_clauses(state.clauses),
        status: "withdrawn",
        version: state.version,
        proposer: state.proposer,
        last_action: "party " + args.party + " withdrew from negotiation"
    }
}
"#;
