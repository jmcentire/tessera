/// The chess validator as Rhai source code.
///
/// This is the embedded code that lives inside the Tessera document.
/// When signed and serialized, this code IS the chess rules — anyone
/// receiving the document can read, verify, and execute it.
///
/// The validator receives (state, args) and must return the new state.
/// It either returns a valid new state or `throw`s on illegal moves.
pub const CHESS_VALIDATOR_CODE: &str = r#"
// ===== Chess Validator for Tessera =====
//
// This code is embedded in the Tessera document and signed by the
// document authority. It validates every chess move: piece movement,
// captures, check, checkmate, castling, en passant, and promotion.
//
// The validator receives the current state (fen, status, move_count,
// last_move) and args (move_uci: "e2e4") and returns the new state.

// ---- Coordinate helpers ----

fn file_from_char(c) {
    if c == 'a' { return 0; }
    if c == 'b' { return 1; }
    if c == 'c' { return 2; }
    if c == 'd' { return 3; }
    if c == 'e' { return 4; }
    if c == 'f' { return 5; }
    if c == 'g' { return 6; }
    if c == 'h' { return 7; }
    throw "invalid file: " + c;
}

fn file_to_char(f) {
    if f == 0 { return 'a'; }
    if f == 1 { return 'b'; }
    if f == 2 { return 'c'; }
    if f == 3 { return 'd'; }
    if f == 4 { return 'e'; }
    if f == 5 { return 'f'; }
    if f == 6 { return 'g'; }
    if f == 7 { return 'h'; }
    throw "invalid file index";
}

fn rank_to_char(r) {
    if r == 0 { return '1'; }
    if r == 1 { return '2'; }
    if r == 2 { return '3'; }
    if r == 3 { return '4'; }
    if r == 4 { return '5'; }
    if r == 5 { return '6'; }
    if r == 6 { return '7'; }
    if r == 7 { return '8'; }
    throw "invalid rank index";
}

fn abs_val(x) {
    if x < 0 { return -x; }
    return x;
}

// ---- Piece helpers ----
// Board is a flat array of 64 strings: "." for empty, or FEN char (P,N,B,R,Q,K,p,n,b,r,q,k)

fn idx(rank, file) { rank * 8 + file }

fn is_white_piece(ch) { ch == 'P' || ch == 'N' || ch == 'B' || ch == 'R' || ch == 'Q' || ch == 'K' }
fn is_black_piece(ch) { ch == 'p' || ch == 'n' || ch == 'b' || ch == 'r' || ch == 'q' || ch == 'k' }
fn is_empty(ch) { ch == '.' }

fn piece_color(ch) {
    if is_white_piece(ch) { return "w"; }
    if is_black_piece(ch) { return "b"; }
    return "none";
}

fn to_lower(ch) {
    if ch == 'P' { return 'p'; }
    if ch == 'N' { return 'n'; }
    if ch == 'B' { return 'b'; }
    if ch == 'R' { return 'r'; }
    if ch == 'Q' { return 'q'; }
    if ch == 'K' { return 'k'; }
    return ch;
}

fn to_upper(ch) {
    if ch == 'p' { return 'P'; }
    if ch == 'n' { return 'N'; }
    if ch == 'b' { return 'B'; }
    if ch == 'r' { return 'R'; }
    if ch == 'q' { return 'Q'; }
    if ch == 'k' { return 'K'; }
    return ch;
}

// ---- FEN parsing ----

fn fen_to_board(fen) {
    let parts = fen.split(' ');
    let position = parts[0];
    let active = parts[1];
    let castling = parts[2];
    let ep = parts[3];
    let halfmove = parse_int(parts[4]);
    let fullmove = parse_int(parts[5]);

    let board = [];
    // Initialize 64 empty squares
    for i in 0..64 { board.push('.'); }

    let ranks = position.split('/');
    for ri in 0..8 {
        let rank = 7 - ri;  // FEN starts from rank 8
        let rank_str = ranks[ri];
        let file = 0;
        for ci in 0..rank_str.len() {
            let ch = rank_str[ci];
            if ch >= '1' && ch <= '8' {
                let skip = ch.to_int() - 48;  // ASCII '0' = 48
                file += skip;
            } else {
                board[idx(rank, file)] = ch;
                file += 1;
            }
        }
    }

    let ep_rank = -1;
    let ep_file = -1;
    if ep != "-" {
        ep_file = file_from_char(ep[0]);
        ep_rank = ep[1].to_int() - 49;  // '1' = 49 -> 0
    }

    #{
        board: board,
        active: active,
        castling: castling,
        ep_rank: ep_rank,
        ep_file: ep_file,
        halfmove: halfmove,
        fullmove: fullmove
    }
}

fn board_to_fen(state) {
    let fen = "";

    for rank_idx in 0..8 {
        let rank = 7 - rank_idx;
        let empty = 0;
        for file in 0..8 {
            let ch = state.board[idx(rank, file)];
            if ch == '.' {
                empty += 1;
            } else {
                if empty > 0 {
                    fen += "" + empty;
                    empty = 0;
                }
                fen += ch;
            }
        }
        if empty > 0 {
            fen += "" + empty;
        }
        if rank_idx < 7 {
            fen += "/";
        }
    }

    fen += " " + state.active;
    fen += " " + state.castling;

    if state.ep_rank >= 0 {
        fen += " " + file_to_char(state.ep_file) + rank_to_char(state.ep_rank);
    } else {
        fen += " -";
    }

    fen += " " + state.halfmove + " " + state.fullmove;
    fen
}

// ---- Attack detection ----

fn is_attacked_by(board, rank, file, by_color) {
    // Pawn attacks
    let pawn_dir = if by_color == "w" { 1 } else { -1 };
    let pr = rank - pawn_dir;
    if pr >= 0 && pr <= 7 {
        for df in [-1, 1] {
            let pf = file + df;
            if pf >= 0 && pf <= 7 {
                let ch = board[idx(pr, pf)];
                let pawn = if by_color == "w" { 'P' } else { 'p' };
                if ch == pawn { return true; }
            }
        }
    }

    // Knight attacks
    let knight = if by_color == "w" { 'N' } else { 'n' };
    let knight_offsets = [[-2,-1],[-2,1],[-1,-2],[-1,2],[1,-2],[1,2],[2,-1],[2,1]];
    for off in knight_offsets {
        let nr = rank + off[0];
        let nf = file + off[1];
        if nr >= 0 && nr <= 7 && nf >= 0 && nf <= 7 {
            if board[idx(nr, nf)] == knight { return true; }
        }
    }

    // King attacks
    let king = if by_color == "w" { 'K' } else { 'k' };
    for dr in [-1, 0, 1] {
        for df in [-1, 0, 1] {
            if dr == 0 && df == 0 { continue; }
            let kr = rank + dr;
            let kf = file + df;
            if kr >= 0 && kr <= 7 && kf >= 0 && kf <= 7 {
                if board[idx(kr, kf)] == king { return true; }
            }
        }
    }

    // Sliding: bishop/queen diagonals
    let bishop = if by_color == "w" { 'B' } else { 'b' };
    let queen = if by_color == "w" { 'Q' } else { 'q' };
    let diag_dirs = [[-1,-1],[-1,1],[1,-1],[1,1]];
    for dir in diag_dirs {
        let r = rank + dir[0];
        let f = file + dir[1];
        while r >= 0 && r <= 7 && f >= 0 && f <= 7 {
            let ch = board[idx(r, f)];
            if ch != '.' {
                if ch == bishop || ch == queen { return true; }
                break;
            }
            r += dir[0];
            f += dir[1];
        }
    }

    // Sliding: rook/queen straights
    let rook = if by_color == "w" { 'R' } else { 'r' };
    let straight_dirs = [[-1,0],[1,0],[0,-1],[0,1]];
    for dir in straight_dirs {
        let r = rank + dir[0];
        let f = file + dir[1];
        while r >= 0 && r <= 7 && f >= 0 && f <= 7 {
            let ch = board[idx(r, f)];
            if ch != '.' {
                if ch == rook || ch == queen { return true; }
                break;
            }
            r += dir[0];
            f += dir[1];
        }
    }

    false
}

fn find_king(board, color) {
    let king = if color == "w" { 'K' } else { 'k' };
    for rank in 0..8 {
        for file in 0..8 {
            if board[idx(rank, file)] == king {
                return [rank, file];
            }
        }
    }
    throw "king not found for " + color;
}

fn is_in_check(board, color) {
    let kpos = find_king(board, color);
    let opponent = if color == "w" { "b" } else { "w" };
    is_attacked_by(board, kpos[0], kpos[1], opponent)
}

// ---- Move application (unchecked) ----

fn apply_move_unchecked(state, from_rank, from_file, to_rank, to_file, promo) {
    // Clone board
    let board = [];
    for i in 0..64 { board.push(state.board[i]); }

    let piece = board[idx(from_rank, from_file)];
    let piece_lower = to_lower(piece);
    let color = piece_color(piece);
    let captured = board[idx(to_rank, to_file)];

    // Move piece
    board[idx(to_rank, to_file)] = piece;
    board[idx(from_rank, from_file)] = '.';

    // Pawn promotion
    if piece_lower == 'p' && (to_rank == 0 || to_rank == 7) {
        let promo_piece = if promo == "" { "q" } else { promo };
        let pp = if color == "w" { to_upper(promo_piece[0]) } else { promo_piece[0] };
        board[idx(to_rank, to_file)] = pp;
    }

    // En passant capture
    if piece_lower == 'p' && to_rank == state.ep_rank && to_file == state.ep_file {
        board[idx(from_rank, to_file)] = '.';
    }

    // Castling: move the rook
    if piece_lower == 'k' && abs_val(from_file - to_file) == 2 {
        if to_file > from_file {
            // Kingside
            let rook = board[idx(from_rank, 7)];
            board[idx(from_rank, 7)] = '.';
            board[idx(from_rank, 5)] = rook;
        } else {
            // Queenside
            let rook = board[idx(from_rank, 0)];
            board[idx(from_rank, 0)] = '.';
            board[idx(from_rank, 3)] = rook;
        }
    }

    // Update castling rights
    // Note: Rhai's replace() modifies in-place and returns (), so don't reassign
    let castling = "" + state.castling;  // clone the string
    if piece == 'K' { castling.replace("K", ""); castling.replace("Q", ""); }
    if piece == 'k' { castling.replace("k", ""); castling.replace("q", ""); }
    if piece == 'R' && from_rank == 0 && from_file == 0 { castling.replace("Q", ""); }
    if piece == 'R' && from_rank == 0 && from_file == 7 { castling.replace("K", ""); }
    if piece == 'r' && from_rank == 7 && from_file == 0 { castling.replace("q", ""); }
    if piece == 'r' && from_rank == 7 && from_file == 7 { castling.replace("k", ""); }
    // Captured rook
    if to_rank == 0 && to_file == 0 { castling.replace("Q", ""); }
    if to_rank == 0 && to_file == 7 { castling.replace("K", ""); }
    if to_rank == 7 && to_file == 0 { castling.replace("q", ""); }
    if to_rank == 7 && to_file == 7 { castling.replace("k", ""); }
    if castling == "" { castling = "-"; }

    // Update en passant
    let ep_rank = -1;
    let ep_file = -1;
    if piece_lower == 'p' && abs_val(from_rank - to_rank) == 2 {
        ep_rank = (from_rank + to_rank) / 2;
        ep_file = from_file;
    }

    // Update halfmove clock
    let halfmove = state.halfmove + 1;
    if piece_lower == 'p' || captured != '.' { halfmove = 0; }

    // Update fullmove
    let fullmove = state.fullmove;
    if color == "b" { fullmove += 1; }

    // Switch active color
    let next_active = if color == "w" { "b" } else { "w" };

    #{
        board: board,
        active: next_active,
        castling: castling,
        ep_rank: ep_rank,
        ep_file: ep_file,
        halfmove: halfmove,
        fullmove: fullmove
    }
}

// ---- Pseudo-legal move generation ----
// Note: Rhai passes arrays by value, so gen functions return arrays.

fn gen_pawn_moves(state, rank, file, color) {
    let moves = [];
    let dir = if color == "w" { 1 } else { -1 };
    let start_rank = if color == "w" { 1 } else { 6 };
    let promo_rank = if color == "w" { 7 } else { 0 };

    let nr = rank + dir;
    if nr < 0 || nr > 7 { return moves; }

    // Forward one
    if state.board[idx(nr, file)] == '.' {
        if nr == promo_rank {
            for p in ["q", "r", "b", "n"] {
                moves.push([rank, file, nr, file, p]);
            }
        } else {
            moves.push([rank, file, nr, file, ""]);
            // Forward two
            if rank == start_rank {
                let nr2 = rank + 2 * dir;
                if state.board[idx(nr2, file)] == '.' {
                    moves.push([rank, file, nr2, file, ""]);
                }
            }
        }
    }

    // Captures
    for df in [-1, 1] {
        let nf = file + df;
        if nf < 0 || nf > 7 { continue; }
        let target = state.board[idx(nr, nf)];
        let is_capture = target != '.' && piece_color(target) != color;
        let is_ep = nr == state.ep_rank && nf == state.ep_file;
        if is_capture || is_ep {
            if nr == promo_rank {
                for p in ["q", "r", "b", "n"] {
                    moves.push([rank, file, nr, nf, p]);
                }
            } else {
                moves.push([rank, file, nr, nf, ""]);
            }
        }
    }
    moves
}

fn gen_knight_moves(state, rank, file, color) {
    let moves = [];
    let offsets = [[-2,-1],[-2,1],[-1,-2],[-1,2],[1,-2],[1,2],[2,-1],[2,1]];
    for off in offsets {
        let nr = rank + off[0];
        let nf = file + off[1];
        if nr >= 0 && nr <= 7 && nf >= 0 && nf <= 7 {
            let target = state.board[idx(nr, nf)];
            if target == '.' || piece_color(target) != color {
                moves.push([rank, file, nr, nf, ""]);
            }
        }
    }
    moves
}

fn gen_sliding_moves(state, rank, file, color, dirs) {
    let moves = [];
    for dir in dirs {
        let r = rank + dir[0];
        let f = file + dir[1];
        while r >= 0 && r <= 7 && f >= 0 && f <= 7 {
            let target = state.board[idx(r, f)];
            if target == '.' {
                moves.push([rank, file, r, f, ""]);
            } else {
                if piece_color(target) != color {
                    moves.push([rank, file, r, f, ""]);
                }
                break;
            }
            r += dir[0];
            f += dir[1];
        }
    }
    moves
}

fn gen_king_moves(state, rank, file, color) {
    let moves = [];
    for dr in [-1, 0, 1] {
        for df in [-1, 0, 1] {
            if dr == 0 && df == 0 { continue; }
            let nr = rank + dr;
            let nf = file + df;
            if nr >= 0 && nr <= 7 && nf >= 0 && nf <= 7 {
                let target = state.board[idx(nr, nf)];
                if target == '.' || piece_color(target) != color {
                    moves.push([rank, file, nr, nf, ""]);
                }
            }
        }
    }

    // Castling
    let opponent = if color == "w" { "b" } else { "w" };
    let back_rank = if color == "w" { 0 } else { 7 };

    if rank == back_rank && file == 4 {
        // Kingside
        let ks = if color == "w" { "K" } else { "k" };
        if state.castling.contains(ks)
            && state.board[idx(back_rank, 5)] == '.'
            && state.board[idx(back_rank, 6)] == '.'
            && !is_attacked_by(state.board, back_rank, 4, opponent)
            && !is_attacked_by(state.board, back_rank, 5, opponent)
            && !is_attacked_by(state.board, back_rank, 6, opponent)
        {
            moves.push([rank, file, rank, 6, ""]);
        }

        // Queenside
        let qs = if color == "w" { "Q" } else { "q" };
        if state.castling.contains(qs)
            && state.board[idx(back_rank, 1)] == '.'
            && state.board[idx(back_rank, 2)] == '.'
            && state.board[idx(back_rank, 3)] == '.'
            && !is_attacked_by(state.board, back_rank, 4, opponent)
            && !is_attacked_by(state.board, back_rank, 3, opponent)
            && !is_attacked_by(state.board, back_rank, 2, opponent)
        {
            moves.push([rank, file, rank, 2, ""]);
        }
    }
    moves
}

fn generate_all_moves(state) {
    let moves = [];
    let color = state.active;
    let diag = [[-1,-1],[-1,1],[1,-1],[1,1]];
    let straight = [[-1,0],[1,0],[0,-1],[0,1]];
    let all_dirs = [[-1,-1],[-1,1],[1,-1],[1,1],[-1,0],[1,0],[0,-1],[0,1]];

    for rank in 0..8 {
        for file in 0..8 {
            let ch = state.board[idx(rank, file)];
            if ch == '.' { continue; }
            if piece_color(ch) != color { continue; }

            let kind = to_lower(ch);
            if kind == 'p' { moves += gen_pawn_moves(state, rank, file, color); }
            if kind == 'n' { moves += gen_knight_moves(state, rank, file, color); }
            if kind == 'b' { moves += gen_sliding_moves(state, rank, file, color, diag); }
            if kind == 'r' { moves += gen_sliding_moves(state, rank, file, color, straight); }
            if kind == 'q' { moves += gen_sliding_moves(state, rank, file, color, all_dirs); }
            if kind == 'k' { moves += gen_king_moves(state, rank, file, color); }
        }
    }
    moves
}

fn legal_moves(state) {
    let pseudo = generate_all_moves(state);
    let legal = [];
    let color = state.active;

    for mv in pseudo {
        let new_state = apply_move_unchecked(state, mv[0], mv[1], mv[2], mv[3], mv[4]);
        if !is_in_check(new_state.board, color) {
            legal.push(mv);
        }
    }
    legal
}

// ---- Game status ----

fn compute_status(state) {
    let moves = legal_moves(state);
    if moves.len() == 0 {
        if is_in_check(state.board, state.active) {
            let winner = if state.active == "w" { "black_wins" } else { "white_wins" };
            return winner;
        } else {
            return "stalemate";
        }
    }
    if state.halfmove >= 100 {
        return "draw";
    }
    "active"
}

// ---- Parse UCI move string ----

fn parse_uci(move_str) {
    if move_str.len() < 4 || move_str.len() > 5 {
        throw "invalid move format: " + move_str;
    }
    let from_file = file_from_char(move_str[0]);
    let from_rank = move_str[1].to_int() - 49;
    let to_file = file_from_char(move_str[2]);
    let to_rank = move_str[3].to_int() - 49;

    let promo = "";
    if move_str.len() == 5 {
        promo = "" + move_str[4];
    }

    [from_rank, from_file, to_rank, to_file, promo]
}

// ===== THE VALIDATOR =====

fn validate_make_move(state, args) {
    if state.status != "active" {
        throw "game is not active";
    }

    let move_str = args.move_uci;
    let parsed = parse_uci(move_str);
    let from_rank = parsed[0];
    let from_file = parsed[1];
    let to_rank = parsed[2];
    let to_file = parsed[3];
    let promo = parsed[4];

    // Parse current board from FEN
    let board_state = fen_to_board(state.fen);

    // Verify a piece exists and belongs to the active player
    let piece = board_state.board[idx(from_rank, from_file)];
    if piece == '.' {
        throw "no piece at source square";
    }
    if piece_color(piece) != board_state.active {
        throw "not your piece";
    }

    // Check that this move is legal
    let legal = legal_moves(board_state);
    let found = false;
    for lm in legal {
        if lm[0] == from_rank && lm[1] == from_file && lm[2] == to_rank && lm[3] == to_file {
            if promo == "" || lm[4] == promo {
                found = true;
                // Use the legal move's promotion if we didn't specify one
                if promo == "" && lm[4] != "" {
                    promo = lm[4];
                }
                break;
            }
        }
    }
    if !found {
        throw "illegal move: " + move_str;
    }

    // Apply the move
    let new_board = apply_move_unchecked(board_state, from_rank, from_file, to_rank, to_file, promo);
    let new_fen = board_to_fen(new_board);
    let new_status = compute_status(new_board);

    // Return new state
    #{
        fen: new_fen,
        status: new_status,
        move_count: state.move_count + 1,
        last_move: move_str
    }
}

fn validate_resign(state, args) {
    if state.status != "active" {
        throw "game is not active";
    }
    let board_state = fen_to_board(state.fen);
    let result = if board_state.active == "w" { "black_wins" } else { "white_wins" };
    #{
        fen: state.fen,
        status: result,
        move_count: state.move_count,
        last_move: state.last_move
    }
}
"#;
