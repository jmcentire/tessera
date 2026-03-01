/// Chess board representation and move validation.
///
/// This module provides a Rust reference implementation of chess rules.
/// The actual game validation is done by the embedded Rhai validator
/// in the Tessera document. This Rust code is used for display (SAN
/// notation, board rendering) and for its own unit tests.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Color {
    White,
    Black,
}

impl Color {
    pub fn opposite(self) -> Color {
        match self {
            Color::White => Color::Black,
            Color::Black => Color::White,
        }
    }

    pub fn fen_char(self) -> char {
        match self {
            Color::White => 'w',
            Color::Black => 'b',
        }
    }

    pub fn from_fen(c: char) -> Option<Color> {
        match c {
            'w' => Some(Color::White),
            'b' => Some(Color::Black),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Color::White => "White",
            Color::Black => "Black",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PieceKind {
    Pawn,
    Knight,
    Bishop,
    Rook,
    Queen,
    King,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Piece {
    pub color: Color,
    pub kind: PieceKind,
}

impl Piece {
    pub fn fen_char(self) -> char {
        let c = match self.kind {
            PieceKind::Pawn => 'p',
            PieceKind::Knight => 'n',
            PieceKind::Bishop => 'b',
            PieceKind::Rook => 'r',
            PieceKind::Queen => 'q',
            PieceKind::King => 'k',
        };
        match self.color {
            Color::White => c.to_ascii_uppercase(),
            Color::Black => c,
        }
    }

    pub fn from_fen(c: char) -> Option<Piece> {
        let color = if c.is_ascii_uppercase() {
            Color::White
        } else {
            Color::Black
        };
        let kind = match c.to_ascii_lowercase() {
            'p' => PieceKind::Pawn,
            'n' => PieceKind::Knight,
            'b' => PieceKind::Bishop,
            'r' => PieceKind::Rook,
            'q' => PieceKind::Queen,
            'k' => PieceKind::King,
            _ => return None,
        };
        Some(Piece { color, kind })
    }

    pub fn symbol(self) -> &'static str {
        match (self.color, self.kind) {
            (Color::White, PieceKind::King) => "\u{2654}",
            (Color::White, PieceKind::Queen) => "\u{2655}",
            (Color::White, PieceKind::Rook) => "\u{2656}",
            (Color::White, PieceKind::Bishop) => "\u{2657}",
            (Color::White, PieceKind::Knight) => "\u{2658}",
            (Color::White, PieceKind::Pawn) => "\u{2659}",
            (Color::Black, PieceKind::King) => "\u{265A}",
            (Color::Black, PieceKind::Queen) => "\u{265B}",
            (Color::Black, PieceKind::Rook) => "\u{265C}",
            (Color::Black, PieceKind::Bishop) => "\u{265D}",
            (Color::Black, PieceKind::Knight) => "\u{265E}",
            (Color::Black, PieceKind::Pawn) => "\u{265F}",
        }
    }
}

/// A chess move in coordinate notation (e.g., "e2e4", "e7e8q").
#[derive(Clone, Debug)]
pub struct Move {
    pub from: (usize, usize), // (rank, file), 0-indexed from white's perspective
    pub to: (usize, usize),
    pub promotion: Option<PieceKind>,
}

impl Move {
    /// Parse a move from UCI-style string: "e2e4" or "e7e8q"
    pub fn parse(s: &str) -> Result<Move, String> {
        let chars: Vec<char> = s.chars().collect();
        if chars.len() < 4 || chars.len() > 5 {
            return Err(format!("invalid move '{}': expected 4-5 chars", s));
        }

        let from_file = file_from_char(chars[0])?;
        let from_rank = rank_from_char(chars[1])?;
        let to_file = file_from_char(chars[2])?;
        let to_rank = rank_from_char(chars[3])?;

        let promotion = if chars.len() == 5 {
            Some(match chars[4] {
                'q' => PieceKind::Queen,
                'r' => PieceKind::Rook,
                'b' => PieceKind::Bishop,
                'n' => PieceKind::Knight,
                c => return Err(format!("invalid promotion piece: '{}'", c)),
            })
        } else {
            None
        };

        Ok(Move {
            from: (from_rank, from_file),
            to: (to_rank, to_file),
            promotion,
        })
    }

    pub fn to_uci(&self) -> String {
        let mut s = format!(
            "{}{}{}{}",
            file_to_char(self.from.1),
            rank_to_char(self.from.0),
            file_to_char(self.to.1),
            rank_to_char(self.to.0),
        );
        if let Some(promo) = self.promotion {
            s.push(match promo {
                PieceKind::Queen => 'q',
                PieceKind::Rook => 'r',
                PieceKind::Bishop => 'b',
                PieceKind::Knight => 'n',
                _ => '?',
            });
        }
        s
    }

    /// Format as Standard Algebraic Notation (simplified).
    pub fn to_san(&self, board: &Board) -> String {
        let piece = board.squares[self.from.0][self.from.1];
        let capture = board.squares[self.to.0][self.to.1].is_some()
            || (piece.map(|p| p.kind) == Some(PieceKind::Pawn)
                && self.from.1 != self.to.1
                && board.squares[self.to.0][self.to.1].is_none());

        // Castling
        if let Some(p) = piece {
            if p.kind == PieceKind::King && self.from.1.abs_diff(self.to.1) == 2 {
                return if self.to.1 > self.from.1 {
                    "O-O".into()
                } else {
                    "O-O-O".into()
                };
            }
        }

        let mut s = String::new();

        if let Some(p) = piece {
            match p.kind {
                PieceKind::Pawn => {
                    if capture {
                        s.push(file_to_char(self.from.1));
                    }
                }
                PieceKind::Knight => s.push('N'),
                PieceKind::Bishop => s.push('B'),
                PieceKind::Rook => s.push('R'),
                PieceKind::Queen => s.push('Q'),
                PieceKind::King => s.push('K'),
            }
        }

        if capture {
            s.push('x');
        }

        s.push(file_to_char(self.to.1));
        s.push(rank_to_char(self.to.0));

        if let Some(promo) = self.promotion {
            s.push('=');
            s.push(match promo {
                PieceKind::Queen => 'Q',
                PieceKind::Rook => 'R',
                PieceKind::Bishop => 'B',
                PieceKind::Knight => 'N',
                _ => '?',
            });
        }

        s
    }
}

fn file_from_char(c: char) -> Result<usize, String> {
    if ('a'..='h').contains(&c) {
        Ok((c as usize) - ('a' as usize))
    } else {
        Err(format!("invalid file: '{}'", c))
    }
}

fn rank_from_char(c: char) -> Result<usize, String> {
    if ('1'..='8').contains(&c) {
        Ok((c as usize) - ('1' as usize))
    } else {
        Err(format!("invalid rank: '{}'", c))
    }
}

fn file_to_char(f: usize) -> char {
    (b'a' + f as u8) as char
}

fn rank_to_char(r: usize) -> char {
    (b'1' + r as u8) as char
}

#[derive(Clone, Debug)]
pub struct CastlingRights {
    pub white_kingside: bool,
    pub white_queenside: bool,
    pub black_kingside: bool,
    pub black_queenside: bool,
}

impl CastlingRights {
    pub fn to_fen(&self) -> String {
        let mut s = String::new();
        if self.white_kingside {
            s.push('K');
        }
        if self.white_queenside {
            s.push('Q');
        }
        if self.black_kingside {
            s.push('k');
        }
        if self.black_queenside {
            s.push('q');
        }
        if s.is_empty() {
            s.push('-');
        }
        s
    }

    pub fn from_fen(s: &str) -> CastlingRights {
        CastlingRights {
            white_kingside: s.contains('K'),
            white_queenside: s.contains('Q'),
            black_kingside: s.contains('k'),
            black_queenside: s.contains('q'),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GameStatus {
    Active,
    Checkmate(Color), // The color that won
    Stalemate,
    Draw,
}

impl GameStatus {
    pub fn as_status_str(&self) -> String {
        match self {
            GameStatus::Active => "active".into(),
            GameStatus::Checkmate(Color::White) => "white_wins".into(),
            GameStatus::Checkmate(Color::Black) => "black_wins".into(),
            GameStatus::Stalemate => "stalemate".into(),
            GameStatus::Draw => "draw".into(),
        }
    }
}

/// Full chess board state.
#[derive(Clone, Debug)]
pub struct Board {
    pub squares: [[Option<Piece>; 8]; 8], // [rank][file]
    pub active: Color,
    pub castling: CastlingRights,
    pub en_passant: Option<(usize, usize)>, // target square
    pub halfmove: u32,
    pub fullmove: u32,
}

pub const STARTING_FEN: &str = "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1";

impl Board {
    pub fn starting() -> Board {
        Board::from_fen(STARTING_FEN).unwrap()
    }

    pub fn from_fen(fen: &str) -> Result<Board, String> {
        let parts: Vec<&str> = fen.split_whitespace().collect();
        if parts.len() != 6 {
            return Err(format!("FEN must have 6 parts, got {}", parts.len()));
        }

        // Parse position
        let mut squares = [[None; 8]; 8];
        let ranks: Vec<&str> = parts[0].split('/').collect();
        if ranks.len() != 8 {
            return Err("FEN position must have 8 ranks".into());
        }
        for (ri, rank_str) in ranks.iter().enumerate() {
            let rank = 7 - ri; // FEN starts from rank 8
            let mut file = 0;
            for c in rank_str.chars() {
                if let Some(skip) = c.to_digit(10) {
                    file += skip as usize;
                } else if let Some(piece) = Piece::from_fen(c) {
                    if file >= 8 {
                        return Err("too many pieces in rank".into());
                    }
                    squares[rank][file] = Some(piece);
                    file += 1;
                } else {
                    return Err(format!("invalid FEN character: '{}'", c));
                }
            }
            if file != 8 {
                return Err(format!("rank {} has {} files, expected 8", rank + 1, file));
            }
        }

        let active = Color::from_fen(parts[1].chars().next().unwrap_or('?'))
            .ok_or("invalid active color")?;
        let castling = CastlingRights::from_fen(parts[2]);

        let en_passant = if parts[3] == "-" {
            None
        } else {
            let ep_chars: Vec<char> = parts[3].chars().collect();
            if ep_chars.len() != 2 {
                return Err("invalid en passant square".into());
            }
            Some((rank_from_char(ep_chars[1])?, file_from_char(ep_chars[0])?))
        };

        let halfmove: u32 = parts[4].parse().map_err(|_| "invalid halfmove clock")?;
        let fullmove: u32 = parts[5].parse().map_err(|_| "invalid fullmove number")?;

        Ok(Board {
            squares,
            active,
            castling,
            en_passant,
            halfmove,
            fullmove,
        })
    }

    pub fn to_fen(&self) -> String {
        let mut fen = String::new();

        // Position
        for rank in (0..8).rev() {
            let mut empty = 0;
            for file in 0..8 {
                match self.squares[rank][file] {
                    Some(piece) => {
                        if empty > 0 {
                            fen.push_str(&empty.to_string());
                            empty = 0;
                        }
                        fen.push(piece.fen_char());
                    }
                    None => empty += 1,
                }
            }
            if empty > 0 {
                fen.push_str(&empty.to_string());
            }
            if rank > 0 {
                fen.push('/');
            }
        }

        fen.push(' ');
        fen.push(self.active.fen_char());
        fen.push(' ');
        fen.push_str(&self.castling.to_fen());
        fen.push(' ');

        match self.en_passant {
            Some((r, f)) => {
                fen.push(file_to_char(f));
                fen.push(rank_to_char(r));
            }
            None => fen.push('-'),
        }

        fen.push_str(&format!(" {} {}", self.halfmove, self.fullmove));
        fen
    }

    fn set(&mut self, rank: usize, file: usize, piece: Option<Piece>) {
        self.squares[rank][file] = piece;
    }

    /// Find the king position for a color.
    fn find_king(&self, color: Color) -> Option<(usize, usize)> {
        for rank in 0..8 {
            for file in 0..8 {
                if let Some(p) = self.squares[rank][file] {
                    if p.color == color && p.kind == PieceKind::King {
                        return Some((rank, file));
                    }
                }
            }
        }
        None
    }

    /// Check if a square is attacked by any piece of the given color.
    fn is_attacked_by(&self, rank: usize, file: usize, color: Color) -> bool {
        // Check pawn attacks
        let pawn_dir: isize = match color {
            Color::White => 1,
            Color::Black => -1,
        };
        let pr = rank as isize - pawn_dir;
        if (0..8).contains(&pr) {
            for df in [-1isize, 1] {
                let pf = file as isize + df;
                if (0..8).contains(&pf) {
                    if let Some(p) = self.squares[pr as usize][pf as usize] {
                        if p.color == color && p.kind == PieceKind::Pawn {
                            return true;
                        }
                    }
                }
            }
        }

        // Check knight attacks
        for (dr, df) in [
            (-2, -1),
            (-2, 1),
            (-1, -2),
            (-1, 2),
            (1, -2),
            (1, 2),
            (2, -1),
            (2, 1),
        ] {
            let nr = rank as isize + dr;
            let nf = file as isize + df;
            if (0..8).contains(&nr) && (0..8).contains(&nf) {
                if let Some(p) = self.squares[nr as usize][nf as usize] {
                    if p.color == color && p.kind == PieceKind::Knight {
                        return true;
                    }
                }
            }
        }

        // Check king attacks (for adjacent squares)
        for dr in -1..=1isize {
            for df in -1..=1isize {
                if dr == 0 && df == 0 {
                    continue;
                }
                let kr = rank as isize + dr;
                let kf = file as isize + df;
                if (0..8).contains(&kr) && (0..8).contains(&kf) {
                    if let Some(p) = self.squares[kr as usize][kf as usize] {
                        if p.color == color && p.kind == PieceKind::King {
                            return true;
                        }
                    }
                }
            }
        }

        // Check sliding pieces (bishop/rook/queen)
        // Bishop/queen diagonals
        for (dr, df) in [(-1isize, -1isize), (-1, 1), (1, -1), (1, 1)] {
            let mut r = rank as isize + dr;
            let mut f = file as isize + df;
            while (0..8).contains(&r) && (0..8).contains(&f) {
                if let Some(p) = self.squares[r as usize][f as usize] {
                    if p.color == color
                        && (p.kind == PieceKind::Bishop || p.kind == PieceKind::Queen)
                    {
                        return true;
                    }
                    break; // blocked
                }
                r += dr;
                f += df;
            }
        }

        // Rook/queen straights
        for (dr, df) in [(-1isize, 0isize), (1, 0), (0, -1), (0, 1)] {
            let mut r = rank as isize + dr;
            let mut f = file as isize + df;
            while (0..8).contains(&r) && (0..8).contains(&f) {
                if let Some(p) = self.squares[r as usize][f as usize] {
                    if p.color == color && (p.kind == PieceKind::Rook || p.kind == PieceKind::Queen)
                    {
                        return true;
                    }
                    break; // blocked
                }
                r += dr;
                f += df;
            }
        }

        false
    }

    /// Is the given color's king in check?
    pub fn is_in_check(&self, color: Color) -> bool {
        if let Some((kr, kf)) = self.find_king(color) {
            self.is_attacked_by(kr, kf, color.opposite())
        } else {
            false
        }
    }

    /// Apply a move to produce a new board state. Does NOT validate legality.
    fn apply_move_unchecked(&self, mv: &Move) -> Board {
        let mut board = self.clone();
        let piece = board.squares[mv.from.0][mv.from.1];

        // Move the piece
        board.set(mv.to.0, mv.to.1, piece);
        board.set(mv.from.0, mv.from.1, None);

        if let Some(p) = piece {
            // Handle pawn promotion
            if p.kind == PieceKind::Pawn && (mv.to.0 == 0 || mv.to.0 == 7) {
                let promo_kind = mv.promotion.unwrap_or(PieceKind::Queen);
                board.set(
                    mv.to.0,
                    mv.to.1,
                    Some(Piece {
                        color: p.color,
                        kind: promo_kind,
                    }),
                );
            }

            // Handle en passant capture
            if p.kind == PieceKind::Pawn && Some(mv.to) == self.en_passant {
                let captured_rank = mv.from.0; // pawn is on same rank as capturing pawn
                board.set(captured_rank, mv.to.1, None);
            }

            // Handle castling: move the rook
            if p.kind == PieceKind::King && mv.from.1.abs_diff(mv.to.1) == 2 {
                let rank = mv.from.0;
                if mv.to.1 > mv.from.1 {
                    // Kingside
                    let rook = board.squares[rank][7];
                    board.set(rank, 7, None);
                    board.set(rank, 5, rook);
                } else {
                    // Queenside
                    let rook = board.squares[rank][0];
                    board.set(rank, 0, None);
                    board.set(rank, 3, rook);
                }
            }

            // Update castling rights
            if p.kind == PieceKind::King {
                match p.color {
                    Color::White => {
                        board.castling.white_kingside = false;
                        board.castling.white_queenside = false;
                    }
                    Color::Black => {
                        board.castling.black_kingside = false;
                        board.castling.black_queenside = false;
                    }
                }
            }
            if p.kind == PieceKind::Rook {
                match (p.color, mv.from) {
                    (Color::White, (0, 0)) => board.castling.white_queenside = false,
                    (Color::White, (0, 7)) => board.castling.white_kingside = false,
                    (Color::Black, (7, 0)) => board.castling.black_queenside = false,
                    (Color::Black, (7, 7)) => board.castling.black_kingside = false,
                    _ => {}
                }
            }
            // If a rook is captured
            match mv.to {
                (0, 0) => board.castling.white_queenside = false,
                (0, 7) => board.castling.white_kingside = false,
                (7, 0) => board.castling.black_queenside = false,
                (7, 7) => board.castling.black_kingside = false,
                _ => {}
            }

            // Update en passant
            if p.kind == PieceKind::Pawn && mv.from.0.abs_diff(mv.to.0) == 2 {
                let ep_rank = (mv.from.0 + mv.to.0) / 2;
                board.en_passant = Some((ep_rank, mv.from.1));
            } else {
                board.en_passant = None;
            }

            // Update halfmove clock
            if p.kind == PieceKind::Pawn || self.squares[mv.to.0][mv.to.1].is_some() {
                board.halfmove = 0;
            } else {
                board.halfmove = self.halfmove + 1;
            }

            // Update fullmove number
            if p.color == Color::Black {
                board.fullmove = self.fullmove + 1;
            }
        }

        // Switch active color
        board.active = self.active.opposite();

        board
    }

    /// Generate all pseudo-legal moves for a piece at (rank, file).
    fn pseudo_legal_moves_from(&self, rank: usize, file: usize) -> Vec<Move> {
        let piece = match self.squares[rank][file] {
            Some(p) if p.color == self.active => p,
            _ => return vec![],
        };

        let mut moves = Vec::new();

        match piece.kind {
            PieceKind::Pawn => self.gen_pawn_moves(rank, file, piece.color, &mut moves),
            PieceKind::Knight => self.gen_knight_moves(rank, file, piece.color, &mut moves),
            PieceKind::Bishop => {
                self.gen_sliding_moves(rank, file, piece.color, true, false, &mut moves)
            }
            PieceKind::Rook => {
                self.gen_sliding_moves(rank, file, piece.color, false, true, &mut moves)
            }
            PieceKind::Queen => {
                self.gen_sliding_moves(rank, file, piece.color, true, true, &mut moves)
            }
            PieceKind::King => self.gen_king_moves(rank, file, piece.color, &mut moves),
        }

        moves
    }

    fn gen_pawn_moves(&self, rank: usize, file: usize, color: Color, moves: &mut Vec<Move>) {
        let dir: isize = match color {
            Color::White => 1,
            Color::Black => -1,
        };
        let start_rank = match color {
            Color::White => 1,
            Color::Black => 6,
        };
        let promo_rank = match color {
            Color::White => 7,
            Color::Black => 0,
        };

        let next_rank = rank as isize + dir;
        if !(0..8).contains(&next_rank) {
            return;
        }
        let nr = next_rank as usize;

        // Forward one
        if self.squares[nr][file].is_none() {
            if nr == promo_rank {
                for kind in [
                    PieceKind::Queen,
                    PieceKind::Rook,
                    PieceKind::Bishop,
                    PieceKind::Knight,
                ] {
                    moves.push(Move {
                        from: (rank, file),
                        to: (nr, file),
                        promotion: Some(kind),
                    });
                }
            } else {
                moves.push(Move {
                    from: (rank, file),
                    to: (nr, file),
                    promotion: None,
                });

                // Forward two from starting rank
                if rank == start_rank {
                    let two_rank = (rank as isize + 2 * dir) as usize;
                    if self.squares[two_rank][file].is_none() {
                        moves.push(Move {
                            from: (rank, file),
                            to: (two_rank, file),
                            promotion: None,
                        });
                    }
                }
            }
        }

        // Captures (including en passant)
        for df in [-1isize, 1] {
            let nf = file as isize + df;
            if !(0..8).contains(&nf) {
                continue;
            }
            let nf = nf as usize;

            let is_capture = self.squares[nr][nf].is_some_and(|p| p.color != color);
            let is_ep = self.en_passant == Some((nr, nf));

            if is_capture || is_ep {
                if nr == promo_rank {
                    for kind in [
                        PieceKind::Queen,
                        PieceKind::Rook,
                        PieceKind::Bishop,
                        PieceKind::Knight,
                    ] {
                        moves.push(Move {
                            from: (rank, file),
                            to: (nr, nf),
                            promotion: Some(kind),
                        });
                    }
                } else {
                    moves.push(Move {
                        from: (rank, file),
                        to: (nr, nf),
                        promotion: None,
                    });
                }
            }
        }
    }

    fn gen_knight_moves(&self, rank: usize, file: usize, color: Color, moves: &mut Vec<Move>) {
        for (dr, df) in [
            (-2, -1),
            (-2, 1),
            (-1, -2),
            (-1, 2),
            (1, -2),
            (1, 2),
            (2, -1),
            (2, 1),
        ] {
            let nr = rank as isize + dr;
            let nf = file as isize + df;
            if (0..8).contains(&nr) && (0..8).contains(&nf) {
                let (nr, nf) = (nr as usize, nf as usize);
                if self.squares[nr][nf].is_none_or(|p| p.color != color) {
                    moves.push(Move {
                        from: (rank, file),
                        to: (nr, nf),
                        promotion: None,
                    });
                }
            }
        }
    }

    fn gen_sliding_moves(
        &self,
        rank: usize,
        file: usize,
        color: Color,
        diagonal: bool,
        straight: bool,
        moves: &mut Vec<Move>,
    ) {
        let mut dirs: Vec<(isize, isize)> = Vec::new();
        if diagonal {
            dirs.extend_from_slice(&[(-1, -1), (-1, 1), (1, -1), (1, 1)]);
        }
        if straight {
            dirs.extend_from_slice(&[(-1, 0), (1, 0), (0, -1), (0, 1)]);
        }

        for (dr, df) in dirs {
            let mut r = rank as isize + dr;
            let mut f = file as isize + df;
            while (0..8).contains(&r) && (0..8).contains(&f) {
                let (ur, uf) = (r as usize, f as usize);
                match self.squares[ur][uf] {
                    None => {
                        moves.push(Move {
                            from: (rank, file),
                            to: (ur, uf),
                            promotion: None,
                        });
                    }
                    Some(p) if p.color != color => {
                        moves.push(Move {
                            from: (rank, file),
                            to: (ur, uf),
                            promotion: None,
                        });
                        break;
                    }
                    _ => break, // own piece
                }
                r += dr;
                f += df;
            }
        }
    }

    fn gen_king_moves(&self, rank: usize, file: usize, color: Color, moves: &mut Vec<Move>) {
        for dr in -1..=1isize {
            for df in -1..=1isize {
                if dr == 0 && df == 0 {
                    continue;
                }
                let nr = rank as isize + dr;
                let nf = file as isize + df;
                if (0..8).contains(&nr) && (0..8).contains(&nf) {
                    let (nr, nf) = (nr as usize, nf as usize);
                    if self.squares[nr][nf].is_none_or(|p| p.color != color) {
                        moves.push(Move {
                            from: (rank, file),
                            to: (nr, nf),
                            promotion: None,
                        });
                    }
                }
            }
        }

        // Castling
        let opponent = color.opposite();
        let back_rank = match color {
            Color::White => 0,
            Color::Black => 7,
        };

        if rank == back_rank && file == 4 {
            // Kingside
            let can_ks = match color {
                Color::White => self.castling.white_kingside,
                Color::Black => self.castling.black_kingside,
            };
            if can_ks
                && self.squares[back_rank][5].is_none()
                && self.squares[back_rank][6].is_none()
                && !self.is_attacked_by(back_rank, 4, opponent)
                && !self.is_attacked_by(back_rank, 5, opponent)
                && !self.is_attacked_by(back_rank, 6, opponent)
            {
                moves.push(Move {
                    from: (rank, file),
                    to: (rank, 6),
                    promotion: None,
                });
            }

            // Queenside
            let can_qs = match color {
                Color::White => self.castling.white_queenside,
                Color::Black => self.castling.black_queenside,
            };
            if can_qs
                && self.squares[back_rank][1].is_none()
                && self.squares[back_rank][2].is_none()
                && self.squares[back_rank][3].is_none()
                && !self.is_attacked_by(back_rank, 4, opponent)
                && !self.is_attacked_by(back_rank, 3, opponent)
                && !self.is_attacked_by(back_rank, 2, opponent)
            {
                moves.push(Move {
                    from: (rank, file),
                    to: (rank, 2),
                    promotion: None,
                });
            }
        }
    }

    /// Generate all legal moves for the active color.
    pub fn legal_moves(&self) -> Vec<Move> {
        let mut legal = Vec::new();

        for rank in 0..8 {
            for file in 0..8 {
                for mv in self.pseudo_legal_moves_from(rank, file) {
                    let new_board = self.apply_move_unchecked(&mv);
                    // Move is legal if it doesn't leave our king in check
                    if !new_board.is_in_check(self.active) {
                        legal.push(mv);
                    }
                }
            }
        }

        legal
    }

    /// Validate and apply a move. Returns the new board or an error.
    pub fn make_move(&self, mv: &Move) -> Result<Board, String> {
        // Must move own piece
        let piece = self.squares[mv.from.0][mv.from.1]
            .ok_or_else(|| format!("no piece at {}", mv.to_uci()))?;
        if piece.color != self.active {
            return Err(format!(
                "not {}'s turn (trying to move {} piece)",
                self.active.name(),
                piece.color.name()
            ));
        }

        // Check if this move is in the legal moves list
        let legal = self.legal_moves();
        let is_legal = legal
            .iter()
            .any(|lm| lm.from == mv.from && lm.to == mv.to && lm.promotion == mv.promotion);

        if !is_legal {
            return Err(format!("illegal move: {}", mv.to_uci()));
        }

        Ok(self.apply_move_unchecked(mv))
    }

    /// Determine game status after a move has been applied.
    pub fn status(&self) -> GameStatus {
        let legal = self.legal_moves();
        if legal.is_empty() {
            if self.is_in_check(self.active) {
                // The player to move is in check with no legal moves = checkmate
                // The winner is the opponent
                GameStatus::Checkmate(self.active.opposite())
            } else {
                GameStatus::Stalemate
            }
        } else if self.halfmove >= 100 {
            GameStatus::Draw // 50-move rule
        } else {
            GameStatus::Active
        }
    }

    /// Pretty-print the board.
    pub fn display(&self) -> String {
        let mut s = String::new();
        s.push_str("  a b c d e f g h\n");
        for rank in (0..8).rev() {
            s.push_str(&format!("{} ", rank + 1));
            for file in 0..8 {
                match self.squares[rank][file] {
                    Some(p) => {
                        s.push_str(p.symbol());
                        s.push(' ');
                    }
                    None => {
                        if (rank + file) % 2 == 0 {
                            s.push_str(". ");
                        } else {
                            s.push_str("  ");
                        }
                    }
                }
            }
            s.push_str(&format!("{}", rank + 1));
            s.push('\n');
        }
        s.push_str("  a b c d e f g h\n");
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starting_position_fen_round_trip() {
        let board = Board::starting();
        assert_eq!(board.to_fen(), STARTING_FEN);
    }

    #[test]
    fn starting_position_has_20_legal_moves() {
        let board = Board::starting();
        assert_eq!(board.legal_moves().len(), 20);
    }

    #[test]
    fn pawn_move_e2e4() {
        let board = Board::starting();
        let mv = Move::parse("e2e4").unwrap();
        let new_board = board.make_move(&mv).unwrap();
        assert_eq!(new_board.active, Color::Black);
        assert!(new_board.squares[3][4].is_some()); // e4 has a pawn
        assert!(new_board.squares[1][4].is_none()); // e2 is empty
        assert_eq!(new_board.en_passant, Some((2, 4))); // e3
    }

    #[test]
    fn illegal_move_rejected() {
        let board = Board::starting();
        let mv = Move::parse("e2e5").unwrap(); // pawn can't jump 3 squares
        assert!(board.make_move(&mv).is_err());
    }

    #[test]
    fn scholars_mate() {
        let mut board = Board::starting();
        let moves = ["e2e4", "e7e5", "f1c4", "b8c6", "d1h5", "g8f6", "h5f7"];
        for m in &moves {
            let mv = Move::parse(m).unwrap();
            board = board.make_move(&mv).unwrap();
        }
        assert_eq!(board.status(), GameStatus::Checkmate(Color::White));
    }

    #[test]
    fn castling_kingside() {
        // Position where white can castle kingside
        let board =
            Board::from_fen("r1bqkbnr/pppppppp/2n5/4P3/2B5/5N2/PPPP1PPP/RNBQK2R w KQkq - 4 4")
                .unwrap();
        let mv = Move::parse("e1g1").unwrap();
        let new_board = board.make_move(&mv).unwrap();
        assert!(new_board.squares[0][6].unwrap().kind == PieceKind::King);
        assert!(new_board.squares[0][5].unwrap().kind == PieceKind::Rook);
    }

    #[test]
    fn en_passant_capture() {
        // White pawn on e5, black just played d7d5
        let board = Board::from_fen("rnbqkbnr/ppp1pppp/8/3pP3/8/8/PPPP1PPP/RNBQKBNR w KQkq d6 0 3")
            .unwrap();
        let mv = Move::parse("e5d6").unwrap();
        let new_board = board.make_move(&mv).unwrap();
        assert!(new_board.squares[5][3].is_some()); // d6 has white pawn
        assert!(new_board.squares[4][3].is_none()); // d5 black pawn captured
    }

    #[test]
    fn pawn_promotion() {
        let board = Board::from_fen("8/P7/8/8/8/8/8/4K2k w - - 0 1").unwrap();
        let mv = Move::parse("a7a8q").unwrap();
        let new_board = board.make_move(&mv).unwrap();
        let promoted = new_board.squares[7][0].unwrap();
        assert_eq!(promoted.kind, PieceKind::Queen);
        assert_eq!(promoted.color, Color::White);
    }

    #[test]
    fn cannot_move_into_check() {
        // King on e1, enemy rook on e8 -- king can't move to e2
        let board = Board::from_fen("4r3/8/8/8/8/8/8/4K3 w - - 0 1").unwrap();
        let mv = Move::parse("e1e2").unwrap();
        assert!(board.make_move(&mv).is_err());
    }

    #[test]
    fn stalemate_detection() {
        // King on a1, no other white pieces, black queen on b3 -- stalemate
        let board = Board::from_fen("8/8/8/8/8/1q6/8/K7 w - - 0 1").unwrap();
        assert_eq!(board.status(), GameStatus::Stalemate);
    }
}
