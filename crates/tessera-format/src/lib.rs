use tessera_core::{Document, TesseraError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FormatError {
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("CBOR encode error: {0}")]
    CborEncode(String),

    #[error("CBOR decode error: {0}")]
    CborDecode(String),

    #[error("unknown format")]
    UnknownFormat,
}

impl From<FormatError> for TesseraError {
    fn from(e: FormatError) -> Self {
        TesseraError::Serialization(e.to_string())
    }
}

/// Detected format of a byte payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Json,
    Cbor,
}

/// Detect the format of a byte payload.
///
/// CBOR maps start with byte 0xA0-0xBF (or 0xBF for indefinite).
/// JSON documents start with `{` (0x7B) or whitespace before `{`.
pub fn detect_format(data: &[u8]) -> Result<Format, FormatError> {
    let first = data
        .iter()
        .find(|b| !b.is_ascii_whitespace())
        .ok_or(FormatError::UnknownFormat)?;

    if *first == b'{' || *first == b'[' {
        Ok(Format::Json)
    } else if *first >= 0xA0 || *first == 0xBF {
        // CBOR major type 5 (map) starts at 0xA0
        Ok(Format::Cbor)
    } else {
        Err(FormatError::UnknownFormat)
    }
}

/// Serialize a document to JSON bytes.
pub fn to_json(doc: &Document) -> Result<Vec<u8>, FormatError> {
    Ok(serde_json::to_vec_pretty(doc)?)
}

/// Serialize a document to compact JSON bytes (no whitespace).
pub fn to_json_compact(doc: &Document) -> Result<Vec<u8>, FormatError> {
    Ok(serde_json::to_vec(doc)?)
}

/// Deserialize a document from JSON bytes.
pub fn from_json(data: &[u8]) -> Result<Document, FormatError> {
    Ok(serde_json::from_slice(data)?)
}

/// Serialize a document to CBOR bytes.
pub fn to_cbor(doc: &Document) -> Result<Vec<u8>, FormatError> {
    let mut buf = Vec::new();
    ciborium::into_writer(doc, &mut buf).map_err(|e| FormatError::CborEncode(e.to_string()))?;
    Ok(buf)
}

/// Deserialize a document from CBOR bytes.
pub fn from_cbor(data: &[u8]) -> Result<Document, FormatError> {
    ciborium::from_reader(data).map_err(|e| FormatError::CborDecode(e.to_string()))
}

/// Deserialize a document from bytes, auto-detecting format.
pub fn from_bytes(data: &[u8]) -> Result<Document, FormatError> {
    match detect_format(data)? {
        Format::Json => from_json(data),
        Format::Cbor => from_cbor(data),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use tessera_core::*;

    fn sample_document() -> Document {
        let mut fields = BTreeMap::new();
        fields.insert(
            "count".into(),
            FieldDef {
                field_type: FieldType::U64,
                default: Some(Value::U64(0)),
            },
        );

        let mut effects = BTreeMap::new();
        effects.insert("count".into(), "count + 1".into());

        let mut mutations = BTreeMap::new();
        mutations.insert(
            "increment".into(),
            MutationDef {
                guards: vec!["count < 1000".into()],
                effects,
                args: BTreeMap::new(),
                validator: None,
            },
        );

        let mut state = BTreeMap::new();
        state.insert("count".into(), Value::U64(0));

        Document {
            tessera: "0.1".into(),
            schema: Schema {
                fields,
                mutations,
                code: None,
            },
            api: ApiSpec {
                read: vec!["count".into()],
                write: vec!["increment".into()],
            },
            state,
            chain: vec![],
            chain_mode: ChainMode::Embedded,
            pubkey: "a".repeat(64),
            signature: "b".repeat(128),
        }
    }

    #[test]
    fn json_round_trip() {
        let doc = sample_document();
        let bytes = to_json(&doc).unwrap();
        let parsed = from_json(&bytes).unwrap();
        assert_eq!(parsed.tessera, "0.1");
        assert_eq!(parsed.chain_mode, ChainMode::Embedded);
        assert_eq!(parsed.state.get("count").unwrap().as_u64(), Some(0));
    }

    #[test]
    fn cbor_round_trip() {
        let doc = sample_document();
        let bytes = to_cbor(&doc).unwrap();
        let parsed = from_cbor(&bytes).unwrap();
        assert_eq!(parsed.tessera, "0.1");
        assert_eq!(parsed.chain_mode, ChainMode::Embedded);
        assert_eq!(parsed.state.get("count").unwrap().as_u64(), Some(0));
    }

    #[test]
    fn json_cbor_equivalence() {
        let doc = sample_document();

        let json_bytes = to_json(&doc).unwrap();
        let cbor_bytes = to_cbor(&doc).unwrap();

        let from_j = from_json(&json_bytes).unwrap();
        let from_c = from_cbor(&cbor_bytes).unwrap();

        assert_eq!(from_j.tessera, from_c.tessera);
        assert_eq!(from_j.chain_mode, from_c.chain_mode);
        assert_eq!(from_j.state, from_c.state);
        assert_eq!(from_j.schema.fields.len(), from_c.schema.fields.len());
    }

    #[test]
    fn detect_json() {
        let json = b"{ \"tessera\": \"0.1\" }";
        assert_eq!(detect_format(json).unwrap(), Format::Json);
    }

    #[test]
    fn detect_json_with_whitespace() {
        let json = b"  \n  { \"tessera\": \"0.1\" }";
        assert_eq!(detect_format(json).unwrap(), Format::Json);
    }

    #[test]
    fn detect_cbor() {
        let doc = sample_document();
        let cbor = to_cbor(&doc).unwrap();
        assert_eq!(detect_format(&cbor).unwrap(), Format::Cbor);
    }

    #[test]
    fn auto_detect_json() {
        let doc = sample_document();
        let json = to_json(&doc).unwrap();
        let parsed = from_bytes(&json).unwrap();
        assert_eq!(parsed.tessera, "0.1");
    }

    #[test]
    fn auto_detect_cbor() {
        let doc = sample_document();
        let cbor = to_cbor(&doc).unwrap();
        let parsed = from_bytes(&cbor).unwrap();
        assert_eq!(parsed.tessera, "0.1");
    }

    #[test]
    fn compact_json_no_whitespace() {
        let doc = sample_document();
        let compact = to_json_compact(&doc).unwrap();
        let s = std::str::from_utf8(&compact).unwrap();
        assert!(!s.contains('\n'));
    }
}
