use std::collections::BTreeMap;

use tessera_core::{FieldType, Schema, State, TesseraError, Value};

/// Normalize a state so that value types match what the schema declares.
///
/// This is critical after Rhai execution: Rhai only has i64, so all integers
/// come back as i64. If the schema declares a field as U64, we coerce
/// non-negative i64 values to U64. This ensures deterministic hashing.
pub fn normalize_state_to_schema(state: &mut State, schema: &Schema) {
    for (name, field_def) in &schema.fields {
        if let Some(value) = state.remove(name) {
            state.insert(name.clone(), normalize_value(value, &field_def.field_type));
        }
    }
}

fn normalize_value(value: Value, expected: &FieldType) -> Value {
    match (value, expected) {
        // i64 -> u64 coercion when schema expects U64 and value is non-negative
        (Value::I64(n), FieldType::U64) if n >= 0 => Value::U64(n as u64),
        // u64 -> i64 coercion when schema expects I64
        (Value::U64(n), FieldType::I64) => {
            if let Ok(i) = i64::try_from(n) {
                Value::I64(i)
            } else {
                Value::U64(n) // will fail validation, but don't lose data
            }
        }
        // Recurse into arrays
        (Value::Array(items), FieldType::Array(inner)) => Value::Array(
            items
                .into_iter()
                .map(|v| normalize_value(v, inner))
                .collect(),
        ),
        // Recurse into maps
        (Value::Map(entries), FieldType::Map(_key_type, val_type)) => {
            let mut normalized = BTreeMap::new();
            for (k, v) in entries {
                normalized.insert(k, normalize_value(v, val_type));
            }
            Value::Map(normalized)
        }
        // Recurse into objects
        (Value::Map(entries), FieldType::Object(field_defs)) => {
            let mut normalized = BTreeMap::new();
            for (k, v) in entries {
                if let Some(fdef) = field_defs.get(&k) {
                    normalized.insert(k, normalize_value(v, &fdef.field_type));
                } else {
                    normalized.insert(k, v);
                }
            }
            Value::Map(normalized)
        }
        // No normalization needed
        (v, _) => v,
    }
}

/// Validate that the current state conforms to the schema's field definitions.
pub fn validate_state_against_schema(state: &State, schema: &Schema) -> Result<(), TesseraError> {
    for (name, field_def) in &schema.fields {
        if let Some(value) = state.get(name) {
            validate_value_type(name, value, &field_def.field_type)?;
        }
        // Missing fields are ok if they have defaults or are optional
    }

    Ok(())
}

fn validate_value_type(
    field_name: &str,
    value: &Value,
    expected_type: &FieldType,
) -> Result<(), TesseraError> {
    match (value, expected_type) {
        (Value::Bool(_), FieldType::Bool) => Ok(()),
        (Value::U64(_), FieldType::U64) => Ok(()),
        (Value::I64(_), FieldType::I64) => Ok(()),
        // Allow u64 values where i64 is expected (common in JSON deserialization)
        (Value::U64(v), FieldType::I64) if i64::try_from(*v).is_ok() => Ok(()),
        (Value::String(_), FieldType::String) => Ok(()),
        (Value::Bytes(_), FieldType::Bytes) => Ok(()),
        (Value::Array(items), FieldType::Array(inner_type)) => {
            for (i, item) in items.iter().enumerate() {
                validate_value_type(&format!("{}[{}]", field_name, i), item, inner_type)?;
            }
            Ok(())
        }
        (Value::Map(entries), FieldType::Map(_key_type, val_type)) => {
            for (k, v) in entries {
                validate_value_type(&format!("{}.{}", field_name, k), v, val_type)?;
            }
            Ok(())
        }
        (Value::Map(entries), FieldType::Object(field_defs)) => {
            for (name, fdef) in field_defs {
                if let Some(v) = entries.get(name) {
                    validate_value_type(&format!("{}.{}", field_name, name), v, &fdef.field_type)?;
                }
            }
            Ok(())
        }
        _ => Err(TesseraError::TypeMismatch {
            expected: format!("{:?}", expected_type),
            got: format!("{} ({})", field_name, value.type_name()),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use tessera_core::FieldDef;

    fn schema_with_fields(fields: Vec<(&str, FieldType, Option<Value>)>) -> Schema {
        let mut f = BTreeMap::new();
        for (name, ft, default) in fields {
            f.insert(
                name.into(),
                FieldDef {
                    field_type: ft,
                    default,
                },
            );
        }
        Schema {
            fields: f,
            mutations: BTreeMap::new(),
            code: None,
        }
    }

    #[test]
    fn valid_u64_field() {
        let schema = schema_with_fields(vec![("count", FieldType::U64, None)]);
        let mut state = BTreeMap::new();
        state.insert("count".into(), Value::U64(42));
        validate_state_against_schema(&state, &schema).unwrap();
    }

    #[test]
    fn wrong_type_rejected() {
        let schema = schema_with_fields(vec![("count", FieldType::U64, None)]);
        let mut state = BTreeMap::new();
        state.insert("count".into(), Value::String("not a number".into()));
        assert!(validate_state_against_schema(&state, &schema).is_err());
    }

    #[test]
    fn missing_field_ok() {
        let schema = schema_with_fields(vec![("count", FieldType::U64, None)]);
        let state = BTreeMap::new();
        validate_state_against_schema(&state, &schema).unwrap();
    }

    #[test]
    fn array_type_validated() {
        let schema = schema_with_fields(vec![(
            "items",
            FieldType::Array(Box::new(FieldType::U64)),
            None,
        )]);
        let mut state = BTreeMap::new();
        state.insert(
            "items".into(),
            Value::Array(vec![Value::U64(1), Value::U64(2)]),
        );
        validate_state_against_schema(&state, &schema).unwrap();
    }

    #[test]
    fn array_with_wrong_element_type_rejected() {
        let schema = schema_with_fields(vec![(
            "items",
            FieldType::Array(Box::new(FieldType::U64)),
            None,
        )]);
        let mut state = BTreeMap::new();
        state.insert(
            "items".into(),
            Value::Array(vec![Value::U64(1), Value::String("oops".into())]),
        );
        assert!(validate_state_against_schema(&state, &schema).is_err());
    }

    #[test]
    fn bool_field() {
        let schema = schema_with_fields(vec![("active", FieldType::Bool, None)]);
        let mut state = BTreeMap::new();
        state.insert("active".into(), Value::Bool(true));
        validate_state_against_schema(&state, &schema).unwrap();
    }

    #[test]
    fn string_field() {
        let schema = schema_with_fields(vec![("name", FieldType::String, None)]);
        let mut state = BTreeMap::new();
        state.insert("name".into(), Value::String("tessera".into()));
        validate_state_against_schema(&state, &schema).unwrap();
    }

    #[test]
    fn normalize_i64_to_u64() {
        let schema = schema_with_fields(vec![("count", FieldType::U64, None)]);
        let mut state = BTreeMap::new();
        // Rhai returns i64; normalization should coerce to U64
        state.insert("count".into(), Value::I64(42));
        normalize_state_to_schema(&mut state, &schema);
        assert_eq!(state.get("count"), Some(&Value::U64(42)));
    }

    #[test]
    fn normalize_negative_i64_stays_i64() {
        let schema = schema_with_fields(vec![("count", FieldType::U64, None)]);
        let mut state = BTreeMap::new();
        state.insert("count".into(), Value::I64(-5));
        normalize_state_to_schema(&mut state, &schema);
        // Negative values can't become U64; stays I64 and will fail validation
        assert_eq!(state.get("count"), Some(&Value::I64(-5)));
    }

    #[test]
    fn normalize_u64_to_i64() {
        let schema = schema_with_fields(vec![("val", FieldType::I64, None)]);
        let mut state = BTreeMap::new();
        state.insert("val".into(), Value::U64(10));
        normalize_state_to_schema(&mut state, &schema);
        assert_eq!(state.get("val"), Some(&Value::I64(10)));
    }

    #[test]
    fn normalize_map_values() {
        let schema = schema_with_fields(vec![(
            "scores",
            FieldType::Map(Box::new(FieldType::String), Box::new(FieldType::U64)),
            None,
        )]);
        let mut inner = BTreeMap::new();
        inner.insert("alice".into(), Value::I64(100));
        let mut state = BTreeMap::new();
        state.insert("scores".into(), Value::Map(inner));
        normalize_state_to_schema(&mut state, &schema);
        if let Some(Value::Map(m)) = state.get("scores") {
            assert_eq!(m.get("alice"), Some(&Value::U64(100)));
        } else {
            panic!("expected map");
        }
    }
}
