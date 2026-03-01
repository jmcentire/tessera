use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand};
use tessera_core::crypto::Ed25519Signer;
use tessera_core::{ApiSpec, ChainMode, Schema, Value};
use tessera_engine::{create_document, load_document, mutate_self, verify_document, version};

#[derive(Parser)]
#[command(name = "tessera", about = "Self-validating document engine")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new document from a schema definition
    Create {
        /// Path to schema JSON file (reads stdin if omitted)
        schema: Option<PathBuf>,

        /// Chain mode: embedded, referenced, or stateless
        #[arg(long, default_value = "embedded")]
        chain_mode: String,

        /// Path to write the output document (prints to stdout if omitted)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Output format: json or cbor
        #[arg(long, default_value = "json")]
        format: String,

        /// Path to existing key file (generates new key if omitted)
        #[arg(long)]
        key: Option<PathBuf>,
    },

    /// Validate a document's integrity (signatures + chain)
    Validate {
        /// Path to document file (reads stdin if omitted)
        file: Option<PathBuf>,
    },

    /// Inspect a document: show metadata, state, chain info
    Inspect {
        /// Path to document file (reads stdin if omitted)
        file: Option<PathBuf>,

        /// Show full chain details
        #[arg(long)]
        chain: bool,
    },

    /// Apply a mutation to a document
    Apply {
        /// Path to document file
        file: PathBuf,

        /// Mutation type (e.g., "increment")
        mutation: String,

        /// Arguments as JSON object (e.g., '{"amount": 5}')
        #[arg(long, default_value = "{}")]
        args: String,

        /// Path to signing key file
        #[arg(long)]
        key: PathBuf,

        /// Output format: json or cbor
        #[arg(long, default_value = "json")]
        format: String,

        /// Path to write the output document (prints to stdout if omitted)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Sign (or re-sign) a document with a key
    Sign {
        /// Path to document file
        file: PathBuf,

        /// Path to signing key file
        #[arg(long)]
        key: PathBuf,

        /// Output format: json or cbor
        #[arg(long, default_value = "json")]
        format: String,

        /// Path to write the output document (prints to stdout if omitted)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Generate a new Ed25519 key pair
    Keygen {
        /// Path to write the key file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Create {
            schema,
            chain_mode,
            output,
            format,
            key,
        } => cmd_create(schema, &chain_mode, output, &format, key),
        Command::Validate { file } => cmd_validate(file),
        Command::Inspect { file, chain } => cmd_inspect(file, chain),
        Command::Apply {
            file,
            mutation,
            args,
            key,
            format,
            output,
        } => cmd_apply(file, &mutation, &args, key, &format, output),
        Command::Sign {
            file,
            key,
            format,
            output,
        } => cmd_sign(file, key, &format, output),
        Command::Keygen { output } => cmd_keygen(output),
    };

    if let Err(e) = result {
        eprintln!("error: {}", e);
        process::exit(1);
    }
}

fn read_input(path: Option<PathBuf>) -> Result<Vec<u8>, String> {
    match path {
        Some(p) => fs::read(&p).map_err(|e| format!("cannot read '{}': {}", p.display(), e)),
        None => {
            let mut buf = Vec::new();
            io::stdin()
                .read_to_end(&mut buf)
                .map_err(|e| format!("cannot read stdin: {}", e))?;
            Ok(buf)
        }
    }
}

fn write_output(data: &[u8], path: Option<&PathBuf>) -> Result<(), String> {
    match path {
        Some(p) => fs::write(p, data).map_err(|e| format!("cannot write '{}': {}", p.display(), e)),
        None => {
            io::Write::write_all(&mut io::stdout(), data)
                .map_err(|e| format!("cannot write stdout: {}", e))?;
            // Add a newline if the output is JSON (text)
            if data.first() == Some(&b'{') || data.first() == Some(&b'[') {
                println!();
            }
            Ok(())
        }
    }
}

fn serialize_doc(doc: &tessera_core::Document, format: &str) -> Result<Vec<u8>, String> {
    match format {
        "json" => tessera_format::to_json(doc).map_err(|e| e.to_string()),
        "cbor" => tessera_format::to_cbor(doc).map_err(|e| e.to_string()),
        _ => Err(format!(
            "unknown format '{}' (use 'json' or 'cbor')",
            format
        )),
    }
}

fn parse_chain_mode(s: &str) -> Result<ChainMode, String> {
    match s {
        "embedded" => Ok(ChainMode::Embedded),
        "referenced" => Ok(ChainMode::Referenced),
        "stateless" => Ok(ChainMode::Stateless),
        _ => Err(format!(
            "unknown chain mode '{}' (use 'embedded', 'referenced', or 'stateless')",
            s
        )),
    }
}

fn load_signer(path: &PathBuf) -> Result<Ed25519Signer, String> {
    let data = fs::read_to_string(path)
        .map_err(|e| format!("cannot read key '{}': {}", path.display(), e))?;
    let hex_str = data.trim();
    Ed25519Signer::from_keypair_hex(hex_str)
        .map_err(|e| format!("invalid key in '{}': {}", path.display(), e))
}

/// Schema input is a JSON object with:
/// - "fields": field definitions
/// - "mutations": mutation definitions
/// - "api" (optional): read/write declarations
///
/// If "api" is present at the top level, it's extracted separately.
fn parse_schema_input(data: &[u8]) -> Result<(Schema, ApiSpec), String> {
    let v: serde_json::Value =
        serde_json::from_slice(data).map_err(|e| format!("invalid JSON: {}", e))?;

    let obj = v.as_object().ok_or("schema must be a JSON object")?;

    // Extract API if present at top level
    let api = if let Some(api_val) = obj.get("api") {
        serde_json::from_value(api_val.clone()).map_err(|e| format!("invalid api: {}", e))?
    } else {
        // Default: expose all fields as readable, all mutations as writable
        let fields: Vec<String> = obj
            .get("fields")
            .and_then(|f| f.as_object())
            .map(|f| f.keys().cloned().collect())
            .unwrap_or_default();
        let mutations: Vec<String> = obj
            .get("mutations")
            .and_then(|m| m.as_object())
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default();
        ApiSpec {
            read: fields,
            write: mutations,
        }
    };

    // Parse schema (fields + mutations)
    let schema: Schema = serde_json::from_value(serde_json::json!({
        "fields": obj.get("fields").cloned().unwrap_or(serde_json::Value::Object(Default::default())),
        "mutations": obj.get("mutations").cloned().unwrap_or(serde_json::Value::Object(Default::default())),
    }))
    .map_err(|e| format!("invalid schema: {}", e))?;

    Ok((schema, api))
}

fn parse_args(args_str: &str) -> Result<BTreeMap<String, Value>, String> {
    let v: serde_json::Value =
        serde_json::from_str(args_str).map_err(|e| format!("invalid args JSON: {}", e))?;
    let obj = v.as_object().ok_or("args must be a JSON object")?;

    let mut result = BTreeMap::new();
    for (k, v) in obj {
        let val = json_to_value(v)?;
        result.insert(k.clone(), val);
    }
    Ok(result)
}

fn json_to_value(v: &serde_json::Value) -> Result<Value, String> {
    match v {
        serde_json::Value::Bool(b) => Ok(Value::Bool(*b)),
        serde_json::Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                Ok(Value::U64(u))
            } else if let Some(i) = n.as_i64() {
                Ok(Value::I64(i))
            } else {
                Err("floating point numbers not supported".into())
            }
        }
        serde_json::Value::String(s) => Ok(Value::String(s.clone())),
        serde_json::Value::Array(arr) => {
            let items: Result<Vec<_>, _> = arr.iter().map(json_to_value).collect();
            Ok(Value::Array(items?))
        }
        serde_json::Value::Object(obj) => {
            let mut map = BTreeMap::new();
            for (k, v) in obj {
                map.insert(k.clone(), json_to_value(v)?);
            }
            Ok(Value::Map(map))
        }
        serde_json::Value::Null => Err("null values not supported".into()),
    }
}

fn cmd_create(
    schema_path: Option<PathBuf>,
    chain_mode: &str,
    output: Option<PathBuf>,
    format: &str,
    key_path: Option<PathBuf>,
) -> Result<(), String> {
    let schema_data = read_input(schema_path)?;
    let (schema, api) = parse_schema_input(&schema_data)?;
    let mode = parse_chain_mode(chain_mode)?;

    let signer = match key_path {
        Some(ref p) => load_signer(p)?,
        None => Ed25519Signer::generate(),
    };

    let doc = create_document(schema, api, mode, &signer).map_err(|e| e.to_string())?;

    let bytes = serialize_doc(&doc, format)?;
    write_output(&bytes, output.as_ref())?;

    // If we generated a key, tell the user
    if key_path.is_none() {
        eprintln!(
            "generated key (save this to reuse): {}",
            signer.keypair_hex()
        );
    }

    Ok(())
}

fn cmd_validate(file: Option<PathBuf>) -> Result<(), String> {
    let data = read_input(file)?;
    let doc = load_document(&data).map_err(|e| e.to_string())?;
    verify_document(&doc).map_err(|e| e.to_string())?;
    let ver = version(&doc).map_err(|e| e.to_string())?;
    eprintln!("valid. version: {}", ver);
    eprintln!("chain: {} mutation(s)", doc.chain.len());
    Ok(())
}

fn cmd_inspect(file: Option<PathBuf>, show_chain: bool) -> Result<(), String> {
    let data = read_input(file)?;
    let doc = load_document(&data).map_err(|e| e.to_string())?;
    let ver = version(&doc).map_err(|e| e.to_string())?;

    println!("tessera: {}", doc.tessera);
    println!("chain_mode: {:?}", doc.chain_mode);
    println!("version: {}", ver);
    println!("pubkey: {}", doc.pubkey);
    println!("chain: {} mutation(s)", doc.chain.len());

    println!();
    println!("--- schema ---");
    println!(
        "fields: {}",
        doc.schema
            .fields
            .keys()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!(
        "mutations: {}",
        doc.schema
            .mutations
            .keys()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ")
    );

    println!();
    println!("--- api ---");
    println!("read: {}", doc.api.read.join(", "));
    println!("write: {}", doc.api.write.join(", "));

    println!();
    println!("--- state ---");
    for (k, v) in &doc.state {
        println!("  {}: {}", k, format_value(v));
    }

    if show_chain && !doc.chain.is_empty() {
        println!();
        println!("--- chain ---");
        for (i, m) in doc.chain.iter().enumerate() {
            println!("[{}] {} (actor: {}...)", i, m.op.op_type, &m.actor[..16]);
            if !m.op.args.is_empty() {
                println!("    args: {:?}", m.op.args);
            }
            println!("    prev: {}...", &m.prev_hash[..16]);
            println!("    next: {}...", &m.next_hash[..16]);
        }
    }

    Ok(())
}

fn cmd_apply(
    file: PathBuf,
    mutation: &str,
    args_str: &str,
    key_path: PathBuf,
    format: &str,
    output: Option<PathBuf>,
) -> Result<(), String> {
    let data = read_input(Some(file))?;
    let mut doc = load_document(&data).map_err(|e| e.to_string())?;
    let signer = load_signer(&key_path)?;
    let args = parse_args(args_str)?;

    mutate_self(&mut doc, mutation, args, &signer).map_err(|e| e.to_string())?;

    let bytes = serialize_doc(&doc, format)?;
    write_output(&bytes, output.as_ref())?;

    let ver = version(&doc).map_err(|e| e.to_string())?;
    eprintln!("applied '{}'. version: {}", mutation, ver);

    Ok(())
}

fn cmd_sign(
    file: PathBuf,
    key_path: PathBuf,
    format: &str,
    output: Option<PathBuf>,
) -> Result<(), String> {
    let data = read_input(Some(file))?;
    let mut doc = load_document(&data).map_err(|e| e.to_string())?;
    let signer = load_signer(&key_path)?;

    tessera_chain::sign_document(&mut doc, &signer).map_err(|e| e.to_string())?;

    let bytes = serialize_doc(&doc, format)?;
    write_output(&bytes, output.as_ref())?;

    eprintln!("signed. pubkey: {}", doc.pubkey);
    Ok(())
}

fn cmd_keygen(output: Option<PathBuf>) -> Result<(), String> {
    let signer = Ed25519Signer::generate();
    let hex = signer.keypair_hex();
    let pubkey = signer.pubkey_hex();

    match output {
        Some(p) => {
            fs::write(&p, &hex).map_err(|e| format!("cannot write '{}': {}", p.display(), e))?;
            println!("key written to: {}", p.display());
            println!("public key: {}", pubkey);
        }
        None => {
            println!("{}", hex);
            eprintln!("public key: {}", pubkey);
        }
    }

    Ok(())
}

fn format_value(v: &Value) -> String {
    match v {
        Value::Bool(b) => b.to_string(),
        Value::U64(n) => n.to_string(),
        Value::I64(n) => n.to_string(),
        Value::String(s) => format!("\"{}\"", s),
        Value::Bytes(b) => format!("<{} bytes>", b.len()),
        Value::Array(items) => {
            let inner: Vec<String> = items.iter().map(format_value).collect();
            format!("[{}]", inner.join(", "))
        }
        Value::Map(entries) => {
            let inner: Vec<String> = entries
                .iter()
                .map(|(k, v)| format!("{}: {}", k, format_value(v)))
                .collect();
            format!("{{{}}}", inner.join(", "))
        }
    }
}
