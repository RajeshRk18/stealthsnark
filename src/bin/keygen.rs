//! Mint an API key and print the record for the auth file.
//!
//! Authentication is only usable if there is a supported way to create a
//! credential. Without this, an operator would hand-compute a SHA-256 digest and
//! very likely store the plaintext key by mistake.
//!
//! The secret is printed once and never written anywhere. The server only ever
//! sees its digest, so a leaked auth file does not yield a usable key.
//!
//! ```text
//! cargo run --bin keygen -- --id alice --tier standard
//! ```

use stealthsnark::protocol::auth::generate_api_key;

fn main() {
    let mut principal_id = "client".to_string();
    let mut tier: Option<String> = None;
    let mut cert_path: Option<String> = None;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--id" | "-i" => {
                i += 1;
                match args.get(i) {
                    Some(v) => principal_id = v.clone(),
                    None => fail("--id needs a value"),
                }
            }
            "--tier" | "-t" => {
                i += 1;
                match args.get(i) {
                    Some(v) => tier = Some(v.clone()),
                    None => fail("--tier needs a value"),
                }
            }
            "--client-cert" | "-c" => {
                i += 1;
                match args.get(i) {
                    Some(v) => cert_path = Some(v.clone()),
                    None => fail("--client-cert needs a value"),
                }
            }
            "--help" | "-h" => {
                print_usage();
                return;
            }
            other => fail(&format!("unknown argument {other:?}")),
        }
        i += 1;
    }

    // Optional: register a TLS client certificate for the same principal, so one
    // command can produce a record usable under either auth mode.
    let cert_digest = cert_path
        .as_deref()
        .map(|path| cert_digest_of(path).unwrap_or_else(|e| fail(&format!("{e}"))));

    let generated = generate_api_key();

    println!("API key (shown once, store it now — the server keeps only its digest):");
    println!();
    println!("  {}", generated.key);
    println!();
    println!("Add this record to the file named by STEALTHSNARK_AUTH_FILE:");
    println!();

    let mut record = serde_json::Map::new();
    record.insert("id".into(), principal_id.clone().into());
    if let Some(t) = &tier {
        record.insert("tier".into(), t.clone().into());
    }
    record.insert("api_key_id".into(), generated.key_id.clone().into());
    record.insert("api_key_sha256".into(), generated.sha256.clone().into());
    if let Some(d) = &cert_digest {
        record.insert("tls_cert_sha256".into(), d.clone().into());
    }

    let document = serde_json::json!({ "principals": [serde_json::Value::Object(record)] });
    println!("{}", serde_json::to_string_pretty(&document).unwrap());

    if tier.is_none() {
        println!();
        println!("No --tier given, so the built-in `default` tier applies.");
    }
}

/// SHA-256 of the first certificate in a PEM file, matching what the server
/// computes from the TLS handshake.
fn cert_digest_of(path: &str) -> anyhow::Result<String> {
    #[cfg(feature = "tls")]
    {
        let pem = std::fs::read(path).map_err(|e| anyhow::anyhow!("cannot read {path}: {e}"))?;
        let mut reader = std::io::BufReader::new(&pem[..]);
        let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("cannot parse certificates in {path}: {e}"))?;
        let first = certs
            .first()
            .ok_or_else(|| anyhow::anyhow!("no certificate found in {path}"))?;
        Ok(stealthsnark::protocol::tls::cert_digest(first))
    }
    #[cfg(not(feature = "tls"))]
    {
        let _ = path;
        anyhow::bail!("--client-cert needs the `tls` feature")
    }
}

fn print_usage() {
    println!(
        "Mint a StealthSnark API key.

Usage:
  keygen [--id <principal>] [--tier <tier>] [--client-cert <file.pem>]

Options:
  -i, --id <principal>       Principal id to record. Default: client
  -t, --tier <tier>          Tier name. Default: the built-in `default` tier
  -c, --client-cert <file>   Also register this PEM certificate for mTLS
  -h, --help                 Show this message"
    );
}

fn fail(message: &str) -> ! {
    eprintln!("keygen: {message}");
    eprintln!();
    print_usage();
    std::process::exit(2);
}
