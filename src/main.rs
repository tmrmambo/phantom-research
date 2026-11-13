use phantom::fingerprint;
use phantom::profile::catalog::{profile_for, RequestTemplateKind};
use phantom::{Client, RequestHeader};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // --- Step 1: Export Chrome 156 profile to JSON for inspection ---
    let profile = profile_for("chrome-156-windows", RequestTemplateKind::Navigation)?;
    let json_bytes = fingerprint::export_profile_json(&profile)?;
    let json_str = String::from_utf8(json_bytes)?;
    let value: serde_json::Value = serde_json::from_str(&json_str)?;
    let pretty = serde_json::to_string_pretty(&value)?;

    std::fs::write("chrome-156-profile-export.json", &pretty)?;
    println!("=== Profile JSON exported ({} bytes) ===", pretty.len());

    // Print top-level keys
    if let Some(obj) = value.as_object() {
        println!("Top-level keys:");
        for (key, val) in obj {
            match val {
                serde_json::Value::Object(inner) => {
                    println!("  {} (object, {} keys: {:?})", key, inner.len(),
                        inner.keys().collect::<Vec<_>>());
                }
                serde_json::Value::Array(arr) => {
                    println!("  {} (array, {} items)", key, arr.len());
                }
                serde_json::Value::String(s) => {
                    let display = if s.len() > 80 { &s[..80] } else { s.as_str() };
                    println!("  {}: \"{}\"", key, display);
                }
                _ => println!("  {}: {:?}", key, val),
            }
        }
    }

    // Print TLS details if present
    for section_name in ["tls", "tls_settings", "connection", "extensions"] {
        if let Some(section) = value.get(section_name) {
            println!("\n=== Section '{}' ===", section_name);
            println!("{}", serde_json::to_string_pretty(section)?
                .lines().take(40).collect::<Vec<_>>().join("\n"));
            println!("  ...(truncated)");
        }
    }

    // --- Step 2: Send Brave-emulated request ---
    let client = Client::builder(profile).build()?;

    let response = client
        .get("https://tls.peet.ws/api/all")?
        .header(RequestHeader::new(
            "sec-ch-ua",
            "\"Not-A.Brand\";v=\"99\", \"Brave\";v=\"157\", \"Chromium\";v=\"157\"",
        ))
        .header(RequestHeader::new(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36",
        ))
        .header(RequestHeader::new(
            "accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8",
        ))
        .header(RequestHeader::new("sec-gpc", "1"))
        .header(RequestHeader::new("accept-language", "en-US,en;q=0.8"))
        .send()
        .await?;

    println!("\n=== Brave-emulated request ===");
    println!("Status: {}", response.status());
    let body = response.into_body().collect_with_limit(1 << 20).await?;
    let body_str = String::from_utf8_lossy(&body);

    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body_str) {
        if let Some(tls) = json.get("tls") {
            println!("JA4: {}", tls.get("ja4").unwrap_or(&serde_json::Value::Null));
            if let Some(exts) = tls.get("extensions").and_then(|e| e.as_array()) {
                let non_grease: Vec<_> = exts.iter()
                    .filter_map(|e| e.get("name").and_then(|n| n.as_str()))
                    .filter(|n| !n.starts_with("TLS_GREASE"))
                    .collect();
                println!("Non-GREASE extensions ({}):", non_grease.len());
                for ext in &non_grease {
                    let marker = if ext.contains("51764") { " ← EXTRA" } else { "" };
                    println!("  {}{}", ext, marker);
                }
            }
        }
        if let Some(h2) = json.get("http2") {
            println!("Akamai hash: {}",
                h2.get("akamai_fingerprint_hash").unwrap_or(&serde_json::Value::Null));
        }
        let pretty = serde_json::to_string_pretty(&json)?;
        std::fs::write("brave-emulated-fingerprint.json", &pretty)?;
    }

    Ok(())
}
