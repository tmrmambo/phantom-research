use phantom::profile::catalog::{profile_for, RequestTemplateKind};
use phantom::{Client, RequestHeader};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // --- Step 1: Export profile JSON to inspect TLS extension structure ---
    export_profile_json()?;

    // --- Step 2: Send request with Brave header overrides ---
    send_brave_request().await?;

    Ok(())
}

/// Export the Chrome 156 profile to JSON so we can inspect
/// what TLS settings are editable (extensions, cipher suites, etc.)
fn export_profile_json() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "fingerprint-import")]
    {
        use phantom::fingerprint;

        let profile = profile_for("chrome-156-windows", RequestTemplateKind::Navigation)?;
        let json_bytes = fingerprint::export_profile_json(&profile)?;
        let json_str = String::from_utf8(json_bytes)?;

        // Pretty print
        let value: serde_json::Value = serde_json::from_str(&json_str)?;
        let pretty = serde_json::to_string_pretty(&value)?;

        // Write to file for inspection
        std::fs::write("chrome-156-profile-export.json", &pretty)?;
        println!("=== Profile JSON exported to chrome-156-profile-export.json ===");
        println!("Size: {} bytes", pretty.len());

        // Also print a summary of the TLS section if present
        if let Some(tls) = value.get("tls") {
            println!("\n=== TLS section keys ===");
            if let Some(obj) = tls.as_object() {
                for key in obj.keys() {
                    let val = &obj[key];
                    match val {
                        serde_json::Value::Array(arr) => {
                            println!("  {}: [{} items]", key, arr.len());
                        }
                        serde_json::Value::String(s) => {
                            println!("  {}: \"{}\"", key, if s.len() > 60 { &s[..60] } else { s });
                        }
                        _ => {
                            println!("  {}: {:?}", key, val);
                        }
                    }
                }
            }
        }
    }

    #[cfg(not(feature = "fingerprint-import"))]
    {
        println!("=== fingerprint-import feature not enabled, skipping export ===");
    }

    Ok(())
}

/// Send a request that emulates Brave 157 as closely as possible,
/// starting from Chrome 156 profile + header overrides.
async fn send_brave_request() -> Result<(), Box<dyn std::error::Error>> {
    let profile = profile_for("chrome-156-windows", RequestTemplateKind::Navigation)?;
    let client = Client::builder(profile).build()?;

    // Override headers to match Brave 157
    let response = client
        .get("https://tls.peet.ws/api/all")?
        // Brave's Sec-CH-UA brand
        .header(RequestHeader::new(
            "sec-ch-ua",
            "\"Not-A.Brand\";v=\"99\", \"Brave\";v=\"157\", \"Chromium\";v=\"157\"",
        ))
        // Brave's User-Agent (Chrome/157)
        .header(RequestHeader::new(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36",
        ))
        // Brave removes signed-exchange from accept
        .header(RequestHeader::new(
            "accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8",
        ))
        // Brave's Global Privacy Control
        .header(RequestHeader::new("sec-gpc", "1"))
        // Brave's accept-language quality
        .header(RequestHeader::new("accept-language", "en-US,en;q=0.8"))
        .send()
        .await?;

    println!("\n=== Brave-emulated request result ===");
    println!("Status: {}", response.status());

    let body = response.into_body().collect_with_limit(1 << 20).await?;
    let body_str = String::from_utf8_lossy(&body);

    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body_str) {
        // Print key fingerprint fields for comparison
        println!("\n--- TLS ---");
        if let Some(tls) = json.get("tls") {
            if let Some(ja4) = tls.get("ja4") {
                println!("JA4: {}", ja4);
            }
            if let Some(ja4r) = tls.get("ja4_r") {
                println!("JA4_r: {}", ja4r);
            }
            // Count extensions (non-GREASE)
            if let Some(exts) = tls.get("extensions").and_then(|e| e.as_array()) {
                let non_grease = exts
                    .iter()
                    .filter(|e| {
                        e.get("name")
                            .and_then(|n| n.as_str())
                            .map(|n| !n.starts_with("TLS_GREASE"))
                            .unwrap_or(true)
                    })
                    .count();
                println!("Extensions: {} total, {} non-GREASE", exts.len(), non_grease);

                // Check if 51764 (0xCA34) is still present
                let has_ca34 = exts.iter().any(|e| {
                    e.get("name")
                        .and_then(|n| n.as_str())
                        .map(|n| n.contains("51764"))
                        .unwrap_or(false)
                });
                println!(
                    "Extension 51764 (0xCA34): {}",
                    if has_ca34 { "PRESENT" } else { "ABSENT" }
                );
            }
        }

        println!("\n--- HTTP/2 ---");
        if let Some(h2) = json.get("http2") {
            if let Some(fp) = h2.get("akamai_fingerprint") {
                println!("Akamai: {}", fp);
            }
            if let Some(hash) = h2.get("akamai_fingerprint_hash") {
                println!("Akamai hash: {}", hash);
            }
        }

        println!("\n--- Headers sent ---");
        if let Some(frames) = json
            .get("http2")
            .and_then(|h| h.get("sent_frames"))
            .and_then(|f| f.as_array())
        {
            for frame in frames {
                if frame.get("frame_type").and_then(|f| f.as_str()) == Some("HEADERS") {
                    if let Some(headers) = frame.get("headers").and_then(|h| h.as_array()) {
                        for h in headers {
                            println!("  {}", h.as_str().unwrap_or("?"));
                        }
                    }
                }
            }
        }

        // Save full response for analysis
        let pretty = serde_json::to_string_pretty(&json)?;
        std::fs::write("brave-emulated-fingerprint.json", &pretty)?;
        println!("\n=== Full response saved to brave-emulated-fingerprint.json ===");
    }

    Ok(())
}
