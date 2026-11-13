use phantom::fingerprint;
use phantom::profile::catalog::{profile_for, RequestTemplateKind};
use phantom::{Client, RequestHeader};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // --- Step 1: Export Chrome 156 profile, patch it for Brave ---
    let base_profile = profile_for("chrome-156-windows", RequestTemplateKind::Navigation)?;
    let json_bytes = fingerprint::export_profile_json(&base_profile)?;
    let mut value: serde_json::Value = serde_json::from_slice(&json_bytes)?;

    // Remove extension 51764 (0xCA34) = trust_anchors
    // by clearing requested_trust_anchor_ids
    if let Some(tls) = value.pointer_mut("/profile/tls") {
        if let Some(obj) = tls.as_object_mut() {
            // Try different approaches to disable trust_anchor_ids
            if let Some(tai) = obj.get_mut("requested_trust_anchor_ids") {
                if let Some(tai_obj) = tai.as_object_mut() {
                    // Clear the orders to empty
                    tai_obj.insert("orders".to_string(), serde_json::json!([]));
                    println!("[patch] Cleared requested_trust_anchor_ids.orders");
                }
            }
        }
    }

    // Save patched JSON for inspection
    let patched_json = serde_json::to_string_pretty(&value)?;
    std::fs::write("brave-157-patched-profile.json", &patched_json)?;

    // --- Step 2: Import the patched profile ---
    let patched_bytes = serde_json::to_vec(&value)?;
    let brave_profile = fingerprint::import_profile_json(&patched_bytes)?;
    println!("[ok] Imported patched profile");

    // --- Step 3: Send request with Brave headers ---
    let client = Client::builder(brave_profile).build()?;

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

    println!("\nStatus: {}", response.status());
    let body = response.into_body().collect_with_limit(1 << 20).await?;
    let body_str = String::from_utf8_lossy(&body);
    let json: serde_json::Value = serde_json::from_str(&body_str)?;

    // --- Step 4: Compare with real Brave ---
    println!("\n=== TLS Comparison ===");

    let brave_target_ja4 = "t13d1516h2_8daaf6152771_806a8c22fdea";
    let brave_target_ja4r = "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01_0904,0905,0906,0403,0804,0401,0503,0805,0501,0806,0601";
    let brave_target_akamai = "52d84b11737d980aef856699f885ca86";

    if let Some(tls) = json.get("tls") {
        let ja4 = tls.get("ja4").and_then(|v| v.as_str()).unwrap_or("");
        let ja4r = tls.get("ja4_r").and_then(|v| v.as_str()).unwrap_or("");

        println!("JA4:  {} {}", ja4,
            if ja4 == brave_target_ja4 { "✓ MATCH" } else { "✗ DIFFERENT" });
        println!("  target: {}", brave_target_ja4);

        println!("JA4_r: {} {}", ja4r,
            if ja4r == brave_target_ja4r { "✓ MATCH" } else { "✗ DIFFERENT" });
        println!("  target: {}", brave_target_ja4r);

        // Check extension count and list
        if let Some(exts) = tls.get("extensions").and_then(|e| e.as_array()) {
            let non_grease: Vec<&str> = exts.iter()
                .filter_map(|e| e.get("name").and_then(|n| n.as_str()))
                .filter(|n| !n.starts_with("TLS_GREASE"))
                .collect();
            println!("Extensions: {} non-GREASE", non_grease.len());
            let has_51764 = non_grease.iter().any(|n| n.contains("51764"));
            println!("Extension 51764: {}",
                if has_51764 { "STILL PRESENT ✗" } else { "REMOVED ✓" });
        }
    }

    println!("\n=== HTTP/2 Comparison ===");
    if let Some(h2) = json.get("http2") {
        let akamai_hash = h2.get("akamai_fingerprint_hash")
            .and_then(|v| v.as_str()).unwrap_or("");
        println!("Akamai hash: {} {}",
            akamai_hash,
            if akamai_hash == brave_target_akamai { "✓ MATCH" } else { "✗ DIFFERENT" });
    }

    println!("\n=== Headers ===");
    if let Some(frames) = json.pointer("/http2/sent_frames").and_then(|f| f.as_array()) {
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

    // Save full result
    std::fs::write("brave-patched-fingerprint.json",
        serde_json::to_string_pretty(&json)?)?;
    println!("\n=== Full result saved to brave-patched-fingerprint.json ===");

    Ok(())
}
