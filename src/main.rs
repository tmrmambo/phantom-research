use phantom::fingerprint;
use phantom::profile::catalog::{profile_for, RequestTemplateKind};
use phantom::{Client, RequestHeader};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base_profile = profile_for("chrome-156-windows", RequestTemplateKind::Navigation)?;
    let json_bytes = fingerprint::export_profile_json(&base_profile)?;

    // Try multiple approaches to disable trust_anchor_ids
    let approaches: Vec<(&str, Box<dyn Fn(&mut serde_json::Value)>)> = vec![
        ("set kind=None", Box::new(|v: &mut serde_json::Value| {
            if let Some(tai) = v.pointer_mut("/profile/tls/requested_trust_anchor_ids") {
                *tai = serde_json::json!({"kind": "None"});
            }
        })),
        ("set to null", Box::new(|v: &mut serde_json::Value| {
            if let Some(tai) = v.pointer_mut("/profile/tls/requested_trust_anchor_ids") {
                *tai = serde_json::Value::Null;
            }
        })),
        ("remove key entirely", Box::new(|v: &mut serde_json::Value| {
            if let Some(tls) = v.pointer_mut("/profile/tls") {
                if let Some(obj) = tls.as_object_mut() {
                    obj.remove("requested_trust_anchor_ids");
                }
            }
        })),
        ("set kind=Disabled", Box::new(|v: &mut serde_json::Value| {
            if let Some(tai) = v.pointer_mut("/profile/tls/requested_trust_anchor_ids") {
                *tai = serde_json::json!({"kind": "Disabled"});
            }
        })),
        ("set kind=Off", Box::new(|v: &mut serde_json::Value| {
            if let Some(tai) = v.pointer_mut("/profile/tls/requested_trust_anchor_ids") {
                *tai = serde_json::json!({"kind": "Off"});
            }
        })),
    ];

    let mut success = false;
    for (name, patcher) in &approaches {
        let mut value: serde_json::Value = serde_json::from_slice(&json_bytes)?;
        patcher(&mut value);
        let patched_bytes = serde_json::to_vec(&value)?;

        match fingerprint::import_profile_json(&patched_bytes) {
            Ok(profile) => {
                println!("[✓] Approach '{}' succeeded!", name);

                // Save patched profile for reference
                std::fs::write("brave-157-patched-profile.json",
                    serde_json::to_string_pretty(&value)?)?;

                // Send request and compare
                send_and_compare(profile).await?;
                success = true;
                break;
            }
            Err(e) => {
                println!("[✗] Approach '{}' failed: {}", name, e);
            }
        }
    }

    if !success {
        println!("\nAll approaches failed. Dumping the original field for analysis:");
        let value: serde_json::Value = serde_json::from_slice(&json_bytes)?;
        if let Some(tai) = value.pointer("/profile/tls/requested_trust_anchor_ids") {
            // Just print the kind and structure, not the full data
            if let Some(obj) = tai.as_object() {
                for (k, v) in obj {
                    match v {
                        serde_json::Value::Array(a) => println!("  {}: array({} items)", k, a.len()),
                        _ => println!("  {}: {:?}", k, v),
                    }
                }
            }
        }
    }

    Ok(())
}

async fn send_and_compare(profile: phantom::profile::ClientProfile) -> Result<(), Box<dyn std::error::Error>> {
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

    println!("\nStatus: {}", response.status());
    let body = response.into_body().collect_with_limit(1 << 20).await?;
    let body_str = String::from_utf8_lossy(&body);
    let json: serde_json::Value = serde_json::from_str(&body_str)?;

    // Target: real Brave 157 values
    let target_ja4 = "t13d1516h2_8daaf6152771_806a8c22fdea";
    let target_ja4r = "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01_0904,0905,0906,0403,0804,0401,0503,0805,0501,0806,0601";
    let target_akamai_hash = "52d84b11737d980aef856699f885ca86";
    let target_peetprint = "GREASE-772-771|2-1.1|GREASE-4588-29-23-24|GREASE-2308-2309-2310-1027-2052-1025-1283-2053-1281-2054-1537|1|2|GREASE-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53|0-10-11-13-16-17613-18-23-27-35-43-45-5-51-65037-65281-GREASE-GREASE";

    if let Some(tls) = json.get("tls") {
        let ja4 = tls.get("ja4").and_then(|v| v.as_str()).unwrap_or("");
        let ja4r = tls.get("ja4_r").and_then(|v| v.as_str()).unwrap_or("");
        let pp = tls.get("peetprint").and_then(|v| v.as_str()).unwrap_or("");

        println!("\n=== TLS Fingerprint Match ===");
        println!("JA4:       {} {}", ja4,
            if ja4 == target_ja4 { "✓" } else { "✗" });
        println!("JA4_r:     {} {}", if ja4r == target_ja4r { "MATCH" } else { "DIFF" },
            if ja4r == target_ja4r { "✓" } else { "✗" });
        println!("Peetprint: {} {}",
            if pp == target_peetprint { "MATCH" } else { "DIFF" },
            if pp == target_peetprint { "✓" } else { "✗" });

        if ja4r != target_ja4r {
            println!("\n  Got:    {}", ja4r);
            println!("  Target: {}", target_ja4r);
        }

        // Extension check
        if let Some(exts) = tls.get("extensions").and_then(|e| e.as_array()) {
            let non_grease: Vec<&str> = exts.iter()
                .filter_map(|e| e.get("name").and_then(|n| n.as_str()))
                .filter(|n| !n.starts_with("TLS_GREASE"))
                .collect();
            let has_51764 = non_grease.iter().any(|n| n.contains("51764"));
            println!("Extension 51764: {}",
                if has_51764 { "STILL PRESENT ✗" } else { "REMOVED ✓" });
            println!("Extension count: {} (target: 16)",non_grease.len());
        }
    }

    if let Some(h2) = json.get("http2") {
        let hash = h2.get("akamai_fingerprint_hash").and_then(|v| v.as_str()).unwrap_or("");
        println!("\n=== HTTP/2 ===");
        println!("Akamai hash: {} {}", hash,
            if hash == target_akamai_hash { "✓" } else { "✗" });
    }

    std::fs::write("brave-patched-fingerprint.json",
        serde_json::to_string_pretty(&json)?)?;

    Ok(())
}
