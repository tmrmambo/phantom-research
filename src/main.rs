use phantom::fingerprint;
use phantom::profile::catalog::{profile_for, RequestTemplateKind};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let profile = profile_for("chrome-156-windows", RequestTemplateKind::Navigation)?;
    let json_bytes = fingerprint::export_profile_json(&profile)?;
    let json_str = String::from_utf8(json_bytes)?;
    let value: serde_json::Value = serde_json::from_str(&json_str)?;

    // Print the TLS section in full
    if let Some(tls) = value.pointer("/profile/tls") {
        println!("=== TLS section ===");
        println!("{}", serde_json::to_string_pretty(tls)?);
    } else {
        println!("No /profile/tls found");
        // Try to find anything tls-related
        if let Some(profile) = value.get("profile").and_then(|p| p.as_object()) {
            for (key, val) in profile {
                if key.contains("tls") || key.contains("ssl") || key.contains("cipher")
                    || key.contains("extension") {
                    println!("Found relevant key: {} ({} chars)",
                        key, serde_json::to_string(val)?.len());
                }
            }
            // Print all keys with brief structure
            for (key, val) in profile {
                let desc = match val {
                    serde_json::Value::Object(o) => format!("object({} keys: {:?})", o.len(),
                        o.keys().take(8).collect::<Vec<_>>()),
                    serde_json::Value::Array(a) => format!("array({} items)", a.len()),
                    serde_json::Value::String(s) => format!("string({})", s.len()),
                    _ => format!("{:?}", val),
                };
                println!("  profile.{}: {}", key, desc);
            }
        }
    }

    Ok(())
}
