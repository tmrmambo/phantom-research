use phantom::profile::catalog::{profile_for, RequestTemplateKind};
use phantom::Client;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Emulate Chrome 156 on Windows (same TLS stack as Brave)
    let profile = profile_for("chrome-156-windows", RequestTemplateKind::Navigation)?;
    let client = Client::builder(profile).build()?;

    // Test against tls.peet.ws to inspect our fingerprint
    let response = client
        .get("https://tls.peet.ws/api/all")?
        .send()
        .await?;

    println!("Status: {}", response.status());
    let body = response.into_body().collect_with_limit(1 << 20).await?;
    let body_str = String::from_utf8_lossy(&body);

    // Pretty-print the JSON response
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body_str) {
        println!("{}", serde_json::to_string_pretty(&json)?);
    } else {
        println!("{}", body_str);
    }

    Ok(())
}
