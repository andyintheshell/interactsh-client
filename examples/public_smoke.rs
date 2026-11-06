use interactsh_client::{ClientConfig, InteractionContext, InteractshClient};
use std::{process::Command, time::Duration};

// Live test: registers with a public server and sends a real HTTP request.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = InteractshClient::new(ClientConfig::default()).await?;
    let url = client.generate_url(InteractionContext::new("public-smoke-test"))?;
    let target = format!("https://{}/interactsh-client-smoke-test", url.url);
    println!("OAST URL: {target}");

    let status = Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--max-time",
            "30",
            "--output",
            "/dev/null",
            "--write-out",
            "HTTP status: %{http_code}\n",
            &target,
        ])
        .status()?;
    if !status.success() {
        return Err(format!("curl failed: {status}").into());
    }

    for _ in 0..30 {
        tokio::time::sleep(Duration::from_secs(2)).await;
        for interaction in client.poll().await? {
            println!(
                "Received {} for {}",
                interaction.event.protocol, interaction.context.label
            );
            if interaction.event.protocol.eq_ignore_ascii_case("http")
                && interaction.context.label == "public-smoke-test"
                && interaction
                    .event
                    .raw_request
                    .as_deref()
                    .is_some_and(|request| request.contains("/interactsh-client-smoke-test"))
            {
                println!(
                    "Verified curl request:\n{}",
                    interaction.event.raw_request.unwrap()
                );
                return Ok(());
            }
        }
    }
    Err("No matching HTTP interaction received within 60 seconds".into())
}
