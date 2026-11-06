//! Demonstrates client registration against a minimal local server and URL generation.
//! This avoids depending on the public Interactsh service at runtime.

use interactsh_client::{ClientConfig, InteractionContext, InteractshClient};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn register_ok_response() -> String {
    let body = r#"{"message":"registration successful"}"#;
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server_url = format!("http://127.0.0.1:{}", addr.port());

    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept register");
        let mut buf = [0u8; 8192];
        let _n = socket.read(&mut buf).await.expect("read request");
        socket
            .write_all(register_ok_response().as_bytes())
            .await
            .expect("write response");
    });

    let client = InteractshClient::new(ClientConfig {
        server: server_url,
        ..ClientConfig::default()
    })
    .await?;

    let generated = client.generate_url(
        InteractionContext::new("blind-xss")
            .with_attribute("template", "xss-oob")
            .with_attribute("target", "https://example.com/profile"),
    )?;

    println!("Send payloads to {}", generated.url);
    println!("Correlation id: {}", client.correlation_id());

    server.await?;
    Ok(())
}
