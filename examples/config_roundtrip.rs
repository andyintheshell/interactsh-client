use interactsh_client::ClientConfig;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ClientConfig {
        server: "interactsh.example.internal".to_string(),
        token: Some("replace-me".to_string()),
        ..ClientConfig::default()
    };

    let rendered = config.to_toml_string()?;
    let parsed = ClientConfig::from_toml_str(&rendered)?;

    println!("{}", rendered);
    println!("server={}", parsed.server);
    Ok(())
}
