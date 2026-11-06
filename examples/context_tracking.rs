use interactsh_client::InteractionContext;

fn main() {
    let context = InteractionContext::builder("ssrf-probe")
        .attribute("target", "https://app.example.com")
        .attribute("template_id", "CVE-2021-44228")
        .build();

    println!("label={}", context.label);
    println!("attributes={}", context.attributes.len());
}
