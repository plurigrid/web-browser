use anyhow::{Context, Result};

pub async fn fetch(url: &str, raw: bool) -> Result<()> {
    let client = reqwest::Client::builder()
        // Prefer HTTP/3 (QUIC) when the server supports it
        .http3_prior_knowledge()
        .user_agent("plurigrid-web-browser/0.1")
        .build()
        .unwrap_or_else(|_| {
            // Fall back to default client if HTTP/3 build fails
            reqwest::Client::new()
        });

    let resp = client
        .get(url)
        .send()
        .await
        .context(format!("failed to fetch {}", url))?;

    let version = resp.version();
    let status = resp.status();
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    println!("[{:?} {} {}]", version, status, content_type);

    let body = resp.text().await.context("failed to read response body")?;

    if raw || !content_type.contains("html") {
        println!("{}", body);
    } else {
        let text = html2text::from_read(body.as_bytes(), 80);
        println!("{}", text);
    }

    Ok(())
}
