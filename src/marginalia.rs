use anyhow::{Context, Result};
use serde::Deserialize;

const MARGINALIA_API: &str = "https://api.marginalia.nu/public/search";

#[derive(Debug, Deserialize)]
struct SearchResponse {
    results: Vec<SearchResult>,
}

#[derive(Debug, Deserialize)]
struct SearchResult {
    url: String,
    title: String,
    description: String,
}

pub async fn search(query: &str, count: u32) -> Result<()> {
    let client = reqwest::Client::new();
    let url = format!("{}/{}?count={}", MARGINALIA_API, urlencoding(query), count);

    let resp = client
        .get(&url)
        .header("User-Agent", "plurigrid-web-browser/0.1")
        .send()
        .await
        .context("marginalia.nu API request failed")?;

    if !resp.status().is_success() {
        anyhow::bail!("marginalia API returned {}", resp.status());
    }

    let body: SearchResponse = resp.json().await.context("failed to parse marginalia response")?;

    if body.results.is_empty() {
        println!("No results found for '{}'", query);
        return Ok(());
    }

    for (i, result) in body.results.iter().enumerate() {
        println!("{}. {}", i + 1, result.title);
        println!("   {}", result.url);
        if !result.description.is_empty() {
            println!("   {}", result.description);
        }
        println!();
    }

    Ok(())
}

fn urlencoding(s: &str) -> String {
    s.replace(' ', "%20")
        .replace('&', "%26")
        .replace('?', "%3F")
        .replace('#', "%23")
}
