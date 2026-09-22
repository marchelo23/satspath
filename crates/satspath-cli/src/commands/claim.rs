use anyhow::Result;
use url::Url;

use super::register::cmd_register;
use satspath_core::privacy::canonical_identifier;

pub async fn cmd_claim(
    claim_url_or_alias: &str,
    lightning_address: Option<&str>,
    onchain_address: Option<&str>,
) -> Result<()> {
    let alias = if let Ok(url) = Url::parse(claim_url_or_alias) {
        if let Some(alias_param) = url.query_pairs().find(|(k, _)| k == "alias") {
            alias_param.1.to_string()
        } else {
            anyhow::bail!("Claim URL does not contain the plaintext alias. Please run `satspath claim <your-alias>` instead.");
        }
    } else {
        claim_url_or_alias.to_string()
    };

    println!(
        "Claiming invite for alias: {}",
        canonical_identifier(&alias)
    );

    // Claiming is essentially registering the profile for the first time,
    // which allows the sender's router to finally resolve and pay it.
    cmd_register(&alias, lightning_address, onchain_address, None, None).await?;

    println!();
    println!("[OK] Claim successful! You can now receive the pending payment.");
    println!("Destination profile is registered and ready for payment routing.");

    Ok(())
}
