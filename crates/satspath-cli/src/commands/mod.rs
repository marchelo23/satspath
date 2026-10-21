mod ark;
mod claim;
mod demo;
mod dns;
mod encode;
mod init;
mod invite;
mod keystore;
mod pay;
mod peer;
mod preview;
mod proofs;
mod qr;
mod quote;
mod register;
mod server;
mod show;
mod wallet;
mod web;

pub use ark::{cmd_ark_receive, cmd_ark_send, cmd_ark_swap, ArkSwapSide};
pub use claim::cmd_claim;
pub use demo::cmd_demo;
pub use dns::cmd_dns_resolve;
pub use encode::{cmd_decode, cmd_encode};
pub use init::cmd_init;
pub use invite::cmd_invite;
pub use pay::cmd_pay;
pub use peer::{cmd_export, cmd_import};
pub use preview::cmd_preview;
pub use proofs::{cmd_attach_proof, cmd_prove};
pub use quote::{cmd_quote, cmd_quote_json};
pub use register::cmd_register;
pub use server::{cmd_server_check, cmd_server_init};
pub use show::cmd_show;
pub use wallet::{
    cmd_alias_recover, cmd_wallet_add_ark, cmd_wallet_add_bolt12, cmd_wallet_add_lightning,
    cmd_wallet_add_methods, cmd_wallet_add_onchain, cmd_wallet_init, cmd_wallet_publish,
    cmd_wallet_receive, cmd_wallet_rotate, cmd_wallet_show,
};
pub use web::cmd_web;

use anyhow::Result;
use satspath_core::registry::Registry;
use std::path::PathBuf;

/// Returns the default SatsPath configuration and data directory.
pub(crate) fn satspath_dir() -> PathBuf {
    satspath_core::default_data_dir()
}

/// Opens the local SatsPath [`Registry`] in [`satspath_dir`].
pub(crate) fn open_registry() -> Result<Registry> {
    let dir = satspath_dir();
    if !dir.exists() {
        anyhow::bail!("{}/ not found. Run `satspath init` first.", dir.display());
    }
    Ok(Registry::open(&dir)?)
}

use satspath_core::resolver::ChainResolver;
use satspath_core::resolvers::bip353::Bip353Resolver;
use satspath_core::resolvers::http::HttpResolver;
use satspath_core::resolvers::nostr::NostrResolver;

/// Builds a [`ChainResolver`] for `alias`, using the local registry when `alias` is registered
/// locally, or the public resolver chain backed by [`satspath_dir`] continuity state otherwise.
pub(crate) fn get_resolver(alias: &str) -> Result<ChainResolver> {
    let dir = satspath_dir();
    let mut chain = ChainResolver::with_continuity_dir(&dir);

    // A locally registered/imported alias has one authoritative source: the
    // verified local registry. Unrelated public transports are not expected
    // for that alias and must not turn offline `show` into a network request.
    if dir.exists() {
        let reg = open_registry()?;
        if reg.is_registered(alias) {
            return Ok(chain.push_authoritative("local-registry", reg));
        }
    }

    // For non-local aliases, every configured public source must agree or
    // explicitly report NotFound. An outage is never silently downgraded.
    chain = chain.push(Bip353Resolver::new(dir));

    // Add public HTTP resolver fallback
    chain = chain.push(HttpResolver::new());
    chain = chain.push(NostrResolver::new());

    Ok(chain)
}
