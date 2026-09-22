//! Startup check that the daemon is attached to the mainchain it expects.
//!
//! The chassis trusts whichever enforcer it is handed: point a node at an
//! enforcer following a different chain and nothing notices, because the only
//! thing that separates two networks is the sidechain P2P magic. A node then
//! builds its chain on foreign mainchain blocks, and its deposits, withdrawals
//! and BMM all refer to a chain nobody else is on.
//!
//! Two checks run once, at startup, before the node is built:
//!
//! 1. **Network.** The enforcer reports its `bitcoin::Network`; it must match
//!    what our own `--network` implies. This catches signet/regtest mix-ups.
//!    It cannot separate two forks of mainnet — an eCash generation reports
//!    `Mainnet` — which is what the second check is for.
//! 2. **Block pin.** A network may name one block it must have: a height and
//!    the hash at that height, chosen after the network's fork point, so a
//!    chain that forked elsewhere cannot have it. The check is skipped (with a
//!    warning) while the enforcer is still below the pinned height, so a node
//!    starting against a syncing enforcer is not refused.
//!
//! Neither check is a consensus rule: nothing here depends on sidechain state,
//! so no activation height is needed and old and new nodes stay compatible.

use std::str::FromStr as _;

use bitcoin::BlockHash;

use crate::types::{
    Network,
    proto::{
        Transport,
        mainchain::{BlockHeaderInfo, ValidatorClient},
    },
};

/// A block the mainchain must carry for a network to be the right one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MainchainPin {
    /// Height the block sits at.
    pub height: u32,
    /// Hash of the block at that height, in the usual displayed byte order.
    pub block_hash_hex: &'static str,
}

impl MainchainPin {
    /// Parse the pinned hash. The constants below are covered by
    /// [`tests::every_pin_parses`], so this cannot fail in a shipped binary.
    pub fn block_hash(&self) -> BlockHash {
        BlockHash::from_str(self.block_hash_hex)
            .expect("pinned mainchain block hash must be valid hex")
    }
}

/// The eCash beta generation forks at mainchain height 967_680, so a block
/// after that point exists only on the beta chain. 968_000 is 320 blocks past
/// the fork and buried under thousands more.
const BETANET_PIN: MainchainPin = MainchainPin {
    height: 968_000,
    block_hash_hex:
        "00000000000000042ab4b327b828ae7bcfc6c88147d24d2c38e517ead4f56234",
};

impl Network {
    /// The mainchain network an enforcer must report for this network.
    ///
    /// An eCash generation runs a Core fork that calls itself `Mainnet`, so
    /// alphanet and betanet both expect `Mainnet`; only the pin separates them.
    pub fn expected_mainchain_network(self) -> bitcoin::Network {
        match self {
            Self::Signet => bitcoin::Network::Signet,
            Self::Regtest | Self::Forknet => bitcoin::Network::Regtest,
            Self::Alphanet | Self::Betanet => bitcoin::Network::Bitcoin,
        }
    }

    /// The block this network's mainchain must carry, where one is known.
    ///
    /// Only betanet is pinned. Regtest and forknet have no fixed chain at all;
    /// signet's is shared by everyone; the eCash alphanet is retired, and
    /// pinning a chain no node follows would refuse startups for no gain.
    pub fn mainchain_pin(self) -> Option<MainchainPin> {
        match self {
            Self::Betanet => Some(BETANET_PIN),
            Self::Signet | Self::Regtest | Self::Forknet | Self::Alphanet => {
                None
            }
        }
    }
}

/// What the startup check concluded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// The mainchain carries the pinned block: this is the right chain.
    Verified { height: u32, block_hash: BlockHash },
    /// The enforcer has not reached the pinned height yet, so the pin could
    /// not be checked. The network matched.
    PinNotReachedYet { tip_height: u32, pin_height: u32 },
    /// This network pins no block. The network matched.
    NoPin,
    /// The enforcer could not be asked (it is not answering yet), so nothing
    /// was checked. Startup continues: an unreachable enforcer is a transient
    /// condition the node already tolerates, and only a chain that is provably
    /// wrong stops a node from starting.
    NotChecked,
}

/// A mainchain that is not the one this network expects.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error(
        "wrong mainchain: `--network {network}` expects a {expected} mainchain, but the enforcer reports {found}"
    )]
    NetworkMismatch {
        network: Network,
        expected: bitcoin::Network,
        found: bitcoin::Network,
    },
    #[error(
        "wrong mainchain: `--network {network}` expects block {expected_hash} at height {height}, and this mainchain does not have it — the enforcer is following a different chain"
    )]
    PinBlockMissing {
        network: Network,
        height: u32,
        expected_hash: BlockHash,
    },
    #[error(
        "wrong mainchain: `--network {network}` expects block {expected_hash} at height {height}, but this mainchain has it at height {found_height}"
    )]
    PinHeightMismatch {
        network: Network,
        height: u32,
        found_height: u32,
        expected_hash: BlockHash,
    },
}

/// How long to keep asking an enforcer that is not answering yet. A node and
/// its enforcer are usually started together, so the first questions can land
/// before the enforcer is listening.
const RPC_ATTEMPTS: u32 = 10;
const RPC_RETRY_DELAY: std::time::Duration =
    std::time::Duration::from_secs(2);

/// Decide, from answers already fetched, whether this is the right mainchain.
///
/// Split out from [`verify`] so the decision is testable without a node:
/// `pin_header` is the `(height, hash)` the enforcer returned for the pinned
/// hash (`None` when it knows no such block).
pub fn check(
    network: Network,
    enforcer_network: bitcoin::Network,
    tip_height: u32,
    pin_header: Option<(u32, BlockHash)>,
) -> Result<Outcome, IdentityError> {
    let expected = network.expected_mainchain_network();
    if enforcer_network != expected {
        return Err(IdentityError::NetworkMismatch {
            network,
            expected,
            found: enforcer_network,
        });
    }
    let Some(pin) = network.mainchain_pin() else {
        return Ok(Outcome::NoPin);
    };
    if tip_height < pin.height {
        return Ok(Outcome::PinNotReachedYet {
            tip_height,
            pin_height: pin.height,
        });
    }
    let expected_hash = pin.block_hash();
    match pin_header {
        None => Err(IdentityError::PinBlockMissing {
            network,
            height: pin.height,
            expected_hash,
        }),
        Some((found_height, _)) if found_height != pin.height => {
            Err(IdentityError::PinHeightMismatch {
                network,
                height: pin.height,
                found_height,
                expected_hash,
            })
        }
        Some((height, block_hash)) => {
            Ok(Outcome::Verified { height, block_hash })
        }
    }
}

/// Ask the enforcer what chain it follows, and check it against `network`.
///
/// Returns an error ONLY when the mainchain is provably the wrong one. An
/// enforcer that cannot be reached yields [`Outcome::NotChecked`], so a node
/// started beside an enforcer that is still coming up is not refused.
pub async fn verify<T>(
    client: &mut ValidatorClient<T>,
    network: Network,
) -> Result<Outcome, IdentityError>
where
    T: Transport,
{
    let mut last_err = None;
    for attempt in 1..=RPC_ATTEMPTS {
        match ask(client, network).await {
            Ok((enforcer_network, tip_height, pin_header)) => {
                let outcome =
                    check(network, enforcer_network, tip_height, pin_header)?;
                report(network, enforcer_network, outcome);
                return Ok(outcome);
            }
            Err(err) => {
                tracing::debug!(
                    %network, attempt,
                    "mainchain identity check: enforcer not answering yet ({err})"
                );
                last_err = Some(err);
                if attempt < RPC_ATTEMPTS {
                    tokio::time::sleep(RPC_RETRY_DELAY).await;
                }
            }
        }
    }
    tracing::warn!(
        %network,
        attempts = RPC_ATTEMPTS,
        "could not ask the enforcer which mainchain it follows ({}); starting without the check",
        last_err
            .map(|err| err.to_string())
            .unwrap_or_else(|| "no answer".to_owned())
    );
    Ok(Outcome::NotChecked)
}

/// One round of questions to the enforcer.
async fn ask<T>(
    client: &mut ValidatorClient<T>,
    network: Network,
) -> Result<(bitcoin::Network, u32, Option<(u32, BlockHash)>), crate::types::proto::Error>
where
    T: Transport,
{
    let chain_info = client.get_chain_info().await?;
    let tip = client.get_chain_tip().await?;
    let pin_header: Option<BlockHeaderInfo> = match network.mainchain_pin() {
        Some(pin) if tip.height >= pin.height => {
            client.get_block_header_info(pin.block_hash()).await?
        }
        _ => None,
    };
    Ok((
        chain_info.network,
        tip.height,
        pin_header.map(|header| (header.height, header.block_hash)),
    ))
}

fn report(network: Network, enforcer_network: bitcoin::Network, outcome: Outcome) {
    match outcome {
        Outcome::Verified { height, block_hash } => tracing::info!(
            %network, height, %block_hash,
            "mainchain identity verified: the enforcer follows the expected chain"
        ),
        Outcome::PinNotReachedYet {
            tip_height,
            pin_height,
        } => tracing::warn!(
            %network, tip_height, pin_height,
            "mainchain identity only partly checked: the enforcer is below the pinned height, so the chain cannot be confirmed yet"
        ),
        Outcome::NoPin => tracing::info!(
            %network, mainchain = %enforcer_network,
            "mainchain network matches; this network pins no block"
        ),
        Outcome::NotChecked => (),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(height: u32, hash: BlockHash) -> (u32, BlockHash) {
        (height, hash)
    }

    #[test]
    fn every_pin_parses() {
        for network in [
            Network::Signet,
            Network::Regtest,
            Network::Forknet,
            Network::Alphanet,
            Network::Betanet,
        ] {
            if let Some(pin) = network.mainchain_pin() {
                // Panics if the constant is not valid hex.
                let _hash = pin.block_hash();
            }
        }
    }

    #[test]
    fn betanet_pins_the_known_beta_block() {
        let pin = Network::Betanet.mainchain_pin().expect("betanet is pinned");
        assert_eq!(pin.height, 968_000);
        assert_eq!(
            pin.block_hash().to_string(),
            "00000000000000042ab4b327b828ae7bcfc6c88147d24d2c38e517ead4f56234"
        );
        assert_eq!(
            Network::Betanet.expected_mainchain_network(),
            bitcoin::Network::Bitcoin
        );
    }

    #[test]
    fn only_betanet_is_pinned() {
        for network in [
            Network::Signet,
            Network::Regtest,
            Network::Forknet,
            Network::Alphanet,
        ] {
            assert_eq!(
                network.mainchain_pin(),
                None,
                "{network} must not pin a mainchain block"
            );
        }
    }

    #[test]
    fn the_right_chain_verifies() {
        let pin = Network::Betanet.mainchain_pin().unwrap();
        let outcome = check(
            Network::Betanet,
            bitcoin::Network::Bitcoin,
            969_999,
            Some(header(pin.height, pin.block_hash())),
        )
        .expect("the beta chain must verify");
        assert_eq!(
            outcome,
            Outcome::Verified {
                height: pin.height,
                block_hash: pin.block_hash()
            }
        );
    }

    #[test]
    fn another_chain_at_the_same_height_is_refused() {
        // An enforcer following a different fork of mainnet — alphanet, say —
        // is past the height but has never heard of the block.
        let err = check(
            Network::Betanet,
            bitcoin::Network::Bitcoin,
            969_999,
            None,
        )
        .expect_err("a chain without the pinned block must be refused");
        let msg = err.to_string();
        assert!(
            matches!(err, IdentityError::PinBlockMissing { height, .. } if height == 968_000),
            "unexpected error: {msg}"
        );
        assert!(msg.contains("following a different chain"), "{msg}");
    }

    #[test]
    fn the_pinned_block_at_the_wrong_height_is_refused() {
        let pin = Network::Betanet.mainchain_pin().unwrap();
        let err = check(
            Network::Betanet,
            bitcoin::Network::Bitcoin,
            969_999,
            Some(header(968_001, pin.block_hash())),
        )
        .expect_err("a pinned block at the wrong height must be refused");
        assert!(
            matches!(
                err,
                IdentityError::PinHeightMismatch {
                    height: 968_000,
                    found_height: 968_001,
                    ..
                }
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn the_wrong_network_is_refused() {
        let err = check(
            Network::Betanet,
            bitcoin::Network::Signet,
            969_999,
            None,
        )
        .expect_err("a signet enforcer must be refused for betanet");
        assert!(
            matches!(
                err,
                IdentityError::NetworkMismatch {
                    expected: bitcoin::Network::Bitcoin,
                    found: bitcoin::Network::Signet,
                    ..
                }
            ),
            "unexpected error: {err}"
        );
        // And the other way round: a mainnet enforcer for a signet node.
        let err = check(
            Network::Signet,
            bitcoin::Network::Bitcoin,
            1,
            None,
        )
        .expect_err("a mainnet enforcer must be refused for signet");
        assert!(matches!(err, IdentityError::NetworkMismatch { .. }));
    }

    #[test]
    fn a_syncing_enforcer_is_not_refused() {
        let outcome = check(
            Network::Betanet,
            bitcoin::Network::Bitcoin,
            900_000,
            None,
        )
        .expect("an enforcer below the pinned height must not be refused");
        assert_eq!(
            outcome,
            Outcome::PinNotReachedYet {
                tip_height: 900_000,
                pin_height: 968_000
            }
        );
    }

    #[test]
    fn unpinned_networks_check_only_the_network() {
        assert_eq!(
            check(Network::Regtest, bitcoin::Network::Regtest, 0, None)
                .expect("regtest against a regtest enforcer is fine"),
            Outcome::NoPin
        );
        assert_eq!(
            check(Network::Signet, bitcoin::Network::Signet, 250_000, None)
                .expect("signet against a signet enforcer is fine"),
            Outcome::NoPin
        );
        assert!(
            check(Network::Regtest, bitcoin::Network::Bitcoin, 0, None)
                .is_err(),
            "regtest against a mainnet enforcer must be refused"
        );
    }
}
