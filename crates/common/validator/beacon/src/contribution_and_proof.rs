use ream_bls::{BLSSignature, PrivateKey, traits::Signable};
use ream_consensus_misc::{
    constants::beacon::genesis_validators_root,
    misc::{compute_domain, compute_epoch_at_slot, compute_signing_root},
};
pub use ream_events_beacon::contribution_and_proof::{
    ContributionAndProof, SyncCommitteeContribution,
};
use ream_network_spec::networks::beacon_network_spec;

use crate::{
    constants::DOMAIN_CONTRIBUTION_AND_PROOF, sync_committee::get_sync_committee_selection_proof,
};

pub fn get_contribution_and_proof(
    contribution: SyncCommitteeContribution,
    aggregator_index: u64,
    private_key: &PrivateKey,
) -> anyhow::Result<ContributionAndProof> {
    Ok(ContributionAndProof {
        selection_proof: get_sync_committee_selection_proof(
            contribution.slot,
            contribution.subcommittee_index,
            private_key,
        )?,
        aggregator_index,
        contribution,
    })
}

pub fn get_contribution_and_proof_signature(
    contribution_and_proof: &ContributionAndProof,
    private_key: &PrivateKey,
) -> anyhow::Result<BLSSignature> {
    let epoch = compute_epoch_at_slot(contribution_and_proof.contribution.slot);
    let domain = compute_domain(
        DOMAIN_CONTRIBUTION_AND_PROOF,
        Some(beacon_network_spec().current_fork_version(epoch)),
        Some(genesis_validators_root()),
    );
    let signing_root = compute_signing_root(contribution_and_proof, domain);
    Ok(private_key.sign(signing_root.as_ref())?)
}
