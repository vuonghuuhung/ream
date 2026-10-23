use anyhow::anyhow;
use ream_bls::traits::Verifiable;
use ream_chain_beacon::beacon_chain::BeaconChain;
use ream_consensus_beacon::{
    electra::beacon_state::BeaconState, single_attestation::SingleAttestation,
};
use ream_consensus_misc::{
    constants::beacon::{DOMAIN_BEACON_ATTESTER, SLOTS_PER_EPOCH},
    misc::{compute_epoch_at_slot, compute_signing_root},
};
use ream_fork_choice_beacon::store::get_checkpoint_block_from_db;
use ream_storage::{
    cache::{AtestationKey, BeaconCacheDB, insert_if_unseen},
    tables::table::REDBTable,
};
use ream_validator_beacon::attestation::compute_subnet_for_attestation;

use super::result::ValidationResult;

const GOSSIP_ATTESTATION_SYNC_TOLERANCE: u64 = 2 * SLOTS_PER_EPOCH;

/// Why an attestation for a block the node has not seen is ignored.
pub const UNSEEN_BLOCK_REASON: &str = "The block being voted for has not been seen";

fn is_too_far_behind_to_validate(head_slot: u64, attestation_slot: u64) -> bool {
    attestation_slot.saturating_sub(head_slot) > GOSSIP_ATTESTATION_SYNC_TOLERANCE
}

pub async fn validate_beacon_attestation(
    attestation: &SingleAttestation,
    beacon_chain: &BeaconChain,
    attestation_subnet_id: u64,
    cached_db: &BeaconCacheDB,
) -> anyhow::Result<ValidationResult> {
    // A cheap read of the published head; everything below runs off-lock. Block lookups go
    // straight to the database, which serves readers without the store lock.
    let head = beacon_chain.head()?;
    let db = beacon_chain.db();
    let current_slot = head.current_slot;

    // [IGNORE] attestation.data.slot is equal to or earlier than the current_slot (with a
    // MAXIMUM_GOSSIP_CLOCK_DISPARITY allowance)
    if attestation.data.slot > current_slot {
        return Ok(ValidationResult::Ignore(
            "Attestation is from a future slot".to_string(),
        ));
    }

    if is_too_far_behind_to_validate(head.head_slot, attestation.data.slot) {
        return Ok(ValidationResult::Ignore(
            "Local chain is syncing and too far behind to validate attestation".to_string(),
        ));
    }

    // The head state fixes committees up to one epoch past its own. Advancing a copy further
    // costs an epoch transition, about a second on mainnet, for every message, which stalls the
    // network loop while the node catches up; such attestations are ignored until the head
    // moves.
    if !head
        .state
        .determines_committees_of(compute_epoch_at_slot(attestation.data.slot))
    {
        return Ok(ValidationResult::Ignore(
            "Head state is too far behind to compute the attestation's committee".to_string(),
        ));
    }
    let state: &BeaconState = &head.state;

    let committee_index = attestation.committee_index;
    let committees_per_slot = state.get_committee_count_per_slot(attestation.data.target.epoch);

    // [REJECT] In Electra, SingleAttestation carries the committee index separately and
    // attestation.data.index must be zero.
    if attestation.data.index != 0 {
        return Ok(ValidationResult::Reject(
            "Electra attestation data index must be 0".to_string(),
        ));
    }

    // [REJECT] The committee index is within the expected range
    if committee_index >= committees_per_slot {
        return Ok(ValidationResult::Reject(
            "The committee index is not within the expected range".to_string(),
        ));
    }

    // [REJECT] The attestation is for the correct subnet
    if compute_subnet_for_attestation(committees_per_slot, attestation.data.slot, committee_index)
        != attestation_subnet_id
    {
        return Ok(ValidationResult::Reject(
            "The attestation is not for the correct subnet".to_string(),
        ));
    }

    // [IGNORE] the epoch of attestation.data.slot is either the current or previous epoch (with a
    // MAXIMUM_GOSSIP_CLOCK_DISPARITY allowance)
    let attestation_epoch = compute_epoch_at_slot(attestation.data.slot);
    let current_epoch = compute_epoch_at_slot(current_slot);
    let previous_epoch = current_epoch.saturating_sub(1);

    if attestation_epoch != current_epoch && attestation_epoch != previous_epoch {
        return Ok(ValidationResult::Ignore(
            "Attestation is from a epoch too far in the past".to_string(),
        ));
    }

    // [REJECT] The attestation's epoch matches its target
    if attestation.data.target.epoch != attestation_epoch {
        return Ok(ValidationResult::Reject(
            "The attestation's epoch doesn't match its target".to_string(),
        ));
    }

    // [REJECT] The attester is a member of the committee
    if !state
        .get_beacon_committee(attestation.data.slot, committee_index)?
        .contains(&(attestation.attester_index))
    {
        return Ok(ValidationResult::Reject(
            "The attester is not a member of the committee".to_string(),
        ));
    }

    // [IGNORE] There has been no other valid attestation seen on an attestation subnet that has an
    // identical attestation.data.target.epoch and participating validator index.
    let attestation_key = AtestationKey {
        attestation_subnet_id,
        target_epoch: attestation.data.target.epoch,
        participating_validator_index: attestation.attester_index,
    };
    if cached_db
        .seen_attestations
        .read()
        .await
        .contains(&attestation_key)
    {
        return Ok(ValidationResult::Ignore(
            "An attestation from this validator for this subnet and target epoch has already been seen".to_string(),
        ));
    }

    // The database checks below are far cheaper than a BLS verification, so they run first:
    // a node that is behind ignores most attestations for unseen blocks. The spec lists the
    // signature check first, so an invalid signature for an unseen block is ignored here rather
    // than rejected. Lighthouse v8.2.0 does the same: `verify_early_checks` requires a known head
    // block before `verify_slashable` checks the signature.
    // [IGNORE] The block being voted for (aggregate.data.beacon_block_root) has been seen (via
    // gossip or non-gossip sources) (a client MAY queue aggregates for processing once block is
    // retrieved).
    if !db
        .block_provider()
        .contains_key(attestation.data.beacon_block_root)?
    {
        return Ok(ValidationResult::Ignore(UNSEEN_BLOCK_REASON.to_string()));
    }

    // [REJECT] The block being voted for (aggregate.data.beacon_block_root) passes validation.
    // All blocks stored passed validation

    // [REJECT] The attestation's target block is an ancestor of the block named in the LMD vote
    if get_checkpoint_block_from_db(
        db,
        attestation.data.beacon_block_root,
        attestation.data.target.epoch,
    )? != attestation.data.target.root
    {
        return Ok(ValidationResult::Reject(
            "The target block is not an ancestor of the LMD vote block".to_string(),
        ));
    }

    // [IGNORE] The current finalized_checkpoint is an ancestor of the block defined by
    // aggregate.data.beacon_block_root
    let finalized_checpoint = head.finalized_checkpoint;
    if get_checkpoint_block_from_db(
        db,
        attestation.data.beacon_block_root,
        finalized_checpoint.epoch,
    )? != finalized_checpoint.root
    {
        return Ok(ValidationResult::Ignore(
            "Finalized checkpoint is not an ancestor of the block defined by aggregate.data.beacon_block_root".to_string(),
        ));
    }

    // [REJECT] The signature of attestation is valid.
    if !attestation_signature_is_valid(state, attestation)? {
        return Ok(ValidationResult::Reject(
            "Invalid attestation signature".to_string(),
        ));
    }

    if !insert_if_unseen(&cached_db.seen_attestations, attestation_key).await {
        return Ok(ValidationResult::Ignore(
            "An attestation from this validator for this subnet and target epoch has already been seen".to_string(),
        ));
    }
    Ok(ValidationResult::Accept)
}

/// Whether `attestation` is signed by its attester, whose committee `state` determines.
pub fn attestation_signature_is_valid(
    state: &BeaconState,
    attestation: &SingleAttestation,
) -> anyhow::Result<bool> {
    let validator = state
        .validators
        .get(attestation.attester_index as usize)
        .ok_or_else(|| anyhow!("Could not get validator"))?;
    let domain = state.get_domain(DOMAIN_BEACON_ATTESTER, Some(attestation.data.target.epoch));
    let signing_root = compute_signing_root(&attestation.data, domain);
    Ok(attestation
        .signature
        .verify(&validator.public_key, signing_root.as_slice())?)
}

#[cfg(test)]
mod tests {
    use super::{GOSSIP_ATTESTATION_SYNC_TOLERANCE, is_too_far_behind_to_validate};

    #[test]
    fn skips_attestation_validation_only_beyond_sync_tolerance() {
        let head_slot = 1_000;

        assert!(!is_too_far_behind_to_validate(
            head_slot,
            head_slot + GOSSIP_ATTESTATION_SYNC_TOLERANCE
        ));
        assert!(is_too_far_behind_to_validate(
            head_slot,
            head_slot + GOSSIP_ATTESTATION_SYNC_TOLERANCE + 1
        ));
        assert!(!is_too_far_behind_to_validate(head_slot, head_slot - 1));
    }
}
