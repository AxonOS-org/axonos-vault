//! The boundary, tested as an adversary would probe it.

use axonos_hal::{
    sim::{FaultProfile, SimDevice},
    AcquisitionDevice, Frontend, LeadOff, SampleFrame, TimingBudget,
};
use axonos_vault::*;

fn frame(seq: u32, v: i32) -> SampleFrame {
    let mut f = SampleFrame::zeroed(seq, seq as u64 * 4_000);
    f.codes = [v; 8];
    f
}

fn filled(n: u32) -> Vault {
    let mut v = Vault::new();
    for i in 0..n {
        v.admit(frame(i, 1_000 + i as i32));
    }
    v
}

// ── the budget is the whole point ──

#[test]
fn a_reduction_costs_bits_and_the_budget_falls() {
    let mut v = filled(10);
    v.issue(Grant::new(1, Purpose::QualityFeedback, 1_000, u64::MAX));
    let r = v.reduce(ContactQuality::new());
    let d = v.release(r, Purpose::QualityFeedback, 1, 0).unwrap();
    assert_eq!(d.reduction.cost_bits(), 32);
    assert_eq!(d.remaining_bits, 968);
}

#[test]
fn the_reconstruction_attack_runs_out_of_budget() {
    // An application that asks for an honest aggregate a thousand times has
    // asked for the signal. The budget is what stops it, and this is the test
    // that proves the stopping is real rather than intended.
    let mut v = filled(250);
    // 1 kbit total: 31 single-scalar disclosures, then nothing
    v.issue(Grant::new(9, Purpose::QualityFeedback, 1_000, u64::MAX));

    let mut granted = 0;
    let mut last = None;
    for i in 0..10_000u64 {
        let r = v.reduce(ContactQuality::new());
        match v.release(r, Purpose::QualityFeedback, 9, i) {
            Ok(_) => granted += 1,
            Err(e) => {
                last = Some(e);
                break;
            }
        }
    }
    assert_eq!(granted, 31, "1000 bits / 32 bits per scalar");
    assert!(matches!(last, Some(Denial::BudgetExhausted { .. })));
    assert!(v.total_released_bits() <= 1_000);
}

#[test]
fn a_wide_reduction_costs_proportionally_more() {
    let mut v = filled(50);
    v.issue(Grant::new(2, Purpose::Calibration, 320, u64::MAX));
    // eight channels = 256 bits; a second one will not fit in the remaining 64
    let r1 = v.reduce(ChannelMean::new());
    assert_eq!(
        v.release(r1, Purpose::Calibration, 2, 0)
            .unwrap()
            .remaining_bits,
        64
    );
    let r2 = v.reduce(ChannelMean::new());
    assert!(matches!(
        v.release(r2, Purpose::Calibration, 2, 0),
        Err(Denial::BudgetExhausted {
            needed_bits: 256,
            remaining_bits: 64
        })
    ));
}

#[test]
fn cost_is_computed_by_the_vault_not_declared_by_the_asker() {
    // Reduction::new is the only constructor and it fixes len from the slice,
    // so a reducer cannot understate what it is carrying.
    let wide = Reduction::new(&[0; 16], 5).unwrap();
    assert_eq!(wide.cost_bits(), 512);
    assert!(
        Reduction::new(&[0; 17], 5).is_none(),
        "over-wide is refused, not truncated"
    );
}

// ── the grant's other terms ──

#[test]
fn revocation_is_terminal_and_outranks_every_other_reason() {
    let mut v = filled(10);
    v.issue(Grant::new(3, Purpose::Control, 32, 1_000));
    v.revoke(3);
    let r = v.reduce(ContactQuality::new());
    // expired AND wrong purpose AND over budget — still reported as Revoked
    assert_eq!(
        v.release(r, Purpose::Calibration, 3, 99_999),
        Err(Denial::Revoked)
    );
    assert!(v.grant(3).unwrap().is_revoked());
}

#[test]
fn purpose_is_checked_and_both_sides_are_named() {
    let mut v = filled(10);
    v.issue(Grant::new(4, Purpose::Calibration, 1_000, u64::MAX));
    let r = v.reduce(ContactQuality::new());
    assert_eq!(
        v.release(r, Purpose::Control, 4, 0),
        Err(Denial::PurposeMismatch {
            granted: Purpose::Calibration,
            requested: Purpose::Control
        })
    );
}

#[test]
fn an_expired_grant_releases_nothing() {
    let mut v = filled(10);
    v.issue(Grant::new(5, Purpose::Control, 1_000, 500));
    let r = v.reduce(ContactQuality::new());
    assert!(
        v.release(r, Purpose::Control, 5, 500).is_ok(),
        "not_after is inclusive"
    );
    let r2 = v.reduce(ContactQuality::new());
    assert_eq!(
        v.release(r2, Purpose::Control, 5, 501),
        Err(Denial::Expired)
    );
}

#[test]
fn an_unknown_grant_is_refused_without_hinting_at_state() {
    let mut v = filled(10);
    let r = v.reduce(ContactQuality::new());
    assert_eq!(
        v.release(r, Purpose::Control, 77, 0),
        Err(Denial::NoSuchGrant)
    );
}

// ── nothing is fabricated ──

#[test]
fn an_empty_window_supports_no_disclosure() {
    let mut v = Vault::new();
    v.issue(Grant::new(6, Purpose::QualityFeedback, 1_000, u64::MAX));
    let r = v.reduce(ContactQuality::new());
    assert!(r.is_empty() && r.support() == 0);
    assert_eq!(
        v.release(r, Purpose::QualityFeedback, 6, 0),
        Err(Denial::EmptyReduction)
    );
}

#[test]
fn a_disclosure_states_its_own_support() {
    let v = filled(37);
    let r = v.reduce(ChannelMean::new());
    assert_eq!(
        r.support(),
        37,
        "the reader can see how thin the evidence is"
    );
}

#[test]
fn the_window_evicts_rather_than_growing() {
    let v = filled((WINDOW + 100) as u32);
    assert_eq!(v.sealed_len(), WINDOW);
}

#[test]
fn reduction_reads_the_window_oldest_first_after_wrap() {
    let mut v = Vault::new();
    for i in 0..(WINDOW as u32 + 5) {
        v.admit(frame(i, i as i32));
    }
    // after wrap the oldest retained is 5, the newest WINDOW+4
    let r = v.reduce(ChannelMean::new());
    assert_eq!(r.support(), WINDOW as u32);
    // retained codes are exactly 5..=WINDOW+4; their integer mean is the
    // arithmetic the classic off-by-one in a ring buffer gets wrong
    let sum: i64 = (5..=(WINDOW as i64 + 4)).sum();
    let expected = (sum / WINDOW as i64) as i32;
    assert!(
        r.values().iter().all(|&v| v == expected),
        "expected every channel to read {expected}, got {:?}",
        r.values()
    );
}

// ── the record ──

#[test]
fn every_disclosure_is_recorded_with_its_terms() {
    let mut v = filled(20);
    v.issue(Grant::new(7, Purpose::ClinicalReview, 1_000, u64::MAX));
    for t in 0..3u64 {
        let r = v.reduce(ContactQuality::new());
        v.release(r, Purpose::ClinicalReview, 7, t * 100).unwrap();
    }
    let entries: Vec<_> = v.log().collect();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].purpose, Purpose::ClinicalReview);
    assert_eq!(entries[2].at_us, 200);
    assert_eq!(v.total_released_bits(), 96);
}

#[test]
fn releases_stop_when_they_can_no_longer_be_recorded() {
    let mut v = filled(20);
    // the largest grant N5 permits: every free log entry at the minimum charge
    assert!(v.issue(Grant::new(
        8,
        Purpose::LocalDiagnostics,
        (LOG_CAPACITY as u32) * BITS_PER_SCALAR,
        u64::MAX
    )));
    for i in 0..LOG_CAPACITY {
        let r = v.reduce(ContactQuality::new());
        assert!(v.release(r, Purpose::LocalDiagnostics, 8, i as u64).is_ok());
    }
    let r = v.reduce(ContactQuality::new());
    // budget and log capacity now reach zero together, which is what N5 is for
    assert!(matches!(
        v.release(r, Purpose::LocalDiagnostics, 8, 999),
        Err(Denial::LogFull) | Err(Denial::BudgetExhausted { .. })
    ));
}

#[test]
fn refusals_are_counted() {
    let mut v = filled(10);
    let r = v.reduce(ContactQuality::new());
    let _ = v.release(r, Purpose::Control, 404, 0);
    assert_eq!(v.refusals(), 1);
}

#[test]
fn purging_destroys_data_but_not_the_record() {
    let mut v = filled(50);
    v.issue(Grant::new(11, Purpose::QualityFeedback, 1_000, u64::MAX));
    let r = v.reduce(ContactQuality::new());
    v.release(r, Purpose::QualityFeedback, 11, 0).unwrap();
    v.purge();
    assert_eq!(v.sealed_len(), 0);
    assert_eq!(
        v.log().count(),
        1,
        "the record outlives the data it describes"
    );
}

// ── grants are bounded too ──

#[test]
fn grant_slots_are_finite_and_refused_rather_than_evicted() {
    let mut v = Vault::new();
    for i in 0..MAX_GRANTS {
        assert!(v.issue(Grant::new(i as u16, Purpose::Control, 32, u64::MAX)));
    }
    assert!(
        !v.issue(Grant::new(99, Purpose::Control, 32, u64::MAX)),
        "evicting a grant would silently widen the budget in flight"
    );
    // reissuing an existing id replaces it
    assert!(v.issue(Grant::new(0, Purpose::Calibration, 64, u64::MAX)));
    assert_eq!(v.grant(0).unwrap().purpose, Purpose::Calibration);
}

// ── the organ connects to the organ below it ──

#[test]
fn a_real_acquisition_session_flows_through_the_boundary() {
    let budget = TimingBudget::canonical(250).unwrap();
    let mut dev = SimDevice::new(11, FaultProfile::FIELD);
    dev.configure(budget, Frontend::CANONICAL).unwrap();

    let mut v = Vault::new();
    assert!(
        v.issue(Grant::new(1, Purpose::QualityFeedback, 2_048, u64::MAX)),
        "2048 = 64 log entries x 32 bits, the most this vault can record"
    );

    let mut admitted = 0u32;
    for _ in 0..1_000 {
        if let Ok(f) = dev.read_frame() {
            v.admit(f);
            admitted += 1;
        }
    }
    assert!(admitted > 900);
    assert_eq!(v.sealed_len(), WINDOW);

    let r = v.reduce(ContactQuality::new());
    let d = v.release(r, Purpose::QualityFeedback, 1, 0).unwrap();
    assert_eq!(d.reduction.support(), WINDOW as u32);
    // the field profile lifts an electrode, so quality is not perfect
    assert_eq!(v.total_released_bits(), 32);
    assert!(v.grant(1).unwrap().spent_bits() == 32);
}

#[test]
fn lead_off_is_visible_through_the_boundary_without_the_signal_being() {
    let mut v = Vault::new();
    for i in 0..100u32 {
        let mut f = frame(i, 500);
        if i >= 60 {
            f.lead_off = LeadOff(0b1);
        }
        v.admit(f);
    }
    v.issue(Grant::new(1, Purpose::QualityFeedback, 64, u64::MAX));
    let r = v.reduce(ContactQuality::new());
    let d = v.release(r, Purpose::QualityFeedback, 1, 0).unwrap();
    // one scalar left the vault: 40 bad frames out of 100. The samples did not.
    assert_eq!(d.reduction.len(), 1);
    assert_eq!(d.reduction.support(), 100);
    assert_eq!(
        d.reduction.values(),
        &[40],
        "40 of 100 frames had a lifted electrode"
    );
}

// ── RFC-0009 N5: a grant must be spendable within the recording capacity ──

#[test]
fn a_grant_larger_than_the_log_can_record_is_refused() {
    let mut v = filled(10);
    // 64 entries x 32 bits = 2048; the 3200 the README once advertised is not
    // spendable, and advertising it was the defect axonos-stack surfaced.
    assert!(!v.issue(Grant::new(1, Purpose::Control, 3_200, u64::MAX)));
    assert!(v.issue(Grant::new(1, Purpose::Control, 2_048, u64::MAX)));
    assert!(v.grant(1).is_some());
}

#[test]
fn capacity_is_shared_so_commitments_sum() {
    let mut v = filled(10);
    assert!(v.issue(Grant::new(1, Purpose::Control, 1_024, u64::MAX)));
    assert!(v.issue(Grant::new(2, Purpose::Calibration, 1_024, u64::MAX)));
    // both fit individually and jointly exhaust the capacity
    assert!(
        !v.issue(Grant::new(3, Purpose::Control, 32, u64::MAX)),
        "issuing two that jointly overcommit is the same defect one step later"
    );
}

#[test]
fn reissuing_a_grant_releases_its_own_commitment() {
    let mut v = filled(10);
    assert!(v.issue(Grant::new(1, Purpose::Control, 2_048, u64::MAX)));
    // replacing id 1 must not double-count the budget it already held
    assert!(v.issue(Grant::new(1, Purpose::Calibration, 2_048, u64::MAX)));
    assert_eq!(v.grant(1).unwrap().purpose, Purpose::Calibration);
}

#[test]
fn recordable_capacity_shrinks_as_the_log_fills() {
    let mut v = filled(10);
    let before = v.recordable_bits();
    v.issue(Grant::new(1, Purpose::QualityFeedback, 1_024, u64::MAX));
    let r = v.reduce(ContactQuality::new());
    v.release(r, Purpose::QualityFeedback, 1, 0).unwrap();
    assert_eq!(v.recordable_bits(), before - BITS_PER_SCALAR);
}

// ── RFC-0009 U2: probing the window is no longer free ──

#[test]
fn probing_an_empty_window_costs_bits() {
    let mut v = Vault::new();
    v.issue(Grant::new(1, Purpose::QualityFeedback, 128, u64::MAX));
    let r = v.reduce(ContactQuality::new());
    assert_eq!(
        v.release(r, Purpose::QualityFeedback, 1, 0),
        Err(Denial::EmptyReduction)
    );
    assert_eq!(
        v.grant(1).unwrap().spent_bits(),
        PROBE_COST_BITS,
        "the liveness answer is charged, so the channel is under the budget"
    );
    assert_eq!(v.probes(), 1);
}

#[test]
fn liveness_polling_is_bounded_by_the_budget() {
    // The attack U2 describes: ask repeatedly whether the device is recording.
    let mut v = Vault::new();
    v.issue(Grant::new(1, Purpose::QualityFeedback, 128, u64::MAX)); // 4 probes
    let mut answered = 0;
    for i in 0..1_000u64 {
        let r = v.reduce(ContactQuality::new());
        match v.release(r, Purpose::QualityFeedback, 1, i) {
            Err(Denial::EmptyReduction) => answered += 1,
            Err(Denial::BudgetExhausted { .. }) => break,
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(
        answered, 4,
        "1000 probes, 4 answers — the channel is finite"
    );
    assert_eq!(v.grant(1).unwrap().remaining_bits(), 0);
}

#[test]
fn a_refusal_on_grant_state_is_still_free() {
    // Charging those would let a malformed client drain a budget that belongs
    // to the subject, and they reveal only what the requester already knew.
    let mut v = filled(10);
    v.issue(Grant::new(1, Purpose::Control, 128, u64::MAX));
    let r = v.reduce(ContactQuality::new());
    assert_eq!(
        v.release(r, Purpose::Calibration, 1, 0),
        Err(Denial::PurposeMismatch {
            granted: Purpose::Control,
            requested: Purpose::Calibration
        })
    );
    assert_eq!(v.grant(1).unwrap().spent_bits(), 0);
    assert_eq!(v.probes(), 0);
}

#[test]
fn a_probe_with_no_budget_left_reports_the_budget_not_the_window() {
    let mut v = Vault::new();
    v.issue(Grant::new(1, Purpose::QualityFeedback, 32, u64::MAX));
    let r = v.reduce(ContactQuality::new());
    assert_eq!(
        v.release(r, Purpose::QualityFeedback, 1, 0),
        Err(Denial::EmptyReduction)
    );
    let r2 = v.reduce(ContactQuality::new());
    // now broke: the answer must not be given away as a consolation
    assert!(matches!(
        v.release(r2, Purpose::QualityFeedback, 1, 1),
        Err(Denial::BudgetExhausted { .. })
    ));
}
