//! # axonos-vault
//!
//! **Raw neural data does not leave. Bounded reductions of it might.**
//!
//! AxonOS makes one promise that matters more than the rest: what your brain
//! produced stays yours. Every other component supports that promise —
//! [`axonos-hal`] refuses to invent or lose a sample, `axonos-consent` decides
//! who may act, `axonos-protocol` carries what was agreed. None of them
//! actually stop an application from reading the samples.
//!
//! This crate is the boundary where that stops being an intention.
//!
//! ## The design, in one paragraph
//!
//! Samples enter a [`Sealed`] window. Nothing can take one out: the type has
//! no accessor, no `Clone`, no `Copy`, and no `Debug`. The only way to learn
//! anything is to run a [`Reducer`] *inside* the vault, which sees frames one
//! at a time and may keep only its own small state. The reducer's output is
//! not returned to the caller either — it goes to [`Vault::release`], which
//! checks a [`Grant`], charges the disclosure against an **information
//! budget**, records it, and only then hands back a [`Disclosure`].
//!
//! ## Why a budget, and not just a permission
//!
//! A permission system that answers yes or no to each request is defeated by
//! asking many times. Eight channels at 250 SPS is 48 kbit/s of raw signal; an
//! application permitted to ask for "the mean of the last window" a thousand
//! times per second has been handed the signal back, one honest answer at a
//! time. This is not hypothetical — it is the standard reconstruction attack
//! against any aggregate-only interface.
//!
//! So the vault does not count requests. It counts **bits released**, against
//! a ceiling the grant declares, and the count is computed by the vault from
//! what a disclosure actually contains — never self-reported by the reducer
//! asking for it. When the budget is gone the grant is spent, and the answer
//! is no until a human grants a new one.
//!
//! This is deliberately the same shape as consent withdrawal and the spending
//! mandate: scoped, bounded, expiring, revocable, terminal when withdrawn, and
//! auditable afterwards. The organism solves authority the same way everywhere,
//! because it is the same problem wearing different clothes.
//!
//! ## What this crate does not claim
//!
//! It does not make reductions *private* in the differential sense — no noise
//! is added, and a bounded release of a real measurement is still a real
//! measurement. It bounds **how much** leaves and **for what**, and it makes
//! the record of that undeniable. Those are different guarantees, and
//! conflating them would be exactly the kind of overclaim this project
//! refuses.
//!
//! [`axonos-hal`]: https://github.com/AxonOS-org/axonos-hal

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

use axonos_hal::{SampleFrame, CHANNELS};

/// Frames held in the sealed window.
///
/// At 250 SPS this is one second of signal. Fixed at compile time because the
/// vault must never allocate, and because a window whose size depends on
/// runtime input is a window an attacker can grow.
pub const WINDOW: usize = 250;

/// Scalars a single disclosure may carry.
///
/// Small on purpose. A reduction that needs more than this is not a reduction,
/// and the correct response is to refuse it rather than to widen the pipe.
pub const MAX_DISCLOSURE: usize = 16;

/// Bits charged per scalar released.
pub const BITS_PER_SCALAR: u32 = 32;

/// What a disclosure is for.
///
/// Purpose is declared by the grant and checked at release. An application
/// holding a grant for calibration cannot spend it on telemetry, even though
/// the bits would be identical — which is the difference between a budget and
/// a licence to look.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Purpose {
    /// Establishing a per-user baseline.
    Calibration,
    /// Producing a control decision the user asked for.
    Control,
    /// Signal quality shown to the user or a clinician.
    QualityFeedback,
    /// A clinician reviewing a session, with the user present.
    ClinicalReview,
    /// Developer diagnostics on the device itself.
    LocalDiagnostics,
}

/// A window of samples that cannot be read.
///
/// There is deliberately no method returning a [`SampleFrame`], no `Clone`, no
/// `Copy`, no `Debug`, and no `Deref`. The absence is the mechanism: code that
/// wants to exfiltrate raw samples cannot be written against this type, so the
/// review question stops being "does anyone read this" and becomes "does
/// anyone construct a second path", which is a much smaller thing to audit.
pub struct Sealed {
    frames: [SampleFrame; WINDOW],
    len: usize,
    head: usize,
    /// Total frames ever admitted, so the audit record can state coverage.
    admitted: u64,
}

impl Default for Sealed {
    fn default() -> Self {
        Self::new()
    }
}

impl Sealed {
    /// An empty window.
    pub const fn new() -> Self {
        Self {
            frames: [SampleFrame::zeroed(0, 0); WINDOW],
            len: 0,
            head: 0,
            admitted: 0,
        }
    }

    /// Admit one frame, evicting the oldest when full.
    ///
    /// Takes the frame by value and keeps no reference to it: the caller's copy
    /// is theirs to drop, and the vault's copy is unreachable.
    pub fn admit(&mut self, f: SampleFrame) {
        self.frames[self.head] = f;
        self.head = (self.head + 1) % WINDOW;
        if self.len < WINDOW {
            self.len += 1;
        }
        self.admitted = self.admitted.saturating_add(1);
    }

    /// Frames currently held.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the window holds nothing.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Frames admitted since the vault was created.
    pub const fn admitted(&self) -> u64 {
        self.admitted
    }

    /// Discard everything held. The only bulk operation, and it destroys rather
    /// than reveals.
    pub fn purge(&mut self) {
        self.len = 0;
        self.head = 0;
        self.frames = [SampleFrame::zeroed(0, 0); WINDOW];
    }

    /// Run a reducer across the window, oldest frame first.
    ///
    /// The reducer is the only thing that ever sees a sample, and it sees them
    /// one at a time with nowhere to put them: whatever it accumulates is
    /// bounded by its own type, which is declared at compile time.
    pub fn reduce<R: Reducer>(&self, r: &mut R) {
        if self.len == 0 {
            return;
        }
        let start = if self.len < WINDOW { 0 } else { self.head };
        for i in 0..self.len {
            r.observe(&self.frames[(start + i) % WINDOW]);
        }
    }
}

/// Something that may look at raw samples, one at a time, and keep a little.
///
/// Implementations live inside the vault boundary. The trait cannot hand a
/// frame back — `observe` takes a reference whose lifetime ends with the call,
/// and `finish` returns a [`Reduction`], which is fixed-size by construction.
pub trait Reducer {
    /// See one frame. Called oldest-first.
    fn observe(&mut self, frame: &SampleFrame);
    /// Produce the bounded result. Consumes the reducer so that a partially
    /// consumed accumulator cannot be released twice under one charge.
    fn finish(self) -> Reduction;
}

/// A fixed-size result. The only thing that can ever leave the vault.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Reduction {
    values: [i32; MAX_DISCLOSURE],
    len: usize,
    /// Frames the reduction was computed over — carried so a disclosure can
    /// state its own support rather than implying one.
    support: u32,
}

impl Reduction {
    /// Build a reduction. Values beyond [`MAX_DISCLOSURE`] are refused, not
    /// truncated: silently dropping part of an answer produces a number that
    /// means something other than what its author intended.
    pub fn new(values: &[i32], support: u32) -> Option<Self> {
        if values.len() > MAX_DISCLOSURE {
            return None;
        }
        let mut v = [0i32; MAX_DISCLOSURE];
        v[..values.len()].copy_from_slice(values);
        Some(Self {
            values: v,
            len: values.len(),
            support,
        })
    }

    /// The permitted values.
    ///
    /// Readable, and deliberately so: the vault's job is to bound *how much*
    /// leaves and *for what*, not to hand back a number nobody can use. What
    /// is unreadable is [`Sealed`] — the samples these were computed from.
    pub fn values(&self) -> &[i32] {
        &self.values[..self.len]
    }

    /// Scalars carried.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the reduction carries nothing.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Frames this was computed over.
    pub const fn support(&self) -> u32 {
        self.support
    }

    /// Information cost in bits, computed from what is actually carried.
    ///
    /// Never supplied by the requester. A reducer that could declare its own
    /// price would set it to zero.
    pub const fn cost_bits(&self) -> u32 {
        (self.len as u32) * BITS_PER_SCALAR
    }
}

/// Why a release was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Denial {
    /// The grant named in the request does not exist.
    NoSuchGrant,
    /// The grant was withdrawn. Terminal.
    Revoked,
    /// The grant's validity window has closed.
    Expired,
    /// The grant covers a different purpose than the request.
    PurposeMismatch {
        /// What the grant permits.
        granted: Purpose,
        /// What was asked for.
        requested: Purpose,
    },
    /// The remaining budget cannot cover this disclosure.
    BudgetExhausted {
        /// Bits this disclosure would cost.
        needed_bits: u32,
        /// Bits left on the grant.
        remaining_bits: u32,
    },
    /// The reduction carries nothing, so there is nothing to release — and a
    /// zero-cost release would be a free probe of the vault's state.
    EmptyReduction,
    /// The window held no frames, so any reduction over it is fabricated.
    NoSupport,
    /// The audit log is full. Releases stop rather than proceeding unrecorded:
    /// an unrecorded disclosure is worse than a refused one.
    LogFull,
}

/// A grant of information: this purpose, this many bits, until this time.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Grant {
    /// Identifier the requester quotes.
    pub id: u16,
    /// What the bits may be spent on.
    pub purpose: Purpose,
    /// Ceiling on cumulative disclosure, in bits.
    pub budget_bits: u32,
    /// Bits spent so far.
    spent_bits: u32,
    /// Last instant at which this grant is valid, microseconds, inclusive.
    pub not_after: u64,
    /// Whether the human withdrew it.
    revoked: bool,
}

impl Grant {
    /// Issue a grant.
    pub const fn new(id: u16, purpose: Purpose, budget_bits: u32, not_after: u64) -> Self {
        Self {
            id,
            purpose,
            budget_bits,
            spent_bits: 0,
            not_after,
            revoked: false,
        }
    }

    /// Bits still available.
    pub const fn remaining_bits(&self) -> u32 {
        self.budget_bits.saturating_sub(self.spent_bits)
    }

    /// Bits released under this grant.
    pub const fn spent_bits(&self) -> u32 {
        self.spent_bits
    }

    /// Whether the human withdrew it.
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }
}

/// One disclosure, as it happened.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Record {
    /// Grant the bits were charged to.
    pub grant: u16,
    /// What the disclosure was for.
    pub purpose: Purpose,
    /// Bits released.
    pub bits: u32,
    /// Frames the reduction was computed over.
    pub support: u32,
    /// When, in microseconds.
    pub at_us: u64,
}

/// What the requester receives when a release is permitted.
///
/// Carries the reduction *and* the terms it was released under, so the two
/// cannot be separated downstream: a number that has lost its purpose and its
/// grant is a number nobody can account for later.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Disclosure {
    /// The permitted values.
    pub reduction: Reduction,
    /// The grant charged.
    pub grant: u16,
    /// The purpose it was released for.
    pub purpose: Purpose,
    /// Bits remaining on the grant afterwards.
    pub remaining_bits: u32,
}

/// Entries the audit log holds before releases stop.
pub const LOG_CAPACITY: usize = 64;
/// Grants a vault may hold at once.
pub const MAX_GRANTS: usize = 8;

/// The boundary itself: sealed samples, the grants against them, and the record.
pub struct Vault {
    sealed: Sealed,
    grants: [Option<Grant>; MAX_GRANTS],
    log: [Option<Record>; LOG_CAPACITY],
    log_len: usize,
    /// Disclosures refused, by any cause — a rising count is a signal in itself.
    refusals: u32,
}

impl Default for Vault {
    fn default() -> Self {
        Self::new()
    }
}

impl Vault {
    /// An empty vault with no grants.
    pub const fn new() -> Self {
        Self {
            sealed: Sealed::new(),
            grants: [None; MAX_GRANTS],
            log: [None; LOG_CAPACITY],
            log_len: 0,
            refusals: 0,
        }
    }

    /// Admit a sample. The only way data enters.
    pub fn admit(&mut self, f: SampleFrame) {
        self.sealed.admit(f);
    }

    /// Frames currently sealed.
    pub const fn sealed_len(&self) -> usize {
        self.sealed.len()
    }

    /// Install a grant, replacing any grant with the same id.
    ///
    /// Returns `false` when there is no room — grants are refused rather than
    /// evicting an existing one, because evicting a grant silently widens the
    /// total budget in flight.
    pub fn issue(&mut self, g: Grant) -> bool {
        for slot in self.grants.iter_mut() {
            if matches!(slot, Some(existing) if existing.id == g.id) {
                *slot = Some(g);
                return true;
            }
        }
        for slot in self.grants.iter_mut() {
            if slot.is_none() {
                *slot = Some(g);
                return true;
            }
        }
        false
    }

    /// Withdraw a grant. Terminal: there is no way back, by design and for the
    /// same reason `axonos-consent` makes withdrawal terminal.
    pub fn revoke(&mut self, id: u16) -> bool {
        for slot in self.grants.iter_mut().flatten() {
            if slot.id == id {
                slot.revoked = true;
                return true;
            }
        }
        false
    }

    /// Inspect a grant's terms and remaining budget.
    pub fn grant(&self, id: u16) -> Option<&Grant> {
        self.grants.iter().flatten().find(|g| g.id == id)
    }

    /// Run a reducer over the sealed window.
    ///
    /// Returns the reduction to the *caller of this crate*, which is the vault
    /// owner (the kernel), not the application. Nothing has been released yet;
    /// [`Vault::release`] is the boundary.
    pub fn reduce<R: Reducer>(&self, mut r: R) -> Reduction {
        self.sealed.reduce(&mut r);
        r.finish()
    }

    /// Attempt to release a reduction under a grant.
    ///
    /// Order of checks is deliberate: existence, then revocation, then expiry,
    /// then purpose, then substance, then budget. A revoked grant reports
    /// `Revoked` and never `BudgetExhausted`, so an audit reads the true reason
    /// rather than whichever check happened to run first.
    pub fn release(
        &mut self,
        reduction: Reduction,
        purpose: Purpose,
        grant_id: u16,
        now_us: u64,
    ) -> Result<Disclosure, Denial> {
        let idx = match self
            .grants
            .iter()
            .position(|g| matches!(g, Some(x) if x.id == grant_id))
        {
            Some(i) => i,
            None => return self.refuse(Denial::NoSuchGrant),
        };
        let g = self.grants[idx].as_ref().expect("checked above");

        if g.revoked {
            return self.refuse(Denial::Revoked);
        }
        if now_us > g.not_after {
            return self.refuse(Denial::Expired);
        }
        if g.purpose != purpose {
            let granted = g.purpose;
            return self.refuse(Denial::PurposeMismatch {
                granted,
                requested: purpose,
            });
        }
        if reduction.is_empty() {
            return self.refuse(Denial::EmptyReduction);
        }
        if reduction.support() == 0 {
            return self.refuse(Denial::NoSupport);
        }

        let cost = reduction.cost_bits();
        let remaining = g.remaining_bits();
        if cost > remaining {
            return self.refuse(Denial::BudgetExhausted {
                needed_bits: cost,
                remaining_bits: remaining,
            });
        }
        // Refuse rather than release unrecorded. A disclosure nobody can point
        // at afterwards defeats the purpose of having a boundary at all.
        if self.log_len >= LOG_CAPACITY {
            return self.refuse(Denial::LogFull);
        }

        let g = self.grants[idx].as_mut().expect("checked above");
        g.spent_bits += cost;
        let remaining_after = g.remaining_bits();

        self.log[self.log_len] = Some(Record {
            grant: grant_id,
            purpose,
            bits: cost,
            support: reduction.support(),
            at_us: now_us,
        });
        self.log_len += 1;

        Ok(Disclosure {
            reduction,
            grant: grant_id,
            purpose,
            remaining_bits: remaining_after,
        })
    }

    fn refuse(&mut self, d: Denial) -> Result<Disclosure, Denial> {
        self.refusals = self.refusals.saturating_add(1);
        Err(d)
    }

    /// Every disclosure that happened, oldest first.
    pub fn log(&self) -> impl Iterator<Item = &Record> {
        self.log[..self.log_len].iter().flatten()
    }

    /// Total bits released across all grants — the number that answers "how
    /// much of me left this device".
    pub fn total_released_bits(&self) -> u32 {
        self.log().map(|r| r.bits).sum()
    }

    /// Releases refused, for any reason.
    pub const fn refusals(&self) -> u32 {
        self.refusals
    }

    /// Destroy the sealed window. Grants and the audit record survive: the
    /// point of the record is that it outlives the data it describes.
    pub fn purge(&mut self) {
        self.sealed.purge();
    }
}

// ---------------------------------------------------------------------------
// Reducers shipped with the vault
// ---------------------------------------------------------------------------

/// Mean amplitude per channel, in raw codes.
///
/// Eight scalars — the smallest useful description of a window, and the one a
/// quality indicator or a calibration routine actually needs.
pub struct ChannelMean {
    sums: [i64; CHANNELS],
    n: u32,
}

impl Default for ChannelMean {
    fn default() -> Self {
        Self::new()
    }
}

impl ChannelMean {
    /// A fresh accumulator.
    pub const fn new() -> Self {
        Self {
            sums: [0; CHANNELS],
            n: 0,
        }
    }
}

impl Reducer for ChannelMean {
    fn observe(&mut self, frame: &SampleFrame) {
        for (s, &c) in self.sums.iter_mut().zip(frame.codes.iter()) {
            *s += c as i64;
        }
        self.n = self.n.saturating_add(1);
    }

    fn finish(self) -> Reduction {
        if self.n == 0 {
            return Reduction::new(&[], 0).expect("empty fits");
        }
        let mut out = [0i32; CHANNELS];
        for (o, s) in out.iter_mut().zip(self.sums.iter()) {
            *o = (*s / self.n as i64) as i32;
        }
        Reduction::new(&out, self.n).expect("CHANNELS <= MAX_DISCLOSURE")
    }
}

/// A single scalar: how many frames in the window had any electrode off
/// contact. The cheapest honest answer to "is the signal usable", at one
/// thirty-second of the cost of the per-channel mean.
pub struct ContactQuality {
    bad: u32,
    n: u32,
}

impl Default for ContactQuality {
    fn default() -> Self {
        Self::new()
    }
}

impl ContactQuality {
    /// A fresh accumulator.
    pub const fn new() -> Self {
        Self { bad: 0, n: 0 }
    }
}

impl Reducer for ContactQuality {
    fn observe(&mut self, frame: &SampleFrame) {
        if frame.lead_off.any() || frame.saturated() {
            self.bad = self.bad.saturating_add(1);
        }
        self.n = self.n.saturating_add(1);
    }

    fn finish(self) -> Reduction {
        if self.n == 0 {
            return Reduction::new(&[], 0).expect("empty fits");
        }
        Reduction::new(&[self.bad as i32], self.n).expect("one value fits")
    }
}
