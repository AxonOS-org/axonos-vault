<div align="center">

# axonos-vault

### Raw neural data does not leave. Bounded reductions of it might.

[![Tests](https://img.shields.io/badge/tests-19%20passing-0d7a5f?style=flat-square)](tests/boundary.rs)
[![no_std](https://img.shields.io/badge/no__std-yes-0a4a8f?style=flat-square)](#constraints)
[![unsafe](https://img.shields.io/badge/unsafe-forbidden-0a4a8f?style=flat-square)](#constraints)
[![Allocation](https://img.shields.io/badge/allocation-none-0a4a8f?style=flat-square)](#constraints)
[![License](https://img.shields.io/badge/License-Apache--2.0%20OR%20MIT-475569?style=flat-square)](#licensing)

</div>

---

AxonOS makes one promise that matters more than the rest: what your brain
produced stays yours. Every other component supports it — the HAL refuses to
invent or lose a sample, the consent layer decides who may act, the protocol
carries what was agreed. **None of them actually stop an application from
reading the samples.**

This crate is where that stops being an intention.

## How it works

Samples enter a `Sealed` window. Nothing takes one out: the type has no
accessor, no `Clone`, no `Copy`, no `Debug`, no `Deref`. The absence *is* the
mechanism — code that exfiltrates raw samples cannot be written against this
type, so the review question stops being "does anyone read this" and becomes
"did anyone build a second path", which is a far smaller thing to audit.

The only way to learn anything is a `Reducer`, which runs **inside** the vault,
sees frames one at a time, and keeps only its own compile-time-bounded state.
Its output does not go to the caller either. It goes to `release`, which checks
a `Grant`, charges the disclosure against an **information budget**, records it,
and only then hands anything back.

```rust
let mut vault = Vault::new();
vault.issue(Grant::new(1, Purpose::QualityFeedback, 3_200, expiry));

vault.admit(frame);                                  // raw enters, never returns

let reduction = vault.reduce(ContactQuality::new()); // one scalar
let disclosure = vault.release(reduction, Purpose::QualityFeedback, 1, now)?;
// disclosure.reduction.values() == [40]  — 40 of 250 frames had a lifted electrode.
// The 250 frames themselves did not move.
```

## Why a budget, and not just a permission

A permission system that answers yes or no per request is defeated by asking
many times. Eight channels at 250 SPS is 48 kbit/s; an application allowed to
ask for "the mean of the last window" a thousand times a second has been handed
the signal back, one honest answer at a time. That is the standard
reconstruction attack against any aggregate-only interface, and a boundary that
does not address it is decoration.

So the vault does not count requests. It counts **bits released**, against a
ceiling the grant declares:

```
the_reconstruction_attack_runs_out_of_budget ... ok
  10 000 honest requests → 31 granted, then BudgetExhausted
```

The cost is computed by the vault from what a disclosure actually carries, never
self-reported by the code asking for it — a reducer that could price itself
would price itself at zero.

## The terms of a grant

Scoped, bounded, expiring, revocable, terminal when withdrawn, auditable
afterwards — deliberately the same shape as consent withdrawal, because it is
the same problem wearing different clothes.

| Check | Behaviour |
|:--|:--|
| Revoked | terminal; outranks every other reason, so an audit reads the true cause |
| Expired | `not_after` is inclusive |
| Purpose | mismatch names both sides — a calibration grant cannot be spent on telemetry |
| Substance | an empty reduction, or one over an empty window, is refused rather than released as zero |
| Budget | refused with the exact shortfall in bits |
| Record | when the audit log is full, releases **stop** — an unrecorded disclosure is worse than a refused one |

`purge()` destroys the sealed window and leaves the record intact: the point of
the record is that it outlives the data it describes.

## What this does not claim

It does not make reductions private in the differential sense. No noise is
added, and a bounded release of a real measurement is still a real measurement.
This bounds **how much** leaves and **for what**, and makes the record of it
undeniable. Those are different guarantees, and conflating them would be exactly
the overclaim this project refuses.

## Constraints

`#![no_std]` · `#![forbid(unsafe_code)]` · `#![deny(missing_docs)]` · no
allocation · fixed window, fixed grant table, fixed audit log · rustfmt clean.

## Where it sits

```
electrodes → axonos-hal → [ axonos-vault ] → axonos-signal-pipeline
                                           → axonos-consent → axonos-protocol → application
```

The HAL guarantees the samples are real. The vault guarantees they stay.

## Licensing

Apache-2.0 OR MIT, matching the AxonOS core.

---

<div align="center">

**© The AxonOS Project / Denis Yermakou**

[axonos.org](https://axonos.org) · [medium.com/@AxonOS](https://medium.com/@AxonOS) · connect@axonos.org · security@axonos.org

</div>
