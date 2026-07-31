# Changelog

## [0.2.2] — 2026-08-01

### Changed
- **Re-pinned `axonos-hal` to v0.3.0.** The stack moved to 0.3.0 for operating
  points while this crate stayed on 0.2.0, which put two copies of the HAL in
  one dependency graph — and two copies mean two distinct `SampleFrame` types
  that cargo resolves without complaint and the compiler then refuses to unify.
  The integration build caught it, which is the argument for having one.

  Nothing here uses operating points; the pin moves so the graph has a single
  HAL, which is a property the whole stack depends on and no individual crate
  can observe.

All notable changes to axonos-vault are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] — 2026-08-01

### Added
- Licence texts (`LICENSE-APACHE`, `LICENSE-MIT`), the `NOTICE` that
  Apache-2.0 section 4(d) obliges a redistributor to retain, `CITATION.cff`
  with the author listed first, and this changelog.

  The crate declared `Apache-2.0 OR MIT` in its manifest and its README from
  the first release and shipped neither text. A dual-licence declaration
  without the licences does not grant what it announces: a reader who wants to
  depend on this had nothing to read, and Apache-2.0's attribution clause
  cannot be honoured against a `NOTICE` that does not exist. That is a defect
  in what the repository *is*, not in what it does, which is why it is recorded
  here rather than quietly added.

  No code changed. The version moves because the artefact a consumer receives
  is materially different: it can now be depended on under the terms it always
  claimed.

---

<sub>**axonos-vault v0.2.1** · © 2026 Denis Yermakou · Apache-2.0 OR MIT ·
authored for [The AxonOS Project](https://axonos.org) · connect@axonos.org</sub>
