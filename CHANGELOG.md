# Changelog

Tutte le modifiche rilevanti a questo progetto sono documentate in questo file.

Il formato segue [Keep a Changelog](https://keepachangelog.com/it/1.1.0/) e il progetto
adotta il [Semantic Versioning](https://semver.org/lang/it/).

## [Unreleased]

### Added

- Fase 0: modelli di dominio, porte, policy (fingerprint, dedup, raggruppamento CVE,
  priorità, rotazione del bug hunting, file protetti, scheduling) e budget con prezzi da config.
- Servizi di triage, fix agent con loop agentico proprio, bug hunting e pipeline notturna
  con verifica indipendente.
- Store SQLite per finding, rotazione e spesa.
- Config YAML validata e segreti da Docker secret.
- CLI `run`, `patrol`, `status` con temi di presentazione per utente.
- Test della pipeline con adapter finti, senza rete.

[Unreleased]: https://github.com/rh363/maxtac-oss/commits/main
