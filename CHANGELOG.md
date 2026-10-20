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
- Fase 1: `GitLabVCS` (python-gitlab + git CLI con git dir separata, hooks e protocolli non
  https disattivati, token solo in header via env, errori ripuliti).
- `DockerSandbox`: container effimeri non root, `cap_drop: ALL`, rootfs in sola lettura, rete
  interna con proxy, limiti di risorse, output e timeout limitati.
- Scanner `osv-scanner`, `semgrep`, `bandit`, `gosec` con normalizzazione in `Finding`.
- `run --scan-only`: checkout e scan a costo zero con lista dei finding normalizzati.
- Dockerfile dell'orchestrator e dei sandbox, proxy squid con allowlist, `docker-compose.yml`,
  script di ricostruzione settimanale dell'immagine dei sandbox.
- Config: identità del bot, parametri del sandbox, ruleset semgrep per linguaggio.
- Fase 2: `AnthropicLLM` sulla Messages API: structured output con JSON schema per triage e
  bug hunting, turni del loop agentico rimandati identici (thinking compresi), prompt caching
  su tool, system e ultimo messaggio, fallback lato server sui rifiuti per Opus e Sonnet 5.5,
  `effort` per modello, timeout e retry configurabili.
- `run` e `patrol` funzionano end-to-end con gli adapter reali; `patrol` sopravvive a una run
  fallita e ricostruisce la pipeline a ogni notte.
- Crediti esauriti o chiave rifiutata fermano la notte in modo pulito (`LLMUnavailable`),
  senza contare tentativi sui finding; il report riporta il motivo.
- `status` mostra la spesa del mese rispetto a `budget.monthly_credits_usd`, la proiezione a fine
  mese e un avviso se la supera.
- Test d'integrazione della Fase 2 con git reale: dipendenza vulnerabile → MR con il bump pushato.

### Changed

- Una chiamata servita da un modello senza prezzo in config (fallback lato server) si conta al
  prezzo più alto noto invece di fallire dopo aver già speso.

[Unreleased]: https://github.com/rh363/maxtac-oss/commits/main
