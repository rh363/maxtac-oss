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
- Fase 3: la verifica fallisce se il fix introduce un finding nuovo dello stesso scanner di
  severità almeno media (SAST nei file toccati, CVE ovunque); il rescan rilancia solo gli
  scanner che hanno prodotto il finding.
- Test d'integrazione della Fase 3 con bandit reale: `shell=True` → MR verificata, falso positivo
  noto ignorato, fingerprint stabili su due notti con il codice spostato.
- Fase 4: il test di regressione di un bug deve fallire sul codice base (controllo in un
  sandbox nuovo con i soli test aggiunti, poi ripristino e confronto del diff).
- Bug hunting: campo `symbol` nello schema, fingerprint dei bug su file + simbolo invece che sul
  titolo; le MR chiuse senza merge valgono come rifiuto anche per i bug.
- Rotazione del bug hunting più equa: a parità di notte vince il repo cacciato meno volte.
- Storico delle run (`RunStore`, tabella `runs` con il report JSON completo) e ultime run in
  `status`.
- Notifica del mattino (`NotifierPort`): `NoopNotifier` di default, `WebhookNotifier` con POST
  JSON, URL da segreto, testo sempre neutro.
- Simulazione di una settimana di notti: tetti di spesa, MR per notte, rotazione, nessuna MR
  doppia.

- Fase 5a: API della dashboard in sola lettura (`maxtac web`, FastAPI, extra `web`): `me`,
  `dashboard`, `findings` con filtri e paginazione, `runs`, dettaglio run e task. Contratto
  OpenAPI in `web/openapi.json` verificato da un test.
- Login OIDC (Authorization Code + PKCE, state e nonce, validazione dell'id_token con JWKS in
  cache), sessione in cookie firmato, allowlist utenti, rate limit sul login, modalità dev
  solo su loopback.
- Temi per utente nella dashboard: il pacchetto di un tema alternativo è servito solo a chi ce
  l'ha assegnato; per tutti gli altri è indistinguibile da un tema inesistente.
- Servizio `web` nel compose: senza socket Docker né segreti del bot, db in sola lettura,
  porta solo su loopback dietro reverse proxy.
- Il report di ogni fix conserva motivo del triage e output dei test della verifica.

### Security

- Descrizione, titolo e commit delle MR: campi non fidati sanificati (niente a capo, `|`,
  backtick, menzioni), testo del modello e output dei test in blocchi di codice, nessuna riga
  che inizi con `/` (quick action GitLab).
- Report e webhook: testo non fidato con HTML, markup di Slack e menzioni neutralizzati.
- File protetti: per CVE e SAST nessun test toccabile, nemmeno aggiunto; config di CI, test
  runner e scanner protetta ovunque nel repo; `pyproject.toml` e `package.json` ammessi per le
  CVE solo se non cambiano le sezioni di test e scanner; symlink e gitlink a un umano.
- Bug: la suite senza i test aggiunti deve passare sul fix; euristica sui test di regressione
  che escono dal processo.
- Scanner senza soppressioni inline (`--disable-nosem`, `--ignore-nosec`, `-nosec`), osv con
  config vuota e database offline, semgrep con ruleset locali; binari per path assoluto.
- Rescan in un sandbox nuovo senza setup né test, sulla fotografia git del fix; `git clean
  -ffdx` dopo l'agente; snapshot e ripristino come tree git invece che via sandbox.
- `PATH` del sandbox con le directory di sistema prima di quelle scrivibili; `GOPROXY` senza
  `direct`; watchdog che uccide il container bloccato oltre timeout + margine.
- Proxy: allowlist ridotta ai registry (niente GitHub, semgrep.dev, api.osv.dev), solo CONNECT.
- `.git` directory nella working tree eliminata; checkout eliminato a fine repo.
- Spesa addebitata anche per le risposte strutturate inutilizzabili; run non avviata a crediti
  del mese esauriti e tetto della notte ridotto ai crediti rimasti.
- Scanner Python installati con hash (`scripts/lock-sandbox-tools.sh`) e script per pinnare i
  digest delle immagini (`scripts/pin-digests.sh`).

### Changed

- Il db SQLite usa il journal `DELETE` invece di WAL, così la dashboard può leggerlo da un
  mount in sola lettura.
- Lo store dei finding è per repo (chiave progetto + fingerprint): prima la stessa CVE in due
  repo condivideva lo stato, e un finding ignorato in un repo veniva soppresso anche negli altri.
- La spesa dei task è registrata con scope `fix:<repo>:<task>`, distinto tra repo.

- Una chiamata servita da un modello senza prezzo in config (fallback lato server) si conta al
  prezzo più alto noto invece di fallire dopo aver già speso.

[Unreleased]: https://github.com/rh363/maxtac-oss/commits/main
