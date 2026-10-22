# Changelog

Tutte le modifiche rilevanti a questo progetto sono documentate in questo file.

Il formato segue [Keep a Changelog](https://keepachangelog.com/it/1.1.0/) e il progetto
adotta il [Semantic Versioning](https://semver.org/lang/it/).

## [Unreleased]

### Fixed

- Sandbox: `/tmp` e la home erano montati `noexec` (default di Docker per i tmpfs), quindi
  `go test` non poteva eseguire i binari compilati e le estensioni C installate da pip non si
  caricavano. Ora i tmpfs hanno `exec`; `smoke-images.sh` esegue un `go test`.
- Proxy dei sandbox: squid andava in crash all'avvio (non può riaprire `/dev/stdout` come
  utente `proxy`), quindi i sandbox non raggiungevano nessun registry. Ora logga su file, che
  l'immagine porta su stdout; `scripts/smoke-proxy.sh` lo verifica in CI.
- Client GitLab con timeout (`gitlab.timeout_s`, default 30 s): una GitLab irraggiungibile dai
  container lasciava `tokens` e la run appesi per sempre.
- Dashboard: la sidebar resta ferma mentre la pagina scorre (prima su pagine lunghe restava
  visibile solo il riquadro della prossima run).
- Documentazione del deploy: i file in `secrets/` devono essere dell'utente 1000; MTU delle
  reti Docker su VM con interfaccia a 1450.

### Added

- Sandbox con Python 3.14 (`python3.14`, CPython standalone via uv in `/opt/python`) accanto
  al 3.13 di default, per i repo che richiedono Python 3.14. L'autodiscovery lo usa da sola
  quando `requires-python` (o Poetry) chiede 3.14, e i prompt di discovery e fix lo citano.
- Repo in sola scansione (`scan_only` in `repos:` del config, `repos approve --scan-only`):
  finding tracciati in `status` e dashboard, ma niente triage, fix né bug hunting. Per i repo
  i cui test non possono girare nel sandbox.
- Registry interni: allowlist locale del proxy in `proxy/local/extra-registries.txt` (fuori da
  git) e credenziali di sola lettura `sandbox.registry_credentials`, scritte nel `~/.netrc` di
  ogni sandbox. I valori sono oscurati nell'output del sandbox, in MR, commit, report e
  webhook; un fix che li contiene non viene pubblicato. Allowlist e credenziali non possono
  coprire GitLab (config, avvio dei sandbox e `status`).
- CLI: riga di chiusura facoltativa dopo `run`, definita dal lessico dell'operatore
  (`quiet_night`, `clean_sweep`); il lessico neutro non ne ha e il report su disco non cambia.
- CI con GitHub Actions (`ci.yml`): test e lint Python e frontend, Playwright, build delle tre
  immagini senza push e prova senza rete con rootfs in sola lettura (`scripts/smoke-images.sh`).
- Pubblicazione su GHCR (`release.yml`) dopo il CI verde: `autofix-orchestrator`,
  `autofix-web`, `autofix-sandbox`, private, con tag `main`/`sha-<commit>`/semver, provenance,
  SBOM e firma cosign keyless; rebuild settimanale del sandbox il lunedì.
- `scripts/update.sh` (pull, sandbox compreso, e riavvio), `scripts/verify-images.sh` (firma
  cosign), `scripts/pin-actions.sh` (SHA delle azioni).
- `DockerSandbox`: errore chiaro se l'immagine dei sandbox manca sull'host, senza tentare il
  pull (il registry è privato).
- Dashboard: il comando da copiare nella pagina Repository segue il lessico dell'utente
  (etichetta `cli.name`); il server scrive sempre il comando neutro `autofix`.

- Più token GitLab: `gitlab.tokens` con un nome e i prefissi di path coperti (gruppo,
  sottogruppo o progetto); ogni repo usa il token con il prefisso più specifico. I valori
  stanno in `secrets/gitlab_tokens/<nome>` (montata dal compose) o in `GITLAB_TOKEN_<NOME>`.
- Utente e identità dei commit letti da GitLab per ogni token (`GET /user`), con controllo di
  scope e scadenza (`GET /personal_access_tokens/self`) a ogni run e con `autofix tokens`.
- Stato dei token (nome, scope, utente, scadenza, mai i valori) in `autofix status` e nella
  pagina Impostazioni della dashboard, con avviso 30 giorni prima della scadenza; token usato
  da ogni repo e proposta nella pagina Repository e in `autofix repos list/show`.
- `autofix schedule` (lo scheduler; il vecchio nome resta accettato ma non è più documentato).


- Fase 6b, dashboard: pagina Repository (repo attivi con origine, comandi, rotazione del bug
  hunting, finding per stato e MR aperte; proposte dell'autodiscovery con baseline, sospetti,
  differenze dalla config attiva e comando `autofix repos approve` da copiare, senza scritture)
  e pagina Impostazioni (config effettiva in sola lettura, senza segreti, path, utenti o temi).
- Ricerca testuale nei finding (`/api/findings?q=`, anche nell'URL della SPA) su regola,
  posizione, dettaglio e tool; `%` e `_` sono letterali. Il dettaglio dei finding ora è salvato
  nello store (colonna `detail`, aggiunta in automatico ai db esistenti).
- Passi dell'agente per task (`iterations` e `agent_stop` in `FixResult` e nei report salvati),
  mostrati nel dettaglio della run e del task; i report precedenti restano validi.
- Grafico della spesa giornaliera nella dashboard (`/api/spend/daily`): colonne impilate per
  fix, bug hunting e triage/discovery, linea del tetto per notte, cumulato del mese contro i
  crediti, dettaglio con mouse e tastiera, tabella dei dati.
- Alias `autofix` del comando `maxtac`: è il nome mostrato dalla dashboard a ogni utente.
- `scripts/seed-demo-db.py`: 30 giorni di spesa, repo con comandi diversi, un repo approvato e
  proposte in attesa (una sospetta), sostituite e rifiutate.

### Changed

- Immagini su GHCR pubbliche: README e go-live non chiedono più `docker login`.
- Il compose usa le immagini di GHCR (`AUTOFIX_TAG`, oppure `AUTOFIX_*_IMAGE` per digest) e
  tiene `build:` per la build locale; profilo `sandbox` al posto di `build` per l'immagine dei
  sandbox, che l'orchestrator riceve in `AUTOFIX_SANDBOX_IMAGE`. Default di `sandbox.image`:
  `ghcr.io/rh363/autofix-sandbox:main`.
- README: il passo "Costruisci e avvia" diventa "Scarica e avvia" (login a GHCR, `.env`,
  `update.sh`); la build locale resta come alternativa.


- Un repo del `config.yaml` non coperto da nessun token blocca l'avvio; uno approvato viene
  saltato con il motivo nel report e `repos approve` lo rifiuta. Un token non valido ferma solo
  i repo che copre.
- `bot_username`, `bot_name` e `bot_email` valgono solo senza `tokens` (configurazione a
  token unico, ancora supportata).
- `scripts/pin-digests.sh` pinna anche le immagini di `Dockerfile.web`.

- Documentazione riorganizzata: il README spiega come si installa e come si usa (requisiti,
  token GitLab senza admin, Application OIDC, primo utilizzo, uso quotidiano, costi,
  manutenzione, problemi comuni); i contenuti tecnici sono in `docs/` (`architecture.md`,
  `security.md`, `configuration.md`, `development.md`, `go-live.md`).
- Le immagini Docker, l'healthcheck e i messaggi della CLI usano il comando `autofix`.


- E2E: ogni progetto Playwright esegue solo i test che lo riguardano (prima 6 test su 10
  risultavano saltati per scelta del progetto o per gli screenshot); screenshot come progetti
  separati con `SCREENSHOTS=1`.
- `approval_blockers` in `domain/policy.py`: regole di `repos approve --force` condivise tra
  CLI e dashboard.

- Fase 6a, autodiscovery dei repo: `maxtac repos discover [--project X | --all] [--no-llm]`
  propone linguaggi e comandi di setup/test (rilevamento deterministico, poi un loop agentico
  breve in sola lettura con tetto `budget.discovery_per_repo_usd`), esegue una baseline sul
  commit base in un sandbox nuovo e salva una proposta `pending`. `repos list`, `show`,
  `approve [--edit] [--force]`, `reject` e `remove` la gestiscono; i repo approvati entrano
  nella run notturna (in caso di conflitto vince `config.yaml`).
- Controllo dei comandi scoperti: test banali, `|| true`, strumenti di rete, publish/push,
  scritture fuori da `/work`, privilegi. Per approvarli serve `--force`.
- Porta `RepoRegistry` con le tabelle SQLite `repo_proposals` e `repos`, leggibili anche dalla
  dashboard.
- Utenti della dashboard per email verificata (`web.user_claim: email`, default): allowlist e
  `ui.themes` per email, senza distinzione di maiuscole; scope `email` aggiunto da solo.
- `gitlab.ca_bundle` per un GitLab self-hosted con CA interna (API, git e login OIDC quando
  l'issuer è GitLab).
- Fase 5b: SPA della dashboard in `frontend/` (SvelteKit SPA, Svelte 5, TypeScript, Tailwind,
  Zod, Lucide) dai mockup approvati: dashboard, finding con filtri nell'URL, storico e dettaglio
  delle run con timeline per repo, dettaglio task con diff e output dei test. Responsive.
- Tema per utente caricato a runtime (`/api/theme/<nome>/theme.css` e `lexicon.json`, font
  self-hosted dallo stesso endpoint protetto); il bundle base contiene solo il tema di default,
  verificato a ogni build con `web/theme-terms.json`.
- FastAPI serve la build della SPA (`web.static_dir`) con fallback su `index.html`, cache
  immutabile per gli asset e CSP con hash per lo script di avvio, senza `'unsafe-inline'`.
- `/api/dashboard` espone anche repository, prossima run, MR massime e repo di bug hunting per
  notte.
- `Dockerfile.web` multi-stage (build Node, poi solo la build nell'immagine Python).
- `scripts/seed-demo-db.py`: db e config demo per sviluppo e test e2e (Playwright) sui due
  temi; test unitari vitest (client API e contratto con `web/openapi.json`, lessico, filtri,
  formattazione); screenshot in `docs/screenshots/`.
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



- `repos` in `config.yaml` può essere vuoto. `config.example.yaml` usa solo domini d'esempio
  (lo verifica un test).
- Tema dell'operatore attenuato come da mockup approvato: etichette funzionali chiare in
  CLI e dashboard, il tema resta in marchio, sottotitoli secondari, colori e font; la valuta è
  sempre `$`. Lessico con override `ui` per le etichette della dashboard.

- Il db SQLite usa il journal `DELETE` invece di WAL, così la dashboard può leggerlo da un
  mount in sola lettura.
- Lo store dei finding è per repo (chiave progetto + fingerprint): prima la stessa CVE in due
  repo condivideva lo stato, e un finding ignorato in un repo veniva soppresso anche negli altri.
- La spesa dei task è registrata con scope `fix:<repo>:<task>`, distinto tra repo.

- Una chiamata servita da un modello senza prezzo in config (fallback lato server) si conta al
  prezzo più alto noto invece di fallire dopo aver già speso.

### Fixed

- `sandbox/Dockerfile`: ruleset semgrep scaricati con retry, User-Agent e controllo del
  contenuto (`sandbox/fetch-semgrep-rules.py`); link `pysemgrep` solo se esiste; errore
  esplicito se il database OSV offline resta vuoto.

### Security

- Un test verifica che l'allowlist del proxy dei sandbox contenga solo i registry dei
  pacchetti e mai l'host di GitLab.
- Login rifiutato con claim `email` mancante o `email_verified` diverso da `true`.
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

[Unreleased]: https://github.com/rh363/maxtac-oss/commits/main
