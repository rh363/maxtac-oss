# Sviluppo

Requisiti: Python 3.13 con [uv](https://docs.astral.sh/uv/), Node LTS per il frontend. Test e
controlli girano senza rete: GitLab, Docker e il modello sono sostituiti da adapter finti
(`tests/fakes.py`), git e bandit sono quelli reali.

## Backend

```bash
uv sync
uv run pytest                     # anche con -W error
uv run ruff check src tests scripts && uv run ruff format --check src tests scripts
uv run mypy src                   # strict
```

Il test d'integrazione con un Docker reale è skippato di default:
`AUTOFIX_DOCKER_TESTS=1 uv run pytest -m docker`.

Si lavora test prima (pytest, adapter finti), poi implementazione, poi documentazione e
CHANGELOG. I vincoli non negoziabili sono in [`CLAUDE.md`](../CLAUDE.md).

## Provarlo in locale

```bash
cp config.example.yaml config.yaml   # adatta workdir e db_path per l'uso locale
uv run autofix --config config.yaml status
GITLAB_TOKEN=... uv run autofix --config config.yaml run --repo team/api --scan-only
ANTHROPIC_API_KEY=... GITLAB_TOKEN=... uv run autofix --config config.yaml run --repo team/api --dry-run
```

Comandi:

- `autofix run [--repo X] [--dry-run]`: esegue subito; in dry-run niente push né MR, diff su
  disco;
- `autofix run --scan-only`: solo checkout e scan (tutti gli scanner, zero token): stampa i
  finding normalizzati e li scrive in `workdir/<run_id>/findings.json`. Non tocca lo store;
- `autofix schedule`: resta in esecuzione e lancia la run all'ora configurata (sezione
  `schedule` della config);
- `autofix status`: spesa del mese, finding tracciati, MR aperte, ultime run, stato dei token
  GitLab all'ultimo controllo;
- `autofix tokens`: ricontrolla subito i token GitLab (utente, scope, scadenza) e salva lo stato;
- `autofix repos ...`: autodiscovery e approvazione dei repo (vedi
  [architecture.md](architecture.md#autodiscovery-dei-repo));
- `autofix web`: dashboard (`--dev` per lo sviluppo, `--export-openapi PATH` per il contratto).

Opzioni globali: `--config`, `--as` (utente di cui usare il tema a schermo), `--theme`,
`-v`. Senza token GitLab o chiave Anthropic il codice d'uscita è 2, con un messaggio che dice
cosa manca (mai il valore). `schedule` sopravvive a una run fallita: logga l'errore e aspetta la
finestra successiva, ricostruendo la pipeline a ogni notte.

## Contratto dell'API

Il contratto della dashboard è [`web/openapi.json`](../web/openapi.json): un test Python
fallisce se il codice diverge, e un test vitest confronta gli schemi Zod di
`frontend/src/lib/api/schemas.ts` con lo stesso file. Dopo una modifica all'API:

```bash
uv run autofix web --export-openapi web/openapi.json
# poi allinea frontend/src/lib/api/schemas.ts
```

## Frontend

Sviluppo, con il backend su `:8080` e il proxy di Vite per `/api` e `/auth`:

```bash
uv run python scripts/seed-demo-db.py --out /tmp/autofix-demo --user alex   # o --user boss
uv run autofix --config /tmp/autofix-demo/config.yaml web --dev --port 8080
cd frontend && npm ci && npm run dev
```

`scripts/seed-demo-db.py` crea un db e una config di esempio: 30 giorni di spesa, run con esiti
diversi, repo approvati e proposte dell'autodiscovery (una sospetta). `--user alex` crea un
utente con tema assegnato, `--user boss` uno senza. Per sviluppare senza login:
`web.dev_user` in config e `autofix web --dev` (solo su loopback).

Controlli:

```bash
npm run build      # build + controllo che il bundle non contenga il tema alternativo
npm run check      # svelte-check
npm run lint       # prettier + eslint
npm test           # vitest: client API e contratto, lessico, filtri, formattazione, grafico
npm run test:e2e   # Playwright su due istanze demo (utente con tema e senza), richiede la build
SCREENSHOTS=1 npm run test:e2e -- --project 'shots-*'   # rigenera docs/screenshots/
```

In questo ambiente Chromium è in `/opt/pw-browsers`: non serve `playwright install`.

I progetti Playwright `operator` e `neutral` eseguono ciascuno i test comuni
(`common.spec.ts`) più quelli del proprio utente (`operator.spec.ts`, `neutral.spec.ts`):
nessun test viene saltato. Gli screenshot (`screenshots.shot.ts`) sono progetti a parte,
definiti solo con `SCREENSHOTS=1`.

Regole del frontend: etichette solo da `src/lib/lexicon/neutral.json` via `t()`; mai stringhe,
font o colori del tema alternativo nel bundle (`npm run build` lo controlla con
[`web/theme-terms.json`](../web/theme-terms.json)); niente `style="..."` statici né script
inline nuovi, perché la CSP non ha `'unsafe-inline'` (gli stili dinamici con `style:` passano
dal CSSOM).

## Screenshot

Screenshot dei due temi in [`screenshots/`](screenshots/): dashboard, finding, run, task,
repository e impostazioni, desktop e mobile (per esempio `neutral-dashboard-desktop.png` e
`operator-repos-mobile.png`).

## Strumenti del sandbox

- `scripts/lock-sandbox-tools.sh`: rigenera `sandbox/tools-requirements.txt` con gli hash
  (installato nell'immagine con `--require-hashes`).
- `scripts/pin-digests.sh`: risolve i digest delle immagini base e li scrive nei Dockerfile e
  nel compose; `--check` esce con errore se mancano. Va lanciato dove c'è accesso ai registry.
- `scripts/rebuild-sandbox.sh`: ricostruzione settimanale dell'immagine dei sandbox.
