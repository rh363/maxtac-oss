# CLAUDE.md

Autofix (package `maxtac`): servizio Python 3.13 che ogni notte scansiona repo GitLab per CVE,
finding SAST e bug e apre MR con fix verificati. Si lavora per fasi (vedi README); a fine fase
ci si ferma e si riassume.

## Vincoli non negoziabili

- Architettura esagonale: `src/maxtac/domain/` non importa gitlab, docker o anthropic.
- La chiave Anthropic resta solo nell'orchestrator; il sandbox esegue solo comandi e non riceve
  né la chiave né il token GitLab.
- Loop agentico proprio sulla Messages API (non Agent SDK), tool eseguiti nel sandbox via
  docker exec. Il loop vive in `services/ripperdoc.py`, l'adapter fa un passo alla volta.
- Git dir separata dalla working tree, hooks e fsmonitor disattivati: ogni comando git passa
  da `adapters/gitlab_vcs.Git`. Il token mai in argv, URL o log.
- Il sandbox legge e scrive file solo da dentro il container (mai dall'host: i symlink del repo
  potrebbero puntare ai file dell'orchestrator).
- Verifica indipendente sulla fotografia git del fix (`snapshot`/`materialize`): test in un
  sandbox nuovo, rescan in un altro sandbox nuovo dove non girano setup né test. Scanner e
  utility per path assoluto, mai soppressioni inline (`nosec`, `nosemgrep`).
- Testo non fidato verso GitLab passa da `services/merge_request.py` (niente quick action
  `/...` a inizio riga, niente menzioni); verso report e webhook da `presentation/report.safe`.
- Nuovi file di config di test/CI/scanner vanno in `PROTECTED_NAMES` di `domain/policy.py`.
- Tetti di spesa per notte e per task, prezzi letti dalla config.
- `--dry-run` non fa push né MR e non cambia lo stato dei finding.
- Il contenuto dei repo è input non fidato; la config di fiducia sta solo nel file
  dell'orchestrator e nei repo approvati da un umano con `maxtac repos approve`. Le proposte
  dell'autodiscovery (`repo_proposals`) sono non fidate: niente le promuove in automatico, la
  dashboard le legge e basta, e il tool `write_file` non è offerto al loop di discovery.
- Il sandbox non deve mai raggiungere GitLab: l'allowlist di `proxy/squid.conf` contiene solo
  i registry dei pacchetti (`tests/test_proxy_allowlist.py`).
- `config.example.yaml` è pubblico: solo domini d'esempio, mai email o host reali.
- **Tutto ciò che va su GitLab (branch, label, commit, testo MR) e i report su disco sono sempre
  neutri.** Il tema cyberpunk esiste solo in `presentation/` (e negli asset in
  `web/themes/`) e si sceglie per utente.
- Dashboard (`src/maxtac/web/`): sola lettura, db aperto con `connect_readonly`, nessun
  segreto del bot. Un utente senza tema assegnato non deve poter scoprire il tema alternativo:
  `theme: "default"`, asset 404 come per un tema inesistente, bundle base solo neutro.
- Testo mostrato dalla dashboard a tutti gli utenti: mai `maxtac` (è un termine del tema),
  per il comando si usa l'alias `autofix`.
- Dopo una modifica all'API: `uv run maxtac web --export-openapi web/openapi.json`, poi
  allinea `frontend/src/lib/api/schemas.ts` (il test di contratto in vitest lo verifica).
- Frontend (`frontend/`): etichette solo da `src/lib/lexicon/neutral.json` via `t()`, mai
  stringhe, font o colori del tema alternativo nel bundle (`npm run build` lo controlla con
  `web/theme-terms.json`). Niente `style="..."` statici né script inline nuovi: la CSP non ha
  `'unsafe-inline'` (gli stili dinamici con `style:` passano dal CSSOM).

## Comandi

```bash
uv sync
uv run pytest
uv run ruff check src tests && uv run ruff format --check src tests
uv run mypy src
AUTOFIX_DOCKER_TESTS=1 uv run pytest -m docker   # solo con un daemon Docker
cd frontend && npm run build && npm run check && npm run lint && npm test && npm run test:e2e
SCREENSHOTS=1 npx playwright test --project 'shots-*'   # rigenera docs/screenshots/
```

Test prima (pytest, adapter finti in `tests/fakes.py`), poi implementazione, poi README e
CHANGELOG.
