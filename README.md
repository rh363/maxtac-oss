# Autofix

Servizio self-hosted che ogni notte cerca CVE nelle dipendenze, finding SAST e bug nei repo
GitLab configurati, e apre Merge Request con il fix già verificato. Ogni MR passa da review
umana: non c'è mai auto-merge.

Gli scanner deterministici (osv-scanner, semgrep, bandit, gosec) trovano i problemi a costo
zero; il modello serve solo per triage, fix e revisione del codice recente, entro tetti di
spesa espliciti.

| Fase | Contenuto | Stato |
| --- | --- | --- |
| 0 | Dominio, porte, policy, config, store SQLite, adapter finti, CLI | fatta |
| 1 | Immagine sandbox, `DockerSandbox`, parser degli scanner, proxy, checkout con git hardening, `GitLabVCS` | fatta |
| 2 | CVE end-to-end: triage, fix agent, verifica, MR (`AnthropicLLM`) | fatta |
| 3 | Finding SAST | da fare |
| 4 | Bug hunting a rotazione sul diff recente | da fare |

## Come funziona una notte

Per ogni repo, in sequenza (un repo che fallisce non blocca gli altri):

1. checkout con il token del bot, git dir separata dalla working tree;
2. scan nel sandbox, senza token;
3. dedup contro lo storico: si scartano finding ignorati, già con MR aperta, già passati a un
   umano o falliti troppe volte. Una MR chiusa senza merge conta come rifiuto;
4. le CVE dello stesso package diventano un solo task (un solo bump);
5. triage (Haiku): una chiamata per repo, risposta JSON vincolata da schema: `fix`, `ignore`, `needs_human`.
   Un task senza verdetto valido va a un umano;
6. fix agent (Sonnet): loop agentico proprio sulla Messages API, tool eseguiti solo nel sandbox;
7. verifica indipendente in un sandbox nuovo: setup, test, rescan dello scanner d'origine.
   Diff vuoto, test rossi o finding ancora presente fanno fallire il task. Un diff che tocca
   test esistenti o la CI va a un umano; per i bug serve un test di regressione nuovo;
8. push e MR con label `autofix`, branch `autofix/<kind>/<fingerprint>`;
9. bug hunting (Opus) solo sui repo scelti a rotazione;
10. report su `workdir/<run_id>/report.md`.

## Architettura

Esagonale: `domain/` non importa GitLab, Docker o Anthropic. I test della pipeline girano con
adapter finti, senza rete.

```
src/maxtac/
├── domain/        models, ports (Protocol), policy (regole pure), budget (prezzi e tetti)
├── services/      pipeline, triage, fix agent, bug hunting, testo delle MR
├── adapters/      sqlite_store, gitlab_vcs, docker_sandbox, scanners, anthropic_llm
├── presentation/  lessici e report per l'operatore
├── config.py      YAML + Docker secret
├── container.py   composition root
└── cli.py         run / patrol / status
```

| Porta | Responsabilità |
| --- | --- |
| `VCSPort` | checkout, branch, diff, push, MR, ricerca di MR aperte |
| `SandboxPort` / `Sandbox` | container effimero, `exec` con timeout, lettura e scrittura file |
| `ScannerPort` | esegue uno scanner nel sandbox e normalizza in `Finding` |
| `LLMPort` | chiamata strutturata e singolo passo del loop agentico |
| `FindingStore` | stato dei finding, tentativi, MR, rotazione del hunting |
| `BudgetPort` | spesa per run e per scope |

Il fingerprint di un finding esclude il numero di riga: un finding SAST resta lo stesso anche
quando il codice sopra si sposta.

## Budget

Prezzi e tetti stanno in config, non nel codice: il costo di ogni chiamata si calcola dai campi
`usage`. Tetti: per notte, per task, per il triage di un repo, per il bug hunting, MR per notte,
iterazioni del loop, tentativi per finding. Il controllo avviene prima di ogni chiamata, quindi
una notte può superare il tetto al massimo del costo di una singola chiamata.
Un modello configurato senza prezzo blocca l'avvio. Se il fallback lato server risponde con un
modello che non è in config, la chiamata si conta al prezzo più alto noto (meglio sovrastimare).
`budget.monthly_credits_usd` (default 100) serve a `status`, che mostra la spesa del mese, la
proiezione a fine mese e un avviso se la proiezione supera i crediti.

Se i crediti API finiscono, o la chiave viene rifiutata, la notte si ferma subito e in modo
pulito: i task restanti non partono, nessun tentativo viene contato sui finding e il report
dice perché. La notte dopo si riparte normalmente.

### Chiamate al modello

- Loop agentico proprio sulla Messages API: l'adapter fa un passo alla volta, il loop sta in
  `services/ripperdoc.py`. I turni dell'assistente si rimandano identici (thinking compresi):
  la storia è append-only.
- Triage e bug hunting usano structured output (`output_config.format` con JSON schema), non un
  `tool_choice` forzato, che Opus 5.5 e Sonnet 5.5 rifiutano.
- Prompt caching: breakpoint dopo le definizioni dei tool e il system prompt (identici tra
  task) e sull'ultimo messaggio utente, così il loop rilegge la storia dalla cache.
- Retry con backoff dell'SDK su 429, 5xx e overloaded; `effort` per modello da config.
- Ottimizzazione futura: il triage può passare alla Batch API (-50% su input e output), visto
  che di notte la latenza non conta.

## Sicurezza in breve

- Il contenuto dei repo è input non fidato (prompt injection inclusa).
- La chiave API e il token GitLab restano nell'orchestrator; il sandbox non li riceve mai.
- Il sandbox sta su una rete interna; l'unica uscita è un proxy con allowlist dei registry.
- Git con `--git-dir`/`--work-tree` espliciti, hooks e fsmonitor disattivati.
- La config di fiducia (comandi di test e setup) sta nel file dell'orchestrator, mai nei repo.
- Verifica indipendente dall'agente, nessun auto-merge.

## Provarlo

```bash
uv sync
uv run pytest
uv run ruff check src tests && uv run mypy src

cp config.example.yaml config.yaml   # adatta workdir e db_path per l'uso locale
uv run maxtac --config config.yaml status
GITLAB_TOKEN=... uv run maxtac --config config.yaml run --repo alex/ecs2 --scan-only
ANTHROPIC_API_KEY=... GITLAB_TOKEN=... uv run maxtac --config config.yaml run --repo alex/ecs2 --dry-run
```

Il test d'integrazione con un Docker reale è skippato di default:
`AUTOFIX_DOCKER_TESTS=1 uv run pytest -m docker`.

Comandi:

- `maxtac run [--repo X] [--dry-run]`: esegue subito; in dry-run niente push né MR, diff su disco;
- `maxtac run --scan-only`: solo checkout e scan (tutti gli scanner, zero token): stampa i
  finding normalizzati e li scrive in `workdir/<run_id>/findings.json`. Non tocca lo store;
- `maxtac patrol`: resta in esecuzione e lancia la run all'ora configurata (`schedule`);
- `maxtac status`: spesa del mese, finding tracciati, MR aperte.

Senza token GitLab o chiave Anthropic il codice d'uscita è 2, con un messaggio che dice cosa
manca (mai il valore). `patrol` sopravvive a una run fallita: logga l'errore e aspetta la
finestra successiva, ricostruendo la pipeline a ogni notte.

## Temi di presentazione

L'output per l'operatore (CLI, report a schermo, in futuro la dashboard) può usare un tema
alternativo, scelto per utente in `ui.themes`; il default è `neutral`. Il tema cambia solo le
parole a schermo: branch, label, commit, testo delle MR e report su disco restano sempre neutri.

## Deploy

Su una VM dedicata (il socket Docker montato nell'orchestrator equivale a root sull'host):

```bash
sudo mkdir -p /var/lib/autofix && sudo chown 1000:1000 /var/lib/autofix
mkdir -p secrets && chmod 700 secrets
printf '%s' "$ANTHROPIC_KEY" > secrets/anthropic_api_key
printf '%s' "$GITLAB_BOT_TOKEN" > secrets/gitlab_token     # utente bot, ruolo Developer, scope api
cp config.example.yaml config.yaml                          # repo, comandi, tetti
export DOCKER_GID=$(stat -c %g /var/run/docker.sock)
docker compose --profile build build sandbox-image          # immagine dei sandbox
docker compose up -d --build                                # orchestrator + proxy
docker compose run --rm orchestrator run --scan-only        # prova a costo zero
```

### Primo avvio, passo per passo

1. **Bot GitLab.** Crea l'utente bot, aggiungilo ai progetti con ruolo Developer e genera un
   token con scope `api`. Mettilo in `secrets/gitlab_token`.
2. **Chiave Anthropic.** Dalla Console dell'organizzazione collegata ai crediti del piano, senza
   auto-reload. Mettila in `secrets/anthropic_api_key`.
3. **Config.** `config.yaml` da `config.example.yaml`: URL di GitLab, repo con `setup_command` e
   `test_command`, tetti di spesa, `ui.themes` se serve. Le feature partono con solo `cve`.
4. **Build.** Immagine dei sandbox e poi orchestrator e proxy (comandi sopra).
5. **Scan a costo zero.** `run --scan-only`: controlla che i finding normalizzati abbiano senso.
6. **Dry-run.** `run --dry-run` su un repo reale: spende crediti, ma non fa push né MR e non
   cambia lo stato dei finding. Leggi `workdir/<run_id>/report.md` e i diff in `diffs/`.
7. **Run vera.** Prima su un repo di prova con una dipendenza vulnerabile apposta:
   `run --repo gruppo/prova`. La MR deve arrivare con i test verdi.
8. **Notturno.** `docker compose up -d`: l'orchestrator resta in `patrol` e lancia la run
   all'ora di `schedule`. `status` mostra spesa del mese, proiezione e MR aperte.

| Componente | Cosa fa |
| --- | --- |
| `orchestrator` | unico con segreti; parla con GitLab, Anthropic e il daemon Docker. Non root, rootfs in sola lettura |
| `proxy` | squid con allowlist: PyPI, proxy Go, npm, OSV, registry semgrep, GitHub. Nessuna cache |
| sandbox | creati a ogni fase dall'orchestrator sulla rete `autofix_sandbox` (`internal`): uid 1000, `cap_drop: ALL`, `no-new-privileges`, rootfs in sola lettura, limiti CPU/RAM/PID, solo la working tree montata in `/work` |

L'immagine dei sandbox (Python 3.13, Go, Node LTS, osv-scanner, semgrep, bandit, gosec, versioni
pinnate in `sandbox/Dockerfile`) va ricostruita ogni settimana: `scripts/rebuild-sandbox.sh`,
da cron (l'esempio è nello script).

### Git e checkout

La git dir sta in `workdir/<run>/<repo>/gitdir`, fuori dalla working tree montata nel sandbox, e
il file `.git` viene rimosso. Ogni comando git passa `--git-dir`/`--work-tree` espliciti, ignora
la config globale e di sistema, disattiva hooks, fsmonitor, helper delle credenziali, submodule
e ogni protocollo diverso da https. Il token del bot non entra mai in argv, URL o log: viaggia
come header HTTP in variabili `GIT_CONFIG_*` limitate all'URL di GitLab, e gli errori vengono
ripuliti. Spazzatura di setup e test (`__pycache__`, `.venv`, `node_modules`...) non finisce
mai nelle MR.
