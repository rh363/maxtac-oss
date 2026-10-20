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
| 3 | Finding SAST: fix, falsi positivi ignorati, nessun finding nuovo introdotto | fatta |
| 4 | Bug hunting a rotazione, test di regressione che fallisce sul base, storico run, notifica | fatta |
| 5a | API della dashboard in sola lettura, login OIDC, temi per utente | fatta |
| 5b | SPA della dashboard (SvelteKit), dopo la validazione dei mockup | da fare |

Tutte le fasi sono verificate in locale (git reale, bandit reale, GitLab e modello finti). Cosa
resta da verificare solo sulla VM vera è in [Go-live](#go-live).

## Come funziona una notte

Per ogni repo, in sequenza (un repo che fallisce non blocca gli altri):

1. checkout con il token del bot, git dir separata dalla working tree;
2. scan nel sandbox, senza token;
3. dedup contro lo storico del repo (lo stesso finding in due repo sono due finding): si
   scartano finding ignorati, già con MR aperta, già passati a un umano o falliti troppe volte.
   Una MR chiusa senza merge conta come rifiuto. Il fingerprint non contiene la riga: un
   finding SAST resta lo stesso quando il codice si sposta;
4. le CVE dello stesso package diventano un solo task (un solo bump);
5. triage (Haiku): una chiamata per repo, risposta JSON vincolata da schema: `fix`, `ignore`, `needs_human`.
   Un task senza verdetto valido va a un umano;
6. fix agent (Sonnet): loop agentico proprio sulla Messages API, tool eseguiti solo nel sandbox;
7. verifica indipendente in un sandbox nuovo: setup, test, rescan del solo scanner d'origine.
   Fanno fallire il task: diff vuoto, test rossi, finding ancora presente, oppure un finding
   **nuovo** dello stesso scanner di severità almeno media (per SAST nei file toccati, per le CVE
   ovunque: un bump verso una versione a sua volta vulnerabile). Un diff che tocca test
   esistenti o la CI va a un umano;
8. push e MR con label `autofix`, branch `autofix/<kind>/<fingerprint>`;
9. bug hunting (Opus) solo sui repo scelti a rotazione (vedi sotto);
10. report su `workdir/<run_id>/report.md`, storico nel db (tabella `runs`, JSON completo con
    esiti, costi e diff troncati: la base per la dashboard), notifica opzionale del mattino.

### Bug hunting

- **Rotazione.** Ogni notte `hunting.repos_per_night` repo: prima i mai cacciati, poi quelli
  cacciati meno di recente; a parità (stessa notte) chi è stato cacciato meno volte.
- **Input.** Diff degli ultimi `hunting.lookback_days` giorni più i file toccati ancora
  esistenti. Si tengono solo i bug a confidenza `high`.
- **Dedup stabile.** Il modello indica il simbolo (funzione, metodo o classe): il fingerprint è
  file + simbolo, non il titolo, che cambia da una notte all'altra. Due bug nella stessa
  funzione diventano un solo task: una MR per funzione alla volta.
- **Test di regressione obbligatorio.** Il fix deve aggiungere un file di test nuovo, e quel
  test deve **fallire sul codice base**: l'orchestrator fotografa i file del fix, riporta la
  working tree al base, rimette solo i test nuovi, esegue `test_command` in un sandbox nuovo
  (deve uscire con errore), poi ripristina il fix e controlla che il diff sia identico. Il
  controllo usa l'intero `test_command`, quindi vale per qualunque linguaggio; il limite è che
  un test già rosso sul base lo farebbe passare comunque, ma la verifica precedente richiede la
  suite verde con il fix.

### Notifica del mattino

`notify.webhook: true` invia il riepilogo della notte con una POST JSON a un webhook generico
(`text` è già nel formato degli incoming webhook di Slack e Mattermost). L'URL è un segreto
(`secrets/notify_webhook_url`) e non compare mai negli errori. Il testo è sempre neutro. Un
errore della notifica o del salvataggio dello storico non fa perdere il report.

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
- `maxtac status`: spesa del mese, finding tracciati, MR aperte, ultime run.

Senza token GitLab o chiave Anthropic il codice d'uscita è 2, con un messaggio che dice cosa
manca (mai il valore). `patrol` sopravvive a una run fallita: logga l'errore e aspetta la
finestra successiva, ricostruendo la pipeline a ogni notte.

## Temi di presentazione

L'output per l'operatore (CLI, report a schermo, dashboard) può usare un tema alternativo,
scelto per utente in `ui.themes`; il default è `neutral`. Il tema cambia solo le parole a
schermo: branch, label, commit, testo delle MR e report su disco restano sempre neutri.

Nella dashboard chi non ha un tema assegnato riceve `theme: "default"` e il bundle base contiene
solo il tema di default: gli asset di un tema alternativo li serve l'API, e solo a chi ce l'ha
assegnato (per gli altri rispondono 404, come un tema inesistente).

## Dashboard

`maxtac web` (servizio `web` del compose, profilo `web`) espone un'API in sola lettura per la
dashboard; la SPA arriverà dopo la validazione dei mockup. Il contratto è
[`web/openapi.json`](web/openapi.json): un test fallisce se il codice diverge
(rigenera con `maxtac web --export-openapi web/openapi.json`).

| Endpoint | Contenuto |
| --- | --- |
| `GET /api/me` | utente e tema risolto |
| `GET /api/dashboard` | spesa del mese vs crediti e proiezione, ultima notte vs tetto, MR aperte, finding per stato, rotazione del bug hunting, ultime run |
| `GET /api/findings` | filtri `kind`, `severity`, `status`, `repo`; `limit` (max 200) e `offset` |
| `GET /api/runs`, `GET /api/runs/{id}` | storico e report completo di una notte |
| `GET /api/runs/{id}/tasks/{fingerprint}` | finding, motivo del triage, diff, output dei test, costo, link alla MR (`?repo=` se serve) |
| `GET /api/theme/{name}/lexicon.json`, `.../theme.css` | pacchetto del tema, solo per chi ce l'ha assegnato |
| `/auth/login`, `/auth/callback`, `POST /auth/logout` | login OIDC |

**Login.** OIDC Authorization Code + PKCE lato server, con `state` e `nonce`, id_token
validato su firma (JWKS in cache, ricaricata su `kid` sconosciuto al massimo una volta al
minuto), `iss`, `aud`/`azp`, `exp`. Sessione in cookie firmato `HttpOnly`, `Secure`,
`SameSite=Lax`. Accesso solo agli utenti di `web.allowed_users`, ricontrollato a ogni
richiesta. Rate limit sul login per client.

Su GitLab: *Admin → Applications* (o le Applications di un gruppo), confidential, scope
`openid` e `profile`, redirect URI `https://<host della dashboard>/auth/callback`. L'Application
ID va in `web.oidc.client_id`, il secret in `secrets/oidc_client_secret`; la chiave delle
sessioni è una stringa casuale di almeno 32 caratteri:

```bash
printf '%s' "$GITLAB_APP_SECRET" > secrets/oidc_client_secret
python3 -c 'import secrets; print(secrets.token_urlsafe(48), end="")' > secrets/web_session_secret
docker compose --profile web up -d web
```

**Isolamento.** Il container `web` non ha il socket Docker né i segreti del bot e della chiave
Anthropic; monta `/var/lib/autofix` in sola lettura e apre il db con `mode=ro` e
`query_only`. Per questo il db usa il journal `DELETE` e non WAL (un lettore WAL deve scrivere
il file `-shm`). La porta è pubblicata solo su `127.0.0.1:8080`: davanti va un reverse proxy
con TLS (Caddy, nginx), per esempio con Caddy:

```
autofix.example.it {
    reverse_proxy 127.0.0.1:8080
}
```

Se il proxy passa `X-Forwarded-For`, elenca il suo indirizzo o la sua rete in
`web.trusted_proxies`, altrimenti il rate limit vede un solo client. Header di sicurezza
sempre attivi: CSP stretta (`'self'`, niente inline), `X-Frame-Options: DENY`, `nosniff`,
`Referrer-Policy: no-referrer`, `Cache-Control: no-store` sull'API. Niente `/docs` né
`/openapi.json` pubblici. Path dell'host e link che non puntano a GitLab vengono tolti dalle
risposte; diff e output dei test sono testo semplice, da mostrare escaped.

Per sviluppare: `web.dev_user` in config e `maxtac web --dev` (solo su loopback, nessun login).

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

## Go-live

Verificato in locale: pipeline completa con git reale e remoto bare, bandit reale, una
settimana di notti simulate (tetti, rotazione, nessuna MR doppia, merge a metà settimana).
Verificabile solo sulla VM:

- build delle immagini e allowlist reale di squid (scanner e package manager dietro proxy);
- `DockerSandbox` con un daemon vero (`put_archive` su rootfs in sola lettura, limiti, rete
  `internal`): `AUTOFIX_DOCKER_TESTS=1 uv run pytest -m docker`;
- API GitLab della propria istanza (versione, permessi del bot, label);
- chiamate vere alla Claude API: cache hit, fallback sui rifiuti, messaggio a crediti finiti.

Checklist, una fase alla volta (ognuna si attiva solo dopo una notte pulita in dry-run):

1. `run --scan-only` su tutti i repo: i finding normalizzati hanno senso, niente errori.
2. **CVE** (`features.cve: true`, default): una notte `run --dry-run`, lettura di report e
   diff; poi la prima run vera su un repo di prova con una dipendenza vulnerabile apposta.
3. **SAST** (`features.sast: true`): una notte in dry-run; controllare che i falsi positivi
   noti finiscano in `ignored` e che i fix non tocchino i test.
4. **Bug hunting** (`features.hunting: true`): una notte in dry-run con
   `hunting.repos_per_night: 1`, poi 2. Controllare in `status` spesa e proiezione del mese.
5. Dopo una settimana: tarare i tetti (`budget.*`) sulla spesa vera e, se serve, attivare la
   notifica del mattino.

### Git e checkout

La git dir sta in `workdir/<run>/<repo>/gitdir`, fuori dalla working tree montata nel sandbox, e
il file `.git` viene rimosso. Ogni comando git passa `--git-dir`/`--work-tree` espliciti, ignora
la config globale e di sistema, disattiva hooks, fsmonitor, helper delle credenziali, submodule
e ogni protocollo diverso da https. Il token del bot non entra mai in argv, URL o log: viaggia
come header HTTP in variabili `GIT_CONFIG_*` limitate all'URL di GitLab, e gli errori vengono
ripuliti. Spazzatura di setup e test (`__pycache__`, `.venv`, `node_modules`...) non finisce
mai nelle MR.
