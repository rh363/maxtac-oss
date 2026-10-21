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
| 5b | SPA della dashboard (SvelteKit) dai mockup approvati, tema per utente caricato a runtime | fatta |
| 6a | Autodiscovery dei repo con approvazione da CLI, utenti per email, GitLab interno con CA privata | fatta |

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

## Sicurezza

Ipotesi di partenza: il contenuto dei repo (codice, commenti, nomi di file, lockfile, output
dei test) è input non fidato e può contenere prompt injection. Lo stesso vale per tutto ciò
che produce il modello che lo ha letto.

| Rischio | Contromisura |
| --- | --- |
| Esfiltrazione di chiave API o token GitLab | Solo nell'orchestrator (Docker secret); mai nel sandbox, in argv, nell'URL del remoto o nei log |
| Code execution nell'orchestrator via git | Git dir separata e non montata, `.git` (file o directory) nella working tree eliminato prima di ogni comando, hooks/fsmonitor/filtri/protocolli non https disattivati, config globale ignorata |
| Quick action GitLab (`/merge`, `/approve`) e menzioni nella MR | Campi non fidati su una riga con `\|` e backtick neutralizzati; motivazioni, riassunto e output dei test in blocchi di codice; nessuna riga della descrizione può iniziare con `/`; `@` neutralizzato |
| Agente che bara sui test | Per CVE e SAST nessun file di test toccabile (nemmeno aggiunto); config di CI, test runner e scanner protetta ovunque nel repo; `pyproject.toml`/`package.json` ammessi per le CVE solo se non cambiano le sezioni di test e scanner; symlink e submodule sempre a un umano |
| Test di regressione finti (bug) | Il test nuovo deve fallire sul codice base; la suite senza i test nuovi deve passare sul fix; euristica su `os._exit`, `sys.exit`, `TestMain`, `pytest.exit` & co. |
| Soppressioni del finding | semgrep `--disable-nosem`, bandit `--ignore-nosec`, gosec `-nosec`, osv-scanner con config vuota esplicita; i file di config degli scanner sono protetti |
| Scanner o tool finti piazzati dal codice del repo | Rescan in un sandbox nuovo dove non girano né setup né test, sulla fotografia git del fix; scanner e utility per path assoluto; `PATH` con le directory di sistema prima di quelle scrivibili |
| File ignorati che truccano la verifica (`.venv/bin/pytest`, `node_modules/.bin`, `.pyc`) | `git clean -ffdx` dopo l'agente; la working tree viene riportata alla fotografia del fix prima di ogni passo |
| Contenuto non verificato nella MR | Snapshot come tree git (binari, symlink, file grandi inclusi): test, rescan e controlli dei bug lavorano su quella fotografia e si verifica che la working tree torni identica |
| Sandbox privilegiato | Non root, `cap_drop: ALL`, `no-new-privileges`, rootfs in sola lettura, limiti CPU/RAM/PID, rete `internal` |
| Sandbox bloccato (processo in background che tiene aperto stdout) | Watchdog: oltre timeout + margine il container viene ucciso |
| Egress dal sandbox | Squid con allowlist dei soli registry (PyPI, proxy Go senza `direct`, npm), solo CONNECT su 443; ruleset semgrep e database OSV sono nell'immagine |
| Spesa fuori controllo | Tetti per notte, task e hunting; tetto della notte ridotto ai crediti del mese rimasti e run non avviata a crediti esauriti; spesa delle risposte strutturate inutilizzabili addebitata comunque |
| Disco pieno | Working tree e git dir eliminate a fine repo (anche in dry-run: i diff stanno nel report) |
| Supply chain | Scanner Python installati con `--require-hashes` (`scripts/lock-sandbox-tools.sh`), digest delle immagini con `scripts/pin-digests.sh`, `go install` coperto da sumdb |
| Merge automatico | Mai: ogni MR passa da review umana |

Rischi residui, accettati e da rivalutare:

- **Pubblicazione su registry.** Squid su HTTPS vede solo l'host. Un agente compromesso con
  credenziali *proprie* potrebbe pubblicare su PyPI o npm e così esfiltrare codice. La
  mitigazione è un mirror in sola lettura (devpi, verdaccio, Athens per Go) con l'allowlist
  ridotta ai soli mirror.
- **Kernel condiviso.** Il sandbox gira con lo stesso uid dei file dell'orchestrator: un escape
  dal kernel darebbe accesso al db. Raccomandato: `userns-remap` nel daemon Docker oppure il
  runtime gVisor (`runsc`), su una VM dedicata solo ad Autofix.
- L'euristica sui test di regressione è aggirabile da un attaccante determinato: per questo
  ogni MR di bug resta da rivedere con particolare attenzione al test aggiunto.

## Provarlo

```bash
uv sync
uv run pytest
uv run ruff check src tests && uv run mypy src

cp config.example.yaml config.yaml   # adatta workdir e db_path per l'uso locale
uv run maxtac --config config.yaml status
GITLAB_TOKEN=... uv run maxtac --config config.yaml run --repo team/api --scan-only
ANTHROPIC_API_KEY=... GITLAB_TOKEN=... uv run maxtac --config config.yaml run --repo team/api --dry-run
```

Il test d'integrazione con un Docker reale è skippato di default:
`AUTOFIX_DOCKER_TESTS=1 uv run pytest -m docker`.

Comandi:

- `maxtac run [--repo X] [--dry-run]`: esegue subito; in dry-run niente push né MR, diff su disco;
- `maxtac run --scan-only`: solo checkout e scan (tutti gli scanner, zero token): stampa i
  finding normalizzati e li scrive in `workdir/<run_id>/findings.json`. Non tocca lo store;
- `maxtac patrol`: resta in esecuzione e lancia la run all'ora configurata (`schedule`);
- `maxtac status`: spesa del mese, finding tracciati, MR aperte, ultime run;
- `maxtac repos ...`: autodiscovery e approvazione dei repo (vedi sotto).

Senza token GitLab o chiave Anthropic il codice d'uscita è 2, con un messaggio che dice cosa
manca (mai il valore). `patrol` sopravvive a una run fallita: logga l'errore e aspetta la
finestra successiva, ricostruendo la pipeline a ogni notte.

## Autodiscovery dei repo

Invece di scrivere a mano `languages`, `setup_command` e `test_command` di ogni repo, si
possono far proporre:

```bash
maxtac repos discover --all                 # tutti i progetti del bot non ancora noti
maxtac repos discover --project team/api    # uno (ripetibile); ridiscovery di un approvato
maxtac repos discover --project team/api --no-llm   # solo rilevamento deterministico, 0 token
maxtac repos list                            # config, approvati e proposte in attesa
maxtac repos show team/api                   # proposta completa, baseline, differenze
maxtac repos approve team/api [--edit] [--force]
maxtac repos reject team/api
maxtac repos remove team/api                 # solo repo approvati, non quelli del config
```

Per ogni progetto: checkout blindato come nella run notturna, rilevamento deterministico dei
file noti (`pyproject.toml`, `requirements*.txt`, `go.mod`, `package.json` e lockfile,
`Makefile`, `tox.ini`, `noxfile.py`; `.gitlab-ci.yml` solo come indizio), poi un loop agentico
breve (`models.discovery`, default Haiku; tetto `budget.discovery_per_repo_usd`, default
$0,15; massimo `budget.discovery_max_iterations` passi) con i tool `list_files`, `read_file` e
`run`, senza `write_file`. Il modello chiude con `submit_config`; se non lo fa, finisce il
budget o la risposta non è valida, vale il rilevamento deterministico. Infine la **baseline**:
working tree riportata al commit base e, in un sandbox nuovo, `setup_command` e `test_command`
sul codice base. Durata, esito e coda dell'output finiscono nella proposta.

**I comandi proposti sono input non fidato** (vengono dal contenuto del repo e da un modello
che l'ha letto). Restano una proposta `pending` nella tabella `repo_proposals` finché un
umano non li approva dalla CLI dell'orchestrator; la dashboard li mostra solo in lettura.
`approve` rifiuta senza `--force` se la baseline non è verde o se i comandi sono sospetti:
banali (`true`, `exit 0`, `echo`), senza un test runner noto, che ignorano i fallimenti
(`|| true`), che usano la rete (`curl`, `wget`, `ssh`...), che pubblicano o fanno push, che
scrivono fuori da `/work` o chiedono privilegi. Con `--edit` i comandi si correggono in
`$EDITOR` e vengono ricontrollati (la baseline si riferisce a quelli originali). In ogni caso
i comandi girano solo nel sandbox, senza segreti e con la sola rete dei registry.

La run notturna usa i repo del `config.yaml` **più** quelli approvati; in caso di conflitto
vince il `config.yaml`, che resta la fonte di fiducia scritta a mano (e `repos:` può essere
vuoto). Una nuova discovery di un repo approvato crea una proposta nuova senza toccare
l'approvato e ne mostra le differenze; la proposta pending precedente diventa `superseded`.

## Temi di presentazione

L'output per l'operatore (CLI, report a schermo, dashboard) può usare un tema alternativo,
scelto per utente in `ui.themes`; il default è `neutral`. Il tema cambia solo le parole a
schermo: branch, label, commit, testo delle MR e report su disco restano sempre neutri.

Nella dashboard chi non ha un tema assegnato riceve `theme: "default"` e il bundle base contiene
solo il tema di default: gli asset di un tema alternativo li serve l'API, e solo a chi ce l'ha
assegnato (per gli altri rispondono 404, come un tema inesistente). Il tema alternativo è
attenuato: le etichette funzionali (finding, run, esiti) restano quelle chiare del tema di
default, il tema cambia colori e font e aggiunge solo marchio, sottotitoli secondari e qualche
dettaglio. `npm run build` fallisce se nel bundle compare uno dei termini di
[`web/theme-terms.json`](web/theme-terms.json).

## Dashboard

`maxtac web` (servizio `web` del compose, profilo `web`) serve la SPA della dashboard
(`frontend/`, SvelteKit) e un'API in sola lettura sullo stesso origin. Il contratto è
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

**Utenti per email.** Con `web.user_claim: email` (default) l'utente è l'email dell'id_token,
accettata solo con `email_verified: true` (GitLab la mette per le email confermate):
un'email non verificata la sceglie l'utente stesso e non identifica nessuno. `allowed_users` e
`ui.themes` si scrivono per email e il confronto ignora maiuscole e minuscole. Lo scope `email`
viene aggiunto da solo se manca. Con `user_claim: username` vale il primo claim di
`web.oidc.username_claims`.

**GitLab come IdP.** L'issuer OIDC è l'URL di GitLab (`web.oidc.issuer` uguale a
`gitlab.url`). Su GitLab: *Admin → Applications* (o *Settings → Applications* di un gruppo),
*Confidential* attivo, scope `openid`, `profile` ed `email`, redirect URI
`https://<host della dashboard>/auth/callback`. L'Application ID va in `web.oidc.client_id`,
il secret in `secrets/oidc_client_secret`; la chiave delle sessioni è una stringa casuale di
almeno 32 caratteri:

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
sempre attivi: CSP stretta (`'self'`, niente `'unsafe-inline'`), `X-Frame-Options: DENY`, `nosniff`,
`Referrer-Policy: no-referrer`, `Cache-Control: no-store` sull'API. Niente `/docs` né
`/openapi.json` pubblici. Path dell'host e link che non puntano a GitLab vengono tolti dalle
risposte; diff e output dei test sono testo semplice, da mostrare escaped.

Per sviluppare: `web.dev_user` in config e `maxtac web --dev` (solo su loopback, nessun login).

### GitLab self-hosted su rete interna

Orchestrator e dashboard parlano con GitLab dalla rete della VM; i sandbox **no**: la loro
unica uscita è il proxy, la cui allowlist contiene solo i registry dei pacchetti (un test
fallisce se cambia o se include l'host di GitLab). Se il certificato di GitLab è firmato da
una CA interna, metti il bundle PEM in `ca/gitlab-ca.pem`, decommenta il mount nel compose
(orchestrator e web) e imposta `gitlab.ca_bundle: /etc/autofix/gitlab-ca.pem`. Il bundle vale
per le API (python-gitlab), per git (`http.<url di GitLab>.sslCAInfo`, passato in ambiente
come il token) e per il login OIDC, ma solo se l'issuer è GitLab stesso: con un IdP pubblico
sostituirebbe le CA di sistema. Il sandbox non lo riceve.

### Frontend (`frontend/`)

SvelteKit in modalità SPA (`adapter-static`, `ssr = false`), Svelte 5, TypeScript strict,
Tailwind, icone `@lucide/svelte`, risposte dell'API validate con Zod (gli schemi in
`src/lib/api/schemas.ts` sono confrontati con `web/openapi.json` da un test). Le pagine stanno
in `src/lib/svelte/page/<feature>/`, le rotte in `src/routes/` sono solo entry point.

| Schermata | Rotta |
| --- | --- |
| Dashboard: spesa del mese e della notte, MR, finding per stato, rotazione del bug hunting, ultime run | `/` |
| Finding con filtri tipo, severità, stato e repo nell'URL, paginazione | `/findings` |
| Storico delle run | `/runs` |
| Dettaglio run: statistiche, timeline per repo (scan, triage, fix, verifica, MR), task con esito e costo | `/runs/{id}` |
| Dettaglio task: finding, motivo del triage, cosa cambia, verifica, diff, output dei test, costo, link alla MR | `/runs/{id}/tasks/{fp}?repo=` |

Etichette e temi: le etichette neutre stanno in `src/lib/lexicon/neutral.json`; dopo
`/api/me`, se l'utente ha un tema, la SPA carica `/api/theme/<nome>/theme.css` e
`lexicon.json` (le cui chiavi `ui` sovrascrivono solo etichette esistenti). Il tema si aggancia
con `data-theme` su `<html>` e ridefinisce le variabili CSS; i suoi font sono serviti dallo stesso
endpoint protetto.

Sviluppo, con il backend su `:8080` e il proxy di Vite per `/api` e `/auth`:

```bash
uv run python scripts/seed-demo-db.py --out /tmp/autofix-demo --user alex   # o --user boss
uv run maxtac --config /tmp/autofix-demo/config.yaml web --dev --port 8080
cd frontend && npm ci && npm run dev
```

Controlli:

```bash
npm run build      # build + controllo che il bundle non contenga il tema alternativo
npm run check      # svelte-check
npm run lint       # prettier + eslint
npm test           # vitest: client API e contratto, lessico, filtri, formattazione
npm run test:e2e   # Playwright su due istanze demo (utente con tema e senza), richiede la build
SCREENSHOTS=1 npm run test:e2e -- screenshots   # rigenera docs/screenshots/
```

Screenshot dei due temi in [`docs/screenshots/`](docs/screenshots/) (per esempio
`neutral-dashboard-desktop.png` e `operator-dashboard-desktop.png`).

**Serving e CSP.** FastAPI serve la build (`web.static_dir`, default `frontend/build` accanto
al sorgente): asset in `_app/immutable/` con cache immutabile, `index.html` senza cache e come
fallback per le rotte della SPA, 404 per un asset mancante. Lo script di avvio inline di
SvelteKit è autorizzato con il suo hash, gli attributi `style` statici dei template con
`'unsafe-hashes'` e i loro hash: niente `'unsafe-inline'`. L'immagine `Dockerfile.web` costruisce
la SPA con Node e poi copia solo la build nell'immagine Python.

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

Prima della prima run vera:

- `./scripts/pin-digests.sh` sulla VM e commit dei digest; `./scripts/pin-digests.sh --check`
  deve uscire con 0;
- build dell'immagine sandbox: verificare che i ruleset semgrep in config siano tutti in
  `SEMGREP_RULESETS` (sandbox/Dockerfile) e che `/opt/osv-db` contenga i database;
- `workdir` su un filesystem dedicato e limitato (es. volume LVM o file system loop da
  20-50 GB montato su `/var/lib/autofix/work`), separato da quello del db SQLite.

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
