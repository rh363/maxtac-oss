# Architettura

Autofix è un servizio self-hosted che ogni notte cerca CVE nelle dipendenze, finding SAST e bug
nei repo GitLab configurati, e apre Merge Request con il fix già verificato. Ogni MR passa da
review umana: non c'è mai auto-merge.

Gli scanner deterministici (osv-scanner, semgrep, bandit, gosec) trovano i problemi a costo
zero; il modello serve solo per triage, fix e revisione del codice recente, entro tetti di
spesa espliciti.

## Stato delle fasi

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
| 6b | Pagine Repository e Impostazioni, ricerca nei finding, passi dell'agente, grafico della spesa | fatta |

Tutte le fasi sono verificate in locale (git reale, bandit reale, GitLab e modello finti). Cosa
resta da verificare solo sulla VM vera è in [go-live.md](go-live.md).

## Come funziona una notte

Per ogni repo, in sequenza (un repo che fallisce non blocca gli altri):

1. checkout con il token del bot, git dir separata dalla working tree;
2. scan nel sandbox, senza token;
3. dedup contro lo storico del repo (lo stesso finding in due repo sono due finding): si
   scartano finding ignorati, già con MR aperta, già passati a un umano o falliti troppe volte.
   Una MR chiusa senza merge conta come rifiuto. Il fingerprint non contiene la riga: un
   finding SAST resta lo stesso quando il codice si sposta;
4. le CVE dello stesso package diventano un solo task (un solo bump);
5. triage (Haiku): una chiamata per repo, risposta JSON vincolata da schema: `fix`, `ignore`,
   `needs_human`. Un task senza verdetto valido va a un umano;
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

## Struttura esagonale

`domain/` non importa GitLab, Docker o Anthropic. I test della pipeline girano con adapter
finti, senza rete. Il package Python si chiama `maxtac`; il comando installato è `autofix`
(con l'alias storico `maxtac`).

```
src/maxtac/
├── domain/        models, ports (Protocol), policy (regole pure), budget (prezzi e tetti)
├── services/      pipeline, triage, fix agent, bug hunting, discovery, testo delle MR, dashboard
├── adapters/      sqlite_store, gitlab_vcs, docker_sandbox, scanners, anthropic_llm, notifier
├── presentation/  lessici e report per l'operatore
├── web/           API e serving della dashboard (adapter driver)
├── config.py      YAML + Docker secret
├── container.py   composition root
└── cli.py         run / patrol / status / repos / web
```

| Porta | Responsabilità |
| --- | --- |
| `VCSPort` | checkout, branch, diff, push, MR, ricerca di MR aperte |
| `SandboxPort` / `Sandbox` | container effimero, `exec` con timeout, lettura e scrittura file |
| `ScannerPort` | esegue uno scanner nel sandbox e normalizza in `Finding` |
| `LLMPort` | chiamata strutturata e singolo passo del loop agentico |
| `FindingStore` | stato dei finding, tentativi, MR, rotazione del hunting |
| `BudgetPort` | spesa per run e per scope |
| `RunStore` | storico delle run con il report completo |
| `RepoRegistry` | repo approvati e proposte dell'autodiscovery |
| `NotifierPort` | riepilogo del mattino (noop o webhook) |

Il fingerprint di un finding esclude il numero di riga: un finding SAST resta lo stesso anche
quando il codice sopra si sposta.

### Componenti del deploy

| Componente | Cosa fa |
| --- | --- |
| `orchestrator` | unico con segreti; parla con GitLab, Anthropic e il daemon Docker. Non root, rootfs in sola lettura |
| `proxy` | squid con allowlist dei soli registry dei pacchetti (PyPI, proxy Go, npm). Nessuna cache |
| sandbox | creati a ogni fase dall'orchestrator sulla rete `autofix_sandbox` (`internal`): uid 1000, `cap_drop: ALL`, `no-new-privileges`, rootfs in sola lettura, limiti CPU/RAM/PID, solo la working tree montata in `/work` |
| `web` | dashboard in sola lettura (profilo `web`), senza socket Docker né segreti del bot |

L'immagine dei sandbox (Python 3.13, Go, Node LTS, osv-scanner, semgrep, bandit, gosec,
versioni pinnate in `sandbox/Dockerfile`, ruleset semgrep e database OSV inclusi) va
ricostruita ogni settimana: `scripts/rebuild-sandbox.sh`, da cron (l'esempio è nello script).

## Budget

Prezzi e tetti stanno in config, non nel codice: il costo di ogni chiamata si calcola dai campi
`usage`. Tetti: per notte, per task, per il triage di un repo, per il bug hunting, per la
discovery di un repo, MR per notte, iterazioni del loop, tentativi per finding. Il controllo
avviene prima di ogni chiamata, quindi una notte può superare il tetto al massimo del costo di
una singola chiamata. Un modello configurato senza prezzo blocca l'avvio. Se il fallback lato
server risponde con un modello che non è in config, la chiamata si conta al prezzo più alto
noto (meglio sovrastimare).

`budget.monthly_credits_usd` (default 100) serve a `status` e alla dashboard, che mostrano la
spesa del mese, la proiezione a fine mese e un avviso se la proiezione supera i crediti. A
crediti del mese esauriti la run non parte, e il tetto della notte si riduce ai crediti
rimasti.

Se i crediti API finiscono, o la chiave viene rifiutata, la notte si ferma subito e in modo
pulito: i task restanti non partono, nessun tentativo viene contato sui finding e il report
dice perché. La notte dopo si riparte normalmente.

### Chiamate al modello

- Loop agentico proprio sulla Messages API: l'adapter fa un passo alla volta, il loop sta in
  `services/ripperdoc.py`. I turni dell'assistente si rimandano identici (thinking compresi):
  la storia è append-only.
- Triage, bug hunting e discovery usano structured output (`output_config.format` con JSON
  schema), non un `tool_choice` forzato, che Opus 5.5 e Sonnet 5.5 rifiutano.
- Prompt caching: breakpoint dopo le definizioni dei tool e il system prompt (identici tra
  task) e sull'ultimo messaggio utente, così il loop rilegge la storia dalla cache.
- Retry con backoff dell'SDK su 429, 5xx e overloaded; `effort` per modello da config.
- Una risposta strutturata inutilizzabile (troncata o JSON non valido) viene addebitata
  comunque.
- Ottimizzazione futura: il triage può passare alla Batch API (-50% su input e output), visto
  che di notte la latenza non conta.

## Autodiscovery dei repo

Invece di scrivere a mano `languages`, `setup_command` e `test_command` di ogni repo, si
possono far proporre:

```bash
autofix repos discover --all                 # tutti i progetti del bot non ancora noti
autofix repos discover --project team/api    # uno (ripetibile); ridiscovery di un approvato
autofix repos discover --project team/api --no-llm   # solo rilevamento deterministico, 0 token
autofix repos list                            # config, approvati e proposte in attesa
autofix repos show team/api                   # proposta completa, baseline, differenze
autofix repos approve team/api [--edit] [--force]
autofix repos reject team/api
autofix repos remove team/api                 # solo repo approvati, non quelli del config
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
i comandi girano solo nel sandbox, senza segreti e con la sola rete dei registry. Le regole di
`--force` sono condivise tra CLI e dashboard (`approval_blockers` in `domain/policy.py`).

La run notturna usa i repo del `config.yaml` **più** quelli approvati; in caso di conflitto
vince il `config.yaml`, che resta la fonte di fiducia scritta a mano (e `repos:` può essere
vuoto). Una nuova discovery di un repo approvato crea una proposta nuova senza toccare
l'approvato e ne mostra le differenze; la proposta pending precedente diventa `superseded`.

## Temi di presentazione

L'output per l'operatore (CLI, report a schermo, dashboard) può usare un tema alternativo,
scelto per utente in `ui.themes`; il default è `neutral`. Il tema cambia solo le parole e
l'aspetto a schermo: branch, label, commit, testo delle MR e report su disco restano sempre
neutri.

Nella dashboard chi non ha un tema assegnato riceve `theme: "default"` e il bundle base contiene
solo il tema di default: gli asset di un tema alternativo li serve l'API, e solo a chi ce l'ha
assegnato (per gli altri rispondono 404, come un tema inesistente). Il tema alternativo è
attenuato: le etichette funzionali (finding, run, esiti) restano quelle chiare del tema di
default, il tema cambia colori e font e aggiunge solo marchio, sottotitoli secondari e qualche
dettaglio. `npm run build` fallisce se nel bundle compare uno dei termini di
[`web/theme-terms.json`](../web/theme-terms.json). Per lo stesso motivo la dashboard mostra
sempre il comando `autofix` e mai l'alias storico.

## Dashboard

`autofix web` (servizio `web` del compose, profilo `web`) serve la SPA della dashboard
(`frontend/`, SvelteKit) e un'API in sola lettura sullo stesso origin. Il contratto è
[`web/openapi.json`](../web/openapi.json): un test fallisce se il codice diverge (vedi
[development.md](development.md)). Login, isolamento e header di sicurezza sono descritti in
[security.md](security.md#dashboard).

| Endpoint | Contenuto |
| --- | --- |
| `GET /api/me` | utente e tema risolto |
| `GET /api/dashboard` | spesa del mese vs crediti e proiezione, ultima notte vs tetto, MR aperte, finding per stato, rotazione del bug hunting, ultime run |
| `GET /api/findings` | filtri `kind`, `severity`, `status`, `repo`; ricerca `q` (max 200 caratteri, senza distinzione di maiuscole, su regola, posizione, dettaglio e tool; `%` e `_` sono letterali); `limit` (max 200) e `offset` |
| `GET /api/spend/daily?days=30` | spesa per giorno (1-90 giorni, fuso di `schedule.timezone`) divisa in triage, fix, hunt, discovery e altro; cumulato del mese; tetto per notte e crediti |
| `GET /api/repos` | repo attivi (da `config.yaml` o approvati dall'autodiscovery), comandi, posizione nella rotazione del bug hunting, finding per stato, MR aperte; proposte dell'autodiscovery (in attesa, sostituite, rifiutate) con baseline, sospetti, differenze dalla config attiva e comando per approvarle |
| `GET /api/settings` | configurazione effettiva in sola lettura: pianificazione, funzioni, modelli, budget, limiti, bug hunting, branch e label, prezzi. Niente segreti, path dell'host, URL di GitLab, utenti o temi |
| `GET /api/runs`, `GET /api/runs/{id}` | storico e report completo di una notte (con i passi dell'agente per ogni task: `iterations` e `agent_stop`, `null` nei report precedenti) |
| `GET /api/runs/{id}/tasks/{fingerprint}` | finding, motivo del triage, diff, output dei test, costo, link alla MR (`?repo=` se serve) |
| `GET /api/theme/{name}/lexicon.json`, `.../theme.css` | pacchetto del tema, solo per chi ce l'ha assegnato |
| `/auth/login`, `/auth/callback`, `POST /auth/logout` | login OIDC |

**Approvare dalla dashboard? No.** La pagina Repository mostra le proposte dell'autodiscovery e
il comando da lanciare sull'orchestrator (`autofix repos approve <progetto>`, con `--force`
quando la baseline non è verde o ci sono sospetti), ma non scrive nulla: la config di fiducia
nasce solo da riga di comando.

### Frontend (`frontend/`)

SvelteKit in modalità SPA (`adapter-static`, `ssr = false`), Svelte 5, TypeScript strict,
Tailwind, icone `@lucide/svelte`, risposte dell'API validate con Zod (gli schemi in
`src/lib/api/schemas.ts` sono confrontati con `web/openapi.json` da un test). Le pagine stanno
in `src/lib/svelte/page/<feature>/`, le rotte in `src/routes/` sono solo entry point.

| Schermata | Rotta |
| --- | --- |
| Dashboard: spesa del mese e della notte, grafico della spesa giornaliera (colonne impilate per categoria, tetto per notte, cumulato del mese contro i crediti, tabella dei dati), MR, finding per stato, rotazione del bug hunting, ultime run | `/` |
| Finding con ricerca testuale e filtri tipo, severità, stato e repo nell'URL, paginazione | `/findings` |
| Storico delle run | `/runs` |
| Dettaglio run: statistiche, timeline per repo (scan, triage, fix, verifica, MR), task con esito e costo | `/runs/{id}` |
| Dettaglio task: finding, motivo del triage, cosa cambia, verifica, diff, output dei test, passi dell'agente, costo, link alla MR | `/runs/{id}/tasks/{fp}?repo=` |
| Repository attivi e proposte dell'autodiscovery (sola lettura, con il comando da copiare) | `/repos` |
| Impostazioni effettive (sola lettura) | `/settings` |

Il grafico della spesa è SVG scritto a mano, senza librerie: colori dalle variabili `--viz-*`
del tema (palette categoriale validata per il daltonismo e per la luminosità sul fondo), passaggio
del mouse e frecce della tastiera per il dettaglio di un giorno, tabella dei dati in un
`<details>`. Il tema alternativo lo ricolora ridefinendo le stesse variabili.

Etichette e temi: le etichette neutre stanno in `src/lib/lexicon/neutral.json`; dopo
`/api/me`, se l'utente ha un tema, la SPA carica `/api/theme/<nome>/theme.css` e
`lexicon.json` (le cui chiavi `ui` sovrascrivono solo etichette esistenti). Il tema si aggancia
con `data-theme` su `<html>` e ridefinisce le variabili CSS; i suoi font sono serviti dallo stesso
endpoint protetto.

**Serving e CSP.** FastAPI serve la build (`web.static_dir`, default `frontend/build` accanto
al sorgente): asset in `_app/immutable/` con cache immutabile, `index.html` senza cache e come
fallback per le rotte della SPA, 404 per un asset mancante. Lo script di avvio inline di
SvelteKit è autorizzato con il suo hash, gli attributi `style` statici dei template con
`'unsafe-hashes'` e i loro hash: niente `'unsafe-inline'`. L'immagine `Dockerfile.web` costruisce
la SPA con Node e poi copia solo la build nell'immagine Python.

## Git e checkout

La git dir sta in `workdir/<run>/<repo>/gitdir`, fuori dalla working tree montata nel sandbox, e
il file `.git` viene rimosso. Ogni comando git passa `--git-dir`/`--work-tree` espliciti, ignora
la config globale e di sistema, disattiva hooks, fsmonitor, helper delle credenziali, submodule
e ogni protocollo diverso da https. Il token del bot non entra mai in argv, URL o log: viaggia
come header HTTP in variabili `GIT_CONFIG_*` limitate all'URL di GitLab, e gli errori vengono
ripuliti. Spazzatura di setup e test (`__pycache__`, `.venv`, `node_modules`...) non finisce
mai nelle MR. Working tree e git dir vengono eliminate a fine repo.
