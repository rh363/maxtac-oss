# Configurazione

Tutta la config di fiducia sta in un file dell'orchestrator (`config.yaml`, montato in sola
lettura in `/etc/autofix/config.yaml`), mai dentro i repo: un file nel repo sarebbe input non
fidato. Il punto di partenza commentato è [`config.example.yaml`](../config.example.yaml).
Chiavi sconosciute, modelli senza prezzo, project non nel formato `gruppo/nome` (i sottogruppi
vanno bene), repo duplicati e `per_task` maggiore di `per_night` bloccano l'avvio.

`config.yaml` non va committato: contiene l'elenco degli utenti della dashboard e la loro
assegnazione dei temi. `config.example.yaml` usa solo domini d'esempio (un test lo verifica).

## Segreti

Docker secret in `/run/secrets/` (file in `secrets/` accanto al compose). In sviluppo valgono
anche le variabili d'ambiente omonime in maiuscolo (`ANTHROPIC_API_KEY`, `GITLAB_TOKEN_<NOME>`).

| File | Usato da | Contenuto |
| --- | --- | --- |
| `anthropic_api_key` | orchestrator | chiave API Anthropic |
| `gitlab_tokens/<nome>` | orchestrator | un file per ogni token di `gitlab.tokens` (Group/Project Access Token, ruolo Developer, scope `api`). La directory `secrets/gitlab_tokens` è montata dal compose: aggiungere un token non richiede di toccarlo |
| `notify_webhook_url` | orchestrator | URL del webhook del mattino (solo con `notify.webhook: true`) |
| `oidc_client_secret` | web | secret dell'Application OIDC su GitLab |
| `web_session_secret` | web | stringa casuale di almeno 32 caratteri per firmare le sessioni |

```bash
python3 -c 'import secrets; print(secrets.token_urlsafe(48), end="")' > secrets/web_session_secret
```

## Sezioni

### `gitlab`

| Chiave | Default | Note |
| --- | --- | --- |
| `url` | | solo `https://` |
| `tokens` | nessuno | elenco dei token, vedi sotto |
| `ca_bundle` | nessuno | bundle PEM della CA interna, per API, git e login OIDC verso GitLab. Va montato nei container `orchestrator` e `web` (righe commentate in `docker-compose.yml`) |

#### `gitlab.tokens`

Un token per ogni gruppo o progetto da controllare. Ogni voce:

| Chiave | Note |
| --- | --- |
| `name` | minuscole, cifre e `-`; il valore del token sta in `secrets/gitlab_tokens/<name>` |
| `scope` | prefissi di path GitLab coperti: un gruppo (`team`, sottogruppi compresi), un sottogruppo (`team/backend`) o un progetto (`alice/tools`) |
| `bot_name` | facoltativo: nome dei commit al posto di quello dell'utente del token |

```yaml
gitlab:
  url: https://gitlab.example.it
  tokens:
    - name: team            # Group Access Token del gruppo team
      scope: [team]
    - name: alice-tools     # Project Access Token di un progetto personale
      scope: [alice/tools]
```

Regole:

- Il confronto è per segmenti di path: `team` copre `team/api` e `team/backend/worker`, non
  `team2/api`.
- Ogni repo usa il token con il **prefisso più specifico** che lo copre: con `team` e
  `team/api` in due token diversi, `team/api` usa il secondo e il resto del gruppo il primo.
- Lo stesso prefisso in due token, nomi duplicati o un repo del `config.yaml` che nessun token
  copre bloccano l'avvio. Un repo approvato dall'autodiscovery che nessun token copre viene
  saltato con il motivo nel report, e `autofix repos approve` lo rifiuta.
- Utente, nome ed email dei commit si leggono da GitLab (`GET /user` con il token): non vanno
  scritti in config. L'email è quella pubblica dell'utente, altrimenti
  `<username>@noreply.<host>`.
- A ogni run, e con `autofix tokens`, ogni token viene controllato su GitLab: utente, scope
  (deve avere `api`) e scadenza (`GET /personal_access_tokens/self`; se la versione di GitLab
  non lo espone, la scadenza risulta "non verificata"). Lo stato finisce nel db e lo
  mostrano `autofix status` e la pagina Impostazioni della dashboard, con un avviso nei 30
  giorni prima della scadenza. Un token non valido ferma solo i repo che copre.
- `autofix repos discover --all` chiede i progetti a ogni token e tiene solo quelli dentro il
  suo `scope`.

**Configurazione senza `tokens` (versioni precedenti).** Un solo token per tutta l'istanza,
dal Docker secret `gitlab_token`, dal file `secrets/gitlab_tokens/default` o dalla variabile
`GITLAB_TOKEN`. In questo caso valgono ancora `bot_username`, `bot_name` e `bot_email` per
forzare l'identità dei commit. Il compose attuale non dichiara più il secret `gitlab_token`:
usa il file in `secrets/gitlab_tokens/default` oppure passa a `tokens`.

### `schedule`

`timezone` (IANA, default `Europe/Rome`) e `at` (`HH:MM`, default `02:30`): ora della run
notturna, lanciata dal servizio `orchestrator` sempre in esecuzione. Il cambio d'ora legale è gestito.

### `budget`

| Chiave | Default | Note |
| --- | --- | --- |
| `monthly_credits_usd` | 100 | crediti del mese: avvisi sulla proiezione, run non avviata a crediti esauriti |
| `per_night_usd` | 3.0 | tetto della notte |
| `per_task_usd` | 0.80 | tetto di un singolo fix |
| `triage_per_repo_usd` | 0.10 | tetto del triage di un repo |
| `hunting_per_night_usd` | 1.0 | tetto del bug hunting di una notte |
| `max_mrs_per_night` | 3 | |
| `max_attempts` | 2 | tentativi falliti per finding, poi passa a un umano |
| `max_iterations` | 30 | passi massimi del fix agent |
| `discovery_per_repo_usd` | 0.15 | tetto dell'autodiscovery di un repo |
| `discovery_max_iterations` | 12 | passi massimi dell'autodiscovery |

### `models`

`triage` (default Haiku 5.5), `fix` (Sonnet 5.5), `hunt` (Opus 5.5), `discovery` (Haiku 5.5).
Ogni modello deve avere un prezzo in `prices_usd_per_mtok`.

### `anthropic`

`timeout_s` (600), `max_retries` (4, su 429, 5xx e overloaded con backoff dell'SDK),
`refusal_fallback` (su un rifiuto dei classificatori la richiesta riparte lato server su un
altro modello, solo Opus 5.5 e Sonnet 5.5), `fallback_models`, `effort` per modello (default:
Haiku `low`, Sonnet `medium`, Opus `high`).

### `features`

`cve` (default `true`), `sast` (`false`), `hunting` (`false`): attivazione a fasi, vedi
[go-live.md](go-live.md). `run --scan-only` esegue sempre tutti gli scanner, perché lo scan non
costa token.

### `hunting`

`repos_per_night` (2) e `lookback_days` (7).

### `vcs`

`branch_prefix` (`autofix`) e `mr_labels` (`[autofix]`): branch `autofix/<kind>/<fingerprint>`.

### `notify`

`webhook: true` invia il riepilogo del mattino con una POST JSON (formato compatibile con gli
incoming webhook di Slack e Mattermost) all'URL del segreto `notify_webhook_url`. Solo https.

### `ui`

`default_theme` (`neutral`) e `themes`: mappa utente → tema, per email (o username con
`web.user_claim: username`). Il tema cambia solo l'output a schermo e la dashboard per
quell'utente; GitLab e i report su disco restano neutri.

### `web`

| Chiave | Default | Note |
| --- | --- | --- |
| `user_claim` | `email` | `email` (solo email verificate) o `username` |
| `allowed_users` | | chi può entrare; tutti gli altri ricevono 403. Confronto senza distinzione di maiuscole |
| `oidc.issuer` | | l'URL di GitLab se l'IdP è GitLab |
| `oidc.client_id` | | Application ID |
| `oidc.redirect_uri` | | `https://<dashboard>/auth/callback` |
| `oidc.scopes` | `[openid, profile, email]` | `email` aggiunto da solo se manca |
| `oidc.username_claims` | `[preferred_username, nickname]` | solo con `user_claim: username` |
| `session_max_age_s` | 28800 | durata della sessione |
| `trusted_proxies` | `[]` | indirizzi o reti del reverse proxy che passa `X-Forwarded-For` (altrimenti il rate limit vede un solo client) |
| `host`, `port` | `0.0.0.0`, 8080 | bind dentro il container; sull'host la porta è pubblicata solo su `127.0.0.1` |
| `static_dir` | `frontend/build` | build della SPA |
| `dev_user` | nessuno | solo con `autofix web --dev`, bind su loopback, nessun login |

**Application OIDC su GitLab.** Non servono permessi di admin: *User Settings → Applications*
(oppure *Settings → Applications* di un gruppo di cui sei Owner). *Confidential* attivo, scope
`openid`, `profile` ed `email`, redirect URI `https://<host della dashboard>/auth/callback`.
L'Application ID va in `web.oidc.client_id`, il secret nel segreto `oidc_client_secret`.

**Reverse proxy.** La dashboard ascolta solo su `127.0.0.1:8080`; davanti serve TLS, per
esempio con Caddy:

```
autofix.example.it {
    reverse_proxy 127.0.0.1:8080
}
```

### `sandbox`

`image` (`autofix-sandbox:latest`), `network` (`autofix_sandbox`, rete Docker `internal`),
`proxy_url` (`http://proxy:3128`), `user` (`1000:1000`, mai root), `mem_limit` (`4g`), `cpus`
(2.0), `pids_limit` (512).

### `scanners`

`semgrep.rulesets` (`[p/default]`) e `semgrep.by_language` (ruleset aggiunti per i linguaggi
presenti nei repo). I ruleset sono scaricati alla build dell'immagine dei sandbox: devono
comparire anche in `SEMGREP_RULESETS` di `sandbox/Dockerfile`.

### `workdir` e `db_path`

`workdir` (`/var/lib/autofix/work`): copie di lavoro, report e diff delle run. `db_path`
(`/var/lib/autofix/autofix.sqlite3`): stato dei finding, spesa, storico, repo approvati e
proposte.

### `repos`

Repo scritti a mano, la config di fiducia che vince su quelli approvati dall'autodiscovery. Può
restare vuota.

```yaml
repos:
  - project: team/api
    languages: [python]
    setup_command: pip install -r requirements.txt
    test_command: pytest -q
  - project: team/agent
    languages: [go]
    test_command: go test ./...
```

### `prices_usd_per_mtok`

Prezzi in USD per milione di token, per modello: `input`, `output`, `cache_read`,
`cache_write`. Il costo di ogni chiamata si calcola dai campi `usage` della risposta.
