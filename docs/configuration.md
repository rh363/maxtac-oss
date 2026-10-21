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
anche le variabili `ANTHROPIC_API_KEY` e `GITLAB_TOKEN`.

| File | Usato da | Contenuto |
| --- | --- | --- |
| `anthropic_api_key` | orchestrator | chiave API Anthropic |
| `gitlab_token` | orchestrator | token GitLab (Group/Project Access Token, ruolo Developer, scope `api`) |
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
| `bot_username` | | username dell'utente legato al token (il bot creato dall'Access Token, o il tuo con un token personale) |
| `bot_name` | `Autofix Bot` | nome dei commit |
| `bot_email` | `<bot_username>@noreply.<host>` | email dei commit |
| `ca_bundle` | nessuno | bundle PEM della CA interna, per API, git e login OIDC verso GitLab. Va montato nei container `orchestrator` e `web` (righe commentate in `docker-compose.yml`) |

Oggi è supportato un solo token: tutti i repo devono essere raggiungibili con lo stesso token
(per esempio un Group Access Token sul gruppo che li contiene).

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
