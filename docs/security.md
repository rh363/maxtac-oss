# Sicurezza

Ipotesi di partenza: il contenuto dei repo (codice, commenti, nomi di file, lockfile, output
dei test) è input non fidato e può contenere prompt injection. Lo stesso vale per tutto ciò
che produce il modello che lo ha letto.

## Rischi e contromisure

| Rischio | Contromisura |
| --- | --- |
| Esfiltrazione di chiave API o token GitLab | Solo nell'orchestrator (Docker secret); mai nel sandbox, in argv, nell'URL del remoto o nei log |
| Credenziali dei registry interni | Solo account di sola lettura; nel sandbox come `~/.netrc` passato su stdin (mai in env o argv). L'output del sandbox arriva a modello, report e dashboard con i valori oscurati (password, `utente:password`, base64); MR e commit sono oscurati e un fix il cui diff contiene un valore non viene pubblicato. Nessuna credenziale e nessuna voce di allowlist può coprire GitLab (controllo in config e all'avvio dei sandbox) |
| Un token usato fuori dal suo perimetro | Con più token ogni repo usa solo quello col prefisso di path più specifico che lo copre, scelto dalla config e mai dal contenuto del repo; un repo non coperto non arriva a GitLab. Token, client API e header git sono separati per token. La dashboard e `status` vedono solo nome, scope, utente e scadenza, mai i valori |
| Code execution nell'orchestrator via git | Git dir separata e non montata, `.git` (file o directory) nella working tree eliminato prima di ogni comando, hooks/fsmonitor/filtri/protocolli non https disattivati, config globale ignorata |
| Quick action GitLab (`/merge`, `/approve`) e menzioni nella MR | Campi non fidati su una riga con `\|` e backtick neutralizzati; motivazioni, riassunto e output dei test in blocchi di codice; nessuna riga della descrizione può iniziare con `/`; `@` neutralizzato |
| Agente che bara sui test | Per CVE e SAST nessun file di test toccabile (nemmeno aggiunto); config di CI, test runner e scanner protetta ovunque nel repo; `pyproject.toml`/`package.json` ammessi per le CVE solo se non cambiano le sezioni di test e scanner; symlink e submodule sempre a un umano |
| Test di regressione finti (bug) | Il test nuovo deve fallire sul codice base; la suite senza i test nuovi deve passare sul fix; euristica su `os._exit`, `sys.exit`, `TestMain`, `pytest.exit` & co. |
| Soppressioni del finding | semgrep `--disable-nosem`, bandit `--ignore-nosec`, gosec `-nosec`, osv-scanner con config vuota esplicita; i file di config degli scanner sono protetti |
| Scanner o tool finti piazzati dal codice del repo | Rescan in un sandbox nuovo dove non girano né setup né test, sulla fotografia git del fix; scanner e utility per path assoluto; `PATH` con le directory di sistema prima di quelle scrivibili |
| File ignorati che truccano la verifica (`.venv/bin/pytest`, `node_modules/.bin`, `.pyc`) | `git clean -ffdx` dopo l'agente; la working tree viene riportata alla fotografia del fix prima di ogni passo |
| Contenuto non verificato nella MR | Snapshot come tree git (binari, symlink, file grandi inclusi): test, rescan e controlli dei bug lavorano su quella fotografia e si verifica che la working tree torni identica |
| Comandi di setup e test proposti dall'autodiscovery | Restano proposte finché un umano non le approva dalla CLI; comandi banali, che ignorano i fallimenti, usano la rete, pubblicano o scrivono fuori da `/work` sono segnalati e richiedono `--force` |
| Sandbox privilegiato | Non root, `cap_drop: ALL`, `no-new-privileges`, rootfs in sola lettura, limiti CPU/RAM/PID, rete `internal` |
| Sandbox bloccato (processo in background che tiene aperto stdout) | Watchdog: oltre timeout + margine il container viene ucciso |
| Egress dal sandbox | Squid con allowlist dei soli registry (PyPI, proxy Go senza `direct`, npm), solo CONNECT su 443; ruleset semgrep e database OSV sono nell'immagine. Il sandbox non raggiunge GitLab (un test lo verifica) |
| Spesa fuori controllo | Tetti per notte, task e hunting; tetto della notte ridotto ai crediti del mese rimasti e run non avviata a crediti esauriti; spesa delle risposte strutturate inutilizzabili addebitata comunque |
| Disco pieno | Working tree e git dir eliminate a fine repo (anche in dry-run: i diff stanno nel report) |
| Supply chain | Scanner Python installati con `--require-hashes` (`scripts/lock-sandbox-tools.sh`), digest delle immagini con `scripts/pin-digests.sh`, `go install` coperto da sumdb |
| Merge automatico | Mai: ogni MR passa da review umana |

## Rischi residui

Accettati e da rivalutare:

- **Pubblicazione su registry.** Squid su HTTPS vede solo l'host. Un agente compromesso con
  credenziali *proprie* potrebbe pubblicare su PyPI o npm e così esfiltrare codice. La
  mitigazione è un mirror in sola lettura (devpi, verdaccio, Athens per Go) con l'allowlist
  ridotta ai soli mirror.
- **Credenziali dei registry nel sandbox.** Il codice del repo gira accanto a `~/.netrc` e può
  leggerle o inviarle a un registry dell'allowlist. L'oscuramento copre i valori in chiaro, non
  una trasformazione scelta da chi controlla il codice (es. il file cifrato o spezzato), che
  potrebbe arrivare al modello o in un diff. Per questo vanno usati solo account di sola
  lettura, dedicati ad Autofix e senza altri permessi.
- **Kernel condiviso.** Il sandbox gira con lo stesso uid dei file dell'orchestrator: un escape
  dal kernel darebbe accesso al db. Raccomandato: `userns-remap` nel daemon Docker oppure il
  runtime gVisor (`runsc`), su una VM dedicata solo ad Autofix.
- **Socket Docker.** Montato nell'orchestrator equivale a root sull'host: per questo la VM deve
  essere dedicata. Valutare Docker rootless.
- **Token GitLab personale.** Con un Personal Access Token al posto di un token di gruppo o
  progetto (ruolo Developer), il token ha tutti i permessi dell'utente, merge compreso. Le
  difese contro le quick action restano attive, ma il raggio d'azione è molto più ampio.
  Con più token conviene un Group o Project Access Token per ogni perimetro: un token
  compromesso espone solo i repo del suo gruppo o progetto.
- L'euristica sui test di regressione è aggirabile da un attaccante determinato: per questo
  ogni MR di bug resta da rivedere con particolare attenzione al test aggiunto.

## Dashboard

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

**Isolamento.** Il container `web` non ha il socket Docker né i segreti del bot e della chiave
Anthropic; monta `/var/lib/autofix` in sola lettura e apre il db con `mode=ro` e
`query_only`. Per questo il db usa il journal `DELETE` e non WAL (un lettore WAL deve scrivere
il file `-shm`). La porta è pubblicata solo su `127.0.0.1:8080`: davanti va un reverse proxy
con TLS.

**Header e risposte.** CSP stretta (`'self'`, niente `'unsafe-inline'`), `X-Frame-Options:
DENY`, `nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` sull'API. Niente
`/docs` né `/openapi.json` pubblici. Path dell'host e link che non puntano a GitLab vengono
tolti dalle risposte; diff e output dei test sono testo semplice, mostrati escaped. La pagina
Impostazioni non espone segreti, path, URL di GitLab, utenti né temi.

**Temi.** Un utente senza tema assegnato non può scoprire che ne esiste un altro: riceve
`theme: "default"`, gli asset di un tema non assegnato rispondono 404 come un tema
inesistente, e il bundle base contiene solo il tema di default (controllato in build).

## GitLab self-hosted su rete interna

Orchestrator e dashboard parlano con GitLab dalla rete della VM; i sandbox **no**: la loro
unica uscita è il proxy, la cui allowlist contiene solo i registry dei pacchetti (un test
fallisce se cambia o se include l'host di GitLab). Il bundle della CA interna
(`gitlab.ca_bundle`) vale per le API (python-gitlab), per git (`http.<url di GitLab>.sslCAInfo`,
passato in ambiente come il token) e per il login OIDC, ma solo se l'issuer è GitLab stesso:
con un IdP pubblico sostituirebbe le CA di sistema. Il sandbox non lo riceve.
