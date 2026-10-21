# Go-live

L'installazione passo per passo è nel [README](../README.md#installazione). Qui la checklist
dettagliata per la messa in produzione.

## Cosa è già verificato e cosa no

Verificato in locale: pipeline completa con git reale e remoto bare, bandit reale, una
settimana di notti simulate (tetti, rotazione, nessuna MR doppia, merge a metà settimana),
dashboard con Playwright su dati demo. Verificabile solo sulla VM:

- allowlist reale di squid (scanner e package manager dietro proxy);
- `DockerSandbox` con un daemon vero (`put_archive` su rootfs in sola lettura, limiti, rete
  `internal`): `AUTOFIX_DOCKER_TESTS=1 uv run pytest -m docker`;
- API GitLab della propria istanza (versione, permessi del token, label);
- chiamate vere alla Claude API: cache hit, fallback sui rifiuti, messaggio a crediti finiti;
- login OIDC verso la propria istanza GitLab.

Verificato dalla CI (`.github/workflows/ci.yml`) a ogni PR: build delle tre immagini e prova
senza rete con rootfs in sola lettura (`scripts/smoke-images.sh`): CLI, SPA nella dashboard,
osv-scanner offline che trova una CVE nota, semgrep con i ruleset dell'immagine, bandit.

## Prima della prima run vera

- VM dedicata: il socket Docker montato nell'orchestrator equivale a root sull'host.
- Immagini da GHCR: dopo la prima pubblicazione, in *GitHub → Packages* controllare che
  `autofix-orchestrator`, `autofix-web` e `autofix-sandbox` siano collegati al repo
  (*Package settings → Manage Actions access*: il repo deve avere il ruolo Write, così la CI può
  aggiornarli). Le immagini sono pubbliche per scelta: non contengono segreti, quindi sulla VM
  non serve `docker login`. Per renderle private: *Package settings → Change visibility*, poi
  `docker login ghcr.io` sulla VM con un token classic `read:packages`.
- Versione fissata: nel `.env` della VM `AUTOFIX_TAG=sha-<commit>`, oppure le tre variabili
  `AUTOFIX_*_IMAGE` con i digest che il job `publish` scrive nel riepilogo della run.
  `./scripts/verify-images.sh` controlla la firma cosign.
- Immagini base: `./scripts/pin-digests.sh` (dove c'è accesso ai registry) e commit dei digest;
  `./scripts/pin-digests.sh --check` deve uscire con 0.
- Build dell'immagine sandbox: verificare che i ruleset semgrep in config siano tutti in
  `SEMGREP_RULESETS` (`sandbox/Dockerfile`) e che `/opt/osv-db` contenga i database.
- `workdir` su un filesystem dedicato e limitato (es. volume LVM o file system loop da
  20-50 GB montato su `/var/lib/autofix/work`), separato da quello del db SQLite.
- Chiave Anthropic senza auto-reload, così a crediti finiti le richieste si fermano.
- Token GitLab di gruppo o progetto con ruolo Developer (vedi il README); con un token
  personale leggere i rischi in [security.md](security.md#rischi-residui).

## Comandi del primo avvio

```bash
sudo mkdir -p /var/lib/autofix && sudo chown 1000:1000 /var/lib/autofix
mkdir -p secrets && chmod 700 secrets
printf '%s' "$ANTHROPIC_KEY" > secrets/anthropic_api_key
mkdir -p secrets/gitlab_tokens
printf '%s' "$GITLAB_TOKEN_TEAM" > secrets/gitlab_tokens/team   # uno per voce di gitlab.tokens
cp config.example.yaml config.yaml
echo "DOCKER_GID=$(stat -c %g /var/run/docker.sock)" > .env
echo "AUTOFIX_TAG=main" >> .env
./scripts/update.sh                                         # pull (sandbox compreso) e avvio
docker compose run --rm orchestrator run --scan-only        # prova a costo zero
```

Il servizio `orchestrator` resta in esecuzione e lancia la run all'ora di `schedule`. `status` mostra spesa
del mese, proiezione e MR aperte.

## Checklist, una fase alla volta

Ogni fase si attiva solo dopo una notte pulita in dry-run.

1. `repos discover --all`, revisione con `repos show` e approvazione dei repo.
2. `run --scan-only` su tutti i repo: i finding normalizzati hanno senso, niente errori.
3. **CVE** (`features.cve: true`, default): una notte `run --dry-run`, lettura di
   `workdir/<run_id>/report.md` e dei diff in `diffs/`; poi la prima run vera su un repo di
   prova con una dipendenza vulnerabile apposta (`run --repo gruppo/prova`): la MR deve
   arrivare con i test verdi.
4. **SAST** (`features.sast: true`): una notte in dry-run; controllare che i falsi positivi
   noti finiscano in `ignored` e che i fix non tocchino i test.
5. **Bug hunting** (`features.hunting: true`): una notte in dry-run con
   `hunting.repos_per_night: 1`, poi 2. Controllare in `status` spesa e proiezione del mese.
6. Dopo una settimana: tarare i tetti (`budget.*`) sulla spesa vera e, se serve, attivare la
   notifica del mattino.
7. Dashboard: Application OIDC, segreti `oidc_client_secret` e `web_session_secret`,
   `docker compose --profile web up -d web`, reverse proxy con TLS, prova di accesso con un
   utente in `allowed_users` e con uno che non c'è (deve ricevere 403).

## Manutenzione

- La CI ripubblica l'immagine dei sandbox ogni lunedì alle 04:17 UTC (scanner e database
  nuovi); sulla VM `scripts/update.sh` da cron il lunedì mattina la scarica. Chi costruisce in
  locale usa `scripts/rebuild-sandbox.sh`.
- Backup del db (`sqlite3 ... ".backup ..."`) fuori dalla finestra della run notturna.
- Pulizia periodica di report e diff vecchi in `workdir`.
