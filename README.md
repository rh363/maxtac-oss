# Autofix

Autofix gira di notte su una VM e controlla i tuoi repo GitLab: dipendenze con vulnerabilità
note (CVE), problemi segnalati dall'analisi statica del codice (SAST) e, a rotazione, bug nel
codice cambiato di recente. La mattina trovi Merge Request con il fix già pronto e già
verificato (test verdi, problema sparito). **Nessuna MR viene unita da sola:** passano tutte da
una review umana. La spesa per il modello AI è limitata da tetti che decidi tu.

La documentazione tecnica (architettura, sicurezza, configurazione completa, sviluppo) sta in
[`docs/`](#documentazione-tecnica).

## Cosa serve

- Una **VM Linux dedicata** con Docker e Docker Compose. Dedicata perché Autofix comanda il
  daemon Docker, che equivale ad avere i permessi di root sulla macchina.
- **Accesso di rete** dalla VM a GitLab (va bene anche un'istanza solo su rete interna) e a
  `api.anthropic.com`.
- Una **chiave API Anthropic**, possibilmente senza ricarica automatica del credito: a crediti
  finiti Autofix si ferma da solo fino al mese dopo.
- Uno o più **token GitLab**: come ottenerli senza essere admin è spiegato al passo 2.
- Per la dashboard (facoltativa): un nome a dominio e un reverse proxy con TLS davanti.
- Accesso dalla VM a **`ghcr.io`**, dove sono pubblicate le immagini (pubbliche, non serve
  un account).

## Installazione

### 1. Scarica il progetto

Sulla VM non serve il codice, ma solo alcuni file: `docker-compose.yml`, `config.example.yaml`,
`proxy/squid.conf` e la cartella `scripts/`. Il modo più semplice è clonare il repo:

```bash
git clone <url-del-repo> /opt/autofix
cd /opt/autofix
sudo mkdir -p /var/lib/autofix && sudo chown 1000:1000 /var/lib/autofix
mkdir -p secrets && chmod 700 secrets
```

`/var/lib/autofix` contiene il database e le copie di lavoro dei repo.

### 2. Crea i token GitLab

Non servono permessi di admin. Le strade sono due.

**A. Group o Project Access Token (consigliata).** Funziona sui gruppi o sui progetti in cui
sei Maintainer o Owner. GitLab crea in automatico un utente bot legato al token, quindi le MR
risultano aperte dal bot e non da te.

1. Apri il gruppo (o il progetto), poi **Settings → Access tokens → Add new token**.
2. Ruolo **Developer**, scope **`api`**, una scadenza (per esempio un anno).
3. Copia il token.

Con il ruolo Developer il bot non può unire MR né scrivere sui branch protetti. Un Group
Access Token vale per tutti i progetti del gruppo e dei sottogruppi; un Project Access Token
per un solo progetto, anche nel tuo namespace personale. **Puoi usarne quanti vuoi**: uno per
ogni gruppo o progetto da controllare. Se la voce "Access tokens" non compare, l'admin
dell'istanza l'ha disattivata: chiedi di abilitarla oppure usa la strada B.

**B. Personal Access Token (ripiego).** **User Settings → Access tokens**, scope `api`, con
una scadenza. Funziona subito, ma MR e commit risultano tuoi e il token ha **tutti i tuoi
permessi** su GitLab, merge compreso. Usalo per una prova, non come soluzione definitiva.

Salva ogni token in un file dentro `secrets/gitlab_tokens/`, con un nome breve a tua scelta
(minuscole, cifre e trattini). Lo stesso nome lo userai nella configurazione al passo 4.

```bash
mkdir -p secrets/gitlab_tokens && chmod 700 secrets
printf '%s' 'TOKEN-DEL-GRUPPO'   > secrets/gitlab_tokens/backend    # Group Access Token del gruppo backend
printf '%s' 'TOKEN-DEL-PROGETTO' > secrets/gitlab_tokens/tools      # Project Access Token di alice/tools
```

### 3. Salva la chiave Anthropic

```bash
printf '%s' 'LA-TUA-CHIAVE' > secrets/anthropic_api_key
chown -R 1000:1000 secrets && chmod -R go= secrets
```

I servizi girano con l'utente 1000, non root: i file in `secrets/` devono essere suoi, se no
non riescono a leggerli. Ripeti il `chown` ogni volta che aggiungi o sostituisci un segreto.

I segreti stanno solo in `secrets/` e non finiscono mai nella configurazione, nei log o nei
repo.

### 4. Scrivi la configurazione

```bash
cp config.example.yaml config.yaml
```

Per partire bastano questi campi; tutto il resto ha già un valore sensato.

```yaml
gitlab:
  url: https://gitlab.example.it        # indirizzo della tua istanza
  tokens:                               # un elemento per ogni file in secrets/gitlab_tokens/
    - name: backend
      scope: [backend]                  # tutto il gruppo backend, sottogruppi compresi
    - name: tools
      scope: [alice/tools]              # un solo progetto, anche personale

schedule:
  timezone: Europe/Rome
  at: "02:30"                           # ora della run notturna

budget:
  monthly_credits_usd: 100.0            # crediti del mese, per gli avvisi
  per_night_usd: 3.0                    # tetto di spesa per notte

features:                               # si attivano un po' alla volta (vedi "Primo utilizzo")
  cve: true
  sast: false
  hunting: false

repos: []                               # vuoto: i repo si aggiungono con l'autodiscovery
```

Ogni repo usa il token che lo copre in modo più specifico. Lo username del bot e il nome dei
commit li legge Autofix da GitLab: non serve scriverli.

Il file `config.yaml` resta sulla VM e non va committato: contiene, per esempio, l'elenco
delle persone che possono entrare nella dashboard.

**GitLab con certificato di una CA interna.** Copia il certificato della CA in
`ca/gitlab-ca.pem`, togli il commento alle righe `gitlab-ca.pem` in `docker-compose.yml` e
aggiungi `ca_bundle: /etc/autofix/gitlab-ca.pem` sotto `gitlab:`.

### 5. Scarica e avvia

Le immagini sono pubblicate dalla CI su GitHub Container Registry e sono pubbliche: si
scaricano senza login. Non contengono segreti: chiavi, token e configurazione restano sulla VM.

Crea un file `.env` accanto a `docker-compose.yml`:

```bash
echo "DOCKER_GID=$(stat -c %g /var/run/docker.sock)" > .env
echo "AUTOFIX_TAG=main" >> .env
```

`AUTOFIX_TAG` sceglie la versione: `main` è l'ultima pubblicata, `sha-<commit>` o `v1.2.3`
una versione precisa. Poi:

```bash
./scripts/update.sh      # scarica le immagini (compreso l'ambiente isolato) e avvia
```

`update.sh` fa `docker compose pull` e `docker compose up -d`. L'ambiente isolato dove girano
scanner e fix non è un servizio: viene solo scaricato, lo avvia Autofix quando serve.

Per controllare che le immagini siano proprio quelle firmate dalla CI di questo repo (serve
[cosign](https://docs.sigstore.dev/cosign/system_config/installation/)):

```bash
./scripts/verify-images.sh
```

**In alternativa, costruire in locale** (serve tutto il repo e più tempo):

```bash
docker compose --profile sandbox build sandbox-image
docker compose up -d --build
```

### 6. Primo controllo

```bash
docker compose run --rm orchestrator status
```

Deve mostrare la spesa del mese (zero) senza errori. Se manca un segreto, il messaggio dice
quale.

Per brevità, negli esempi seguenti `autofix …` sta per
`docker compose run --rm orchestrator …`. Un alias comodo:

```bash
alias autofix='docker compose -f /opt/autofix/docker-compose.yml run --rm orchestrator'
```

## Primo utilizzo

### Aggiungi i repo con l'autodiscovery

Per ogni repo Autofix deve sapere quali linguaggi usa, come si installano le dipendenze e come
si lanciano i test. Non serve scriverlo a mano:

```bash
autofix repos discover --all     # analizza tutti i progetti che i token vedono
autofix repos list               # elenco: attivi e proposte in attesa
autofix repos show team/api      # dettaglio di una proposta
```

Per ogni progetto Autofix guarda i file del repo, chiede al modello di proporre i comandi e li
prova sul codice attuale: i test devono passare. Costa pochi centesimi per repo; con
`--no-llm` usa solo il riconoscimento automatico dei file, a costo zero.

Il risultato è una **proposta**, non ancora attiva. Serve la tua approvazione perché i comandi
vengono dal contenuto del repo, e il comando di test è quello che decide se un fix è buono:
un repo scritto male (o con intenzione) potrebbe proporre un "test" che passa sempre. Autofix
segnala da solo i comandi sospetti, ma l'ultima parola è tua:

```bash
autofix repos approve team/api           # la proposta diventa attiva
autofix repos approve team/api --edit    # correggi i comandi prima di approvare
autofix repos reject team/api            # scarta la proposta
autofix repos remove team/api            # toglie un repo approvato
```

Se i test non passano o ci sono comandi sospetti, `approve` chiede anche `--force`. In
alternativa puoi scrivere i repo a mano nella sezione `repos:` del `config.yaml`, che ha
sempre la precedenza.

### Prova a costo zero

```bash
autofix run --scan-only
```

Esegue solo gli scanner, senza usare il modello: mostra i problemi trovati in ogni repo.

### Una notte di prova

```bash
autofix run --dry-run
```

Fa tutto il lavoro di una notte vera (e spende crediti), ma **non crea branch né MR**. Il
report e le modifiche proposte finiscono in `/var/lib/autofix/work/<id-della-run>/`: leggi
`report.md` e i diff per farti un'idea della qualità.

### Attiva le funzioni un po' alla volta

Ogni funzione si attiva in `features:` del `config.yaml`, dopo una notte di prova pulita:

1. **CVE** (attiva di default): aggiornamento delle dipendenze vulnerabili.
2. **SAST** (`sast: true`): correzione dei problemi segnalati dall'analisi statica. Controlla
   che i falsi positivi vengano ignorati.
3. **Bug hunting** (`hunting: true`): ogni notte 1-2 repo, a rotazione, vengono riletti dal
   modello sul codice degli ultimi 7 giorni. È la funzione più costosa: parti con
   `hunting.repos_per_night: 1`.

Dopo ogni modifica al `config.yaml`: `docker compose restart orchestrator`.

Da questo momento Autofix lavora da solo ogni notte all'ora di `schedule.at`.

## Uso quotidiano

**La mattina** apri su GitLab le MR con la label **`autofix`**. Ognuna spiega cosa è stato
trovato, perché si è deciso di correggerlo, cosa cambia, l'esito dei test e quanto è costata.
Rivedila come faresti con quella di un collega.

- **La MR va bene:** uniscila.
- **Non ti convince:** chiudila senza unirla. Autofix lo considera un rifiuto e non riproporrà
  lo stesso fix.
- **Problemi che richiedono una persona:** quando un fix è rischioso (per esempio un salto di
  versione importante) o tocca i test esistenti, Autofix non apre la MR e lo segnala nel
  report e nella dashboard come "serve un umano".

Comandi utili:

| Comando | Cosa fa |
| --- | --- |
| `autofix status` | spesa del mese e proiezione, problemi trovati per stato, MR aperte, ultime run, scadenza dei token |
| `autofix tokens` | ricontrolla subito i token GitLab: utente, permessi e scadenza |
| `autofix run --dry-run` | una run subito, senza creare MR |
| `autofix run --repo team/api` | una run vera subito, solo su quel repo |
| `autofix run --scan-only` | solo gli scanner, gratis |
| `autofix repos list` | repo attivi e proposte in attesa |

**Cambiare orario o budget:** modifica `schedule` o `budget` nel `config.yaml`, poi
`docker compose restart orchestrator`.

## Dashboard

La dashboard mostra in sola lettura tutto quello che fa Autofix: spesa giorno per giorno, MR
aperte, problemi trovati (con ricerca e filtri), storico delle notti con il dettaglio di ogni
fix, repo attivi e proposte da approvare, impostazioni in vigore. Non permette di modificare
nulla: le approvazioni si fanno sempre dalla riga di comando. Supporta temi diversi per utente.

L'accesso avviene con l'account GitLab ed è riservato alle persone elencate in configurazione.

**1. Crea l'Application su GitLab** (non serve essere admin): **User Settings → Applications →
Add new application**.

- Redirect URI: `https://<indirizzo-della-dashboard>/auth/callback`
- **Confidential** attivo
- Scope: `openid`, `profile`, `email`

**2. Salva i segreti:**

```bash
printf '%s' 'SECRET-DELL-APPLICATION' > secrets/oidc_client_secret
python3 -c 'import secrets; print(secrets.token_urlsafe(48), end="")' > secrets/web_session_secret
chown -R 1000:1000 secrets && chmod -R go= secrets
```

**3. Configura chi può entrare** nel `config.yaml`:

```yaml
web:
  allowed_users:                     # email verificate su GitLab; tutti gli altri vengono respinti
    - mario.rossi@example.com
    - anna.bianchi@example.com
  oidc:
    issuer: https://gitlab.example.it          # stesso indirizzo di GitLab
    client_id: "<Application ID>"
    redirect_uri: https://autofix.example.it/auth/callback
```

**4. Avvia** la dashboard e mettile davanti un reverse proxy con TLS. Con Caddy:

```bash
docker compose --profile web up -d web     # ascolta solo su 127.0.0.1:8080
```

```
autofix.example.it {
    reverse_proxy 127.0.0.1:8080
}
```

## Costi

Gli scanner sono gratuiti. Si paga solo il modello AI, in tre momenti:

| Attività | Modello | Peso sulla spesa |
| --- | --- | --- |
| Valutare quali problemi correggere | Haiku | quasi nullo |
| Scrivere e verificare il fix | Sonnet | la parte principale |
| Bug hunting a rotazione | Opus | il più costoso, con un tetto suo |

Tetti di default, tutti modificabili in `budget:`:

- **$3 a notte** in tutto (circa $90 al mese al massimo);
- **$0,80** per singolo fix;
- **$1 a notte** per il bug hunting;
- **3 MR a notte** al massimo;
- **2 tentativi** per lo stesso problema, poi passa a una persona.

`autofix status` e la dashboard mostrano la spesa del mese e la proiezione a fine mese, con un
avviso se supera i crediti. **A crediti finiti** la notte si ferma subito e senza danni; le
run riprendono quando arrivano i crediti del mese successivo. Non ci sono addebiti a sorpresa,
purché la ricarica automatica sia spenta sulla Console Anthropic.

## Manutenzione

- **Aggiornare gli scanner (ogni settimana).** La CI ripubblica l'ambiente isolato ogni lunedì
  mattina con scanner e database delle vulnerabilità aggiornati. Per portarlo sulla VM, da
  cron il lunedì:

  ```
  0 8 * * 1  cd /opt/autofix && ./scripts/update.sh >> /var/log/autofix-update.log 2>&1
  ```

  Se costruisci in locale, usa invece `./scripts/rebuild-sandbox.sh`.

- **Aggiornare Autofix.** `git pull` (per compose e script aggiornati), poi
  `./scripts/update.sh`: aggiorna anche la dashboard se è in uso. Per tornare a una versione
  precedente, imposta `AUTOFIX_TAG=sha-<commit>` nel file `.env` e rilancia lo script.
- **Backup.** Lo stato (problemi già visti, MR aperte, storico e spesa) è nel file
  `/var/lib/autofix/autofix.sqlite3`. Copialo quando Autofix non sta girando, per esempio di
  pomeriggio:

  ```bash
  sqlite3 /var/lib/autofix/autofix.sqlite3 ".backup '/backup/autofix-$(date +%F).sqlite3'"
  ```

- **Spazio disco.** Le copie dei repo vengono cancellate a fine lavoro. Restano solo report e
  diff delle run in `/var/lib/autofix/work/`, che puoi ripulire dopo qualche settimana.

## Problemi comuni

**`status` dice che manca un segreto.** Controlla che il file esista in `secrets/` e non sia
vuoto, poi `docker compose restart orchestrator`.

**`autofix tokens` va in timeout, ma dalla VM GitLab risponde.** Spesso è l'MTU: su reti
overlay (Proxmox SDN, VXLAN, alcuni cloud) l'interfaccia della VM ha MTU 1450 e le reti
Docker 1500. Controlla con `ip link`; se è più basso di 1500, imposta lo stesso valore per
Docker in `/etc/docker/daemon.json`:

```json
{"mtu": 1450, "default-network-opts": {"bridge": {"com.docker.network.driver.mtu": "1450"}}}
```

poi `systemctl restart docker`, `docker compose down` e `./scripts/update.sh` (le reti si
ricreano con il nuovo MTU).

**Errore di certificato verso GitLab.** L'istanza usa una CA interna: vedi il passo 4
dell'installazione.

**Stanotte non è arrivata nessuna MR.** È normale se non c'erano problemi nuovi, se il triage li
ha giudicati falsi positivi o se i fix non hanno superato la verifica. Il motivo è nel report
della notte (`autofix status`, dashboard o `report.md`).

**Il token è scaduto o sta per scadere.** `autofix status` e la pagina Impostazioni della
dashboard avvisano un mese prima. Crea un token nuovo (passo 2), sovrascrivi il suo file in
`secrets/gitlab_tokens/` e controlla con `autofix tokens`. Un token non valido ferma solo i
repo che copre.

**Un repo risulta "non coperto da nessun token".** Aggiungi in `gitlab.tokens` un token il cui
`scope` contenga il gruppo o il progetto, e il file con il suo valore in `secrets/gitlab_tokens/`.

**Un repo non viene mai controllato.** Controlla con `autofix repos list` che sia attivo: le
proposte dell'autodiscovery restano ferme finché non le approvi.

**Non riesco a entrare nella dashboard.** La tua email deve essere in `web.allowed_users` ed
essere verificata su GitLab. Dopo una modifica: `docker compose --profile web restart web`.

## Documentazione tecnica

- [Architettura](docs/architecture.md): come funziona una notte, componenti, budget, modelli,
  autodiscovery, dashboard.
- [Sicurezza](docs/security.md): modello di minaccia, contromisure, rischi residui.
- [Configurazione](docs/configuration.md): riferimento completo di `config.yaml` e dei segreti.
- [Go-live](docs/go-live.md): checklist dettagliata per la messa in produzione.
- [Sviluppo](docs/development.md): ambiente di sviluppo, test, frontend, dati demo.
- [CHANGELOG](CHANGELOG.md).
