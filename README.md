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
| 1 | Immagine sandbox, `DockerSandbox`, parser degli scanner, proxy, checkout con git hardening | da fare |
| 2 | CVE end-to-end: triage, fix agent, verifica, MR (`GitLabVCS`, `AnthropicLLM`) | da fare |
| 3 | Finding SAST | da fare |
| 4 | Bug hunting a rotazione sul diff recente | da fare |

## Come funziona una notte

Per ogni repo, in sequenza (un repo che fallisce non blocca gli altri):

1. checkout con il token del bot, git dir separata dalla working tree;
2. scan nel sandbox, senza token;
3. dedup contro lo storico: si scartano finding ignorati, già con MR aperta, già passati a un
   umano o falliti troppe volte. Una MR chiusa senza merge conta come rifiuto;
4. le CVE dello stesso package diventano un solo task (un solo bump);
5. triage (Haiku): una chiamata per repo, risposta JSON forzata: `fix`, `ignore`, `needs_human`.
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
├── adapters/      sqlite_store (fase 0); gitlab, docker, scanner, anthropic (fasi 1-2)
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
Un modello senza prezzo in config blocca l'avvio.

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
uv run maxtac --config config.yaml run --repo alex/ecs2 --dry-run   # dalla fase 2
```

Comandi:

- `maxtac run [--repo X] [--dry-run]`: esegue subito; in dry-run niente push né MR, diff su disco;
- `maxtac patrol`: resta in esecuzione e lancia la run all'ora configurata (`schedule`);
- `maxtac status`: spesa del mese, finding tracciati, MR aperte.

In fase 0 `run` e `patrol` escono con codice 3: gli adapter reali arrivano nelle fasi 1 e 2.

## Temi di presentazione

L'output per l'operatore (CLI, report a schermo, in futuro la dashboard) può usare un tema
alternativo, scelto per utente in `ui.themes`; il default è `neutral`. Il tema cambia solo le
parole a schermo: branch, label, commit, testo delle MR e report su disco restano sempre neutri.
