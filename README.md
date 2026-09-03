# coap-security-analysis

Active scanning pipeline for assessing the security posture of IoT devices
exposing CoAP (RFC 7252) on the public Internet.

**Network Security – Università degli Studi di Verona, A.A. 2025/2026**  
Camilla Vivaldi

---

## Descrizione

Lo studio analizza un campione di 909 host estratti da Shodan (`port:5683 "CoAP"`)
tramite una pipeline di scansione attiva in tre fasi sequenziali, ciascuna
progettata per risolvere un'ambiguità lasciata aperta dalla precedente.

| Fase | Script | n host | Output |
|------|--------|--------|--------|
| 1 – Scansione + Resource Discovery | `scanner_shodan.py` | 1000 → 909 | `risultati_massivi_shodan.csv` |
| 2 – Reclassificazione applicativa | `error401.py` | 909 | `classificazione_dettagliata_sicurezza.csv` |
| 3 – Contro-test ICMP differenziato | `contro_test_iniziale.py` | 438 | `risultati_contro_test_icmp.csv` |

Script di analisi secondaria:

| Script | Scopo |
|--------|-------|
| `analisi_avanzata.py` | Fingerprinting ecosistemi vendor |
| `analisi_sicurezza.py` | Reclassificazione endpoint SCONOSCIUTO |
| `mappa_mondiale.py` | Distribuzione geografica del campione |
| `test_autenticazione.py` | Verifica Access Control ecosistema And-Link |
| `ispeziona_config.py` | Resource Discovery approfondito And-Link |
| `ispezione_falle_critiche.py` | PoC Rogue Account Creation |

---

## Requisiti

Python 3.12 — installare le dipendenze con:

```bash
pip install coapthon3==4.0.2 shodan==1.31.0 pandas==2.2.1 matplotlib==3.8.4 requests==2.31.0
```

---

## Configurazione

Creare un file `.env` nella root del progetto con la propria API key Shodan:

```
SHODAN_API_KEY=la_tua_chiave_qui
```

La chiave è leggibile su [account.shodan.io](https://account.shodan.io) → Overview → API Key.
`scanner_shodan.py` la legge tramite `os.getenv("SHODAN_API_KEY")` .

---

## Ordine di esecuzione

```bash
python scanner_shodan.py          # Fase 1 – richiede API key Shodan
python error401.py                # Fase 2 – richiede output Fase 1
python contro_test_iniziale.py    # Fase 3 – richiede output Fase 1
python analisi_avanzata.py        # analisi vendor
python analisi_sicurezza.py       # reclassificazione endpoint SCONOSCIUTO
python mappa_mondiale.py          # distribuzione geografica
```

Le Fasi 2 e 3 leggono `risultati_massivi_shodan.csv` prodotto dalla Fase 1.
Gli script di analisi secondaria leggono entrambi i CSV delle fasi precedenti.

---

## Struttura del repository

```
coap-security-analysis/
├── README.md
├── .gitignore
├── .env                           # NON incluso – contiene API key
├── scanner_shodan.py
├── error401.py
├── contro_test_iniziale.py
├── analisi_avanzata.py
├── analisi_sicurezza.py
├── mappa_mondiale.py
├── test_autenticazione.py
├── ispeziona_config.py
└── ispezione_falle_critiche.py
```

I dataset CSV con gli IP reali, i grafici PNG e il file `.env`
non sono inclusi nel repository.

---

## Note etiche

Le scansioni si sono limitate a richieste GET non autenticate verso
endpoint pubblicamente esposti su Internet, senza alcuna modifica
dello stato dei dispositivi target. 
