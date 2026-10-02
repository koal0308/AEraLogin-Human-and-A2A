# Phase 0.1 – Human Identity Foundation: Verifikationsbericht

Stand: 2026-10-02 · Code-Stand: `main` @ `d46dbe703b9d` (Merge von Phase 0.1
`c775d0317815` mit Remote-Doku-Commits) · Working Tree sauber.

Alle Ergebnisse unten wurden auf genau diesem Stand **neu ausgeführt**, sofern
nicht ausdrücklich anders vermerkt. Es wird nichts behauptet, was nicht durch
einen Lauf belegt ist.

---

## 1. Welche Tests tatsächlich ausgeführt wurden

| Lauf | Befehl | Ergebnis |
|---|---|---|
| Gesamte pytest-Suite | `python -m pytest tests/ -q` | **716 passed, 3 skipped, 12 xfailed** (vor Phase 0.1: 678 passed) |
| Agent-Suite gesamt | `python -m pytest tests/agent -q` | **492 passed, 3 skipped** |
| Human-Identity-Unit/Migration | `tests/human_identity/test_human_identity.py` | 29 passed (Teil der 38) |
| Human-Identity-Integration (HTTP) | `tests/agent/test_human_identity_integration.py` | 9 passed |
| Negproof Human Identity | `python negproof_human_identity.py` | **13/13 Mutanten gefangen**, Baseline wiederhergestellt |
| Migration auf realer DB-Kopie | siehe Abschnitt 4 | idempotent, 0 Abweichungen |

Zusätzlich auf **identischem Code-Stand** (zwischen diesen Läufen und jetzt
wurden laut Git nur Doku-Dateien gemergt: `LICENSE`, `README.md`,
`docs/ROADMAP.md`, `docs/WHITEPAPER.md`, `docs/PHASE_0_1_MIGRATION_MATRIX.md`)
ausgeführt und grün:

| Lauf | Ergebnis |
|---|---|
| `negproof_a2a_credentials.py` | 29/29 |
| `negproof_a2a_trust.py` | 32/32 |
| `negproof_a2a_gateway.py` | 10/10, restored |
| `negproof_a2a_ratelimit.py` | 7/7, restored |
| `negproof_agent_runtime.py` | 14/14, restored |
| `tools/enrollment_mutation_check.py` | 9/9 killed |
| `aera-agent-security-lab/negproof_external_a2a.py` | 6/6, restored |
| Security-Lab `pytest tests` | 237 passed |
| Security-Lab `src.cli.lab --provider mock` | 26/26 checks |
| `tools/release_live_e2e.py` (isolierter Server, Port 8892) | 114/114 |
| `tools/secret_scan.py` | HIGH findings: 0 |
| `tools/repo_audit.py` | forbidden files: 0 |
| `tools/sync_site_shell.py --check` | keine Änderungen |

**Nicht ausgeführt:** Kein Test gegen die laufende Produktion. Produktion
läuft noch mit Code vor Phase 0.1 (kein Restart erfolgt).

---

## 2. Ist die komplette bestehende Agent-Suite noch grün?

**Ja.** Einzelläufe pro Datei (`tests/agent/`):

| Datei | Ergebnis |
|---|---|
| test_a2a_credentials.py | 87 passed |
| test_a2a_gateway.py | 61 passed |
| test_a2a_gateway_ratelimit.py | 36 passed |
| test_a2a_trust.py | 71 passed |
| test_agent_enrollment.py | 44 passed |
| test_agent_layer.py | 41 passed, 1 skipped |
| test_agent_runtime.py | 55 passed |
| test_crypto.py | 14 passed |
| test_dashboard_agents.py | 54 passed, 2 skipped |
| test_e2e.py | 1 passed |
| test_flag_and_secret.py | 4 passed |
| test_jti_binding.py | 15 passed |
| test_human_identity_integration.py (neu) | 9 passed |

Die Skips sind dieselben wie vor Phase 0.1 (umgebungsabhängige Tests). An
bestehenden Tests wurde nichts geändert; einzige Anpassung in `tests/agent/conftest.py`:
`wipe_agent_tables` leert zusätzlich die beiden neuen Identity-Tabellen.

---

## 3. Fängt `negproof_human_identity.py` wirklich alle Mutationen?

**Alle 13 definierten Mutanten werden gefangen** (Lauf vom 2026-10-02):

| # | Mutation | Fehlschläge |
|---|---|---|
| 1 | `UNIQUE(provider, provider_subject)` entfernt | 2 |
| 2 | bestehende Bindung nicht nachgeschlagen (neuer Human je Login) | 1 |
| 3 | Race-Verlierer rollt eigenen Human nicht zurück (Waisen) | 1 |
| 4 | `human_id` aus Wallet abgeleitet statt zufällig | 1 |
| 5 | Wallet-Adresse nicht validiert | 11 |
| 6 | Future-Provider (google/github) akzeptiert | 2 |
| 7 | `owner_id`-Mismatch ignoriert | 1 |
| 8 | Wallet-Mismatch ignoriert | 2 |
| 9 | deaktivierte Humans weiter autorisiert | 1 |
| 10 | Migration überschreibt vorhandene `owner_id` | 2 |
| 11 | Migration übernimmt ungültige Wallets | 4 |
| 12 | `create_agent` setzt `owner_id` nicht | 4 |
| 13 | Dashboard prüft `owner_id` nicht | 1 |

Das Skript prüft vor jedem Lauf, dass eine Mutation den Code tatsächlich
ändert (sonst `SKIPPED` → Gesamtergebnis rot), und stellt danach den
Originalzustand wieder her (Baseline 38 passed vor und nach).

**Ehrliche Einschränkung:** „Alle Mutationen“ heißt *alle 13 bewusst gewählten
sicherheitsrelevanten Mutanten*. Eine Negproof beweist nicht, dass *jede
denkbare* Änderung erkannt wird. Bei der Erstellung überlebte zunächst Mutant 4;
der Test wurde daraufhin verschärft – genau dafür existiert die Negproof.
Mutanten mit 1 Fehlschlag hängen an genau einem Test; sie sind gefangen, aber
dünn abgedeckt.

---

## 4. Funktioniert die DB-Migration auf einer realen bestehenden DB?

**Ja – geprüft auf einer Kopie der echten Produktions-DB `aera.db`.** Die
Quelle wurde nur lesend (`mode=ro`) über die SQLite-Backup-API kopiert; die
Produktions-DB wurde nicht verändert.

Ausgangslage der Kopie: keine `human_*`-Tabellen, keine Spalte `agents.owner_id`.

| Prüfung | Ergebnis |
|---|---|
| 1. Lauf | 214 Wallets gefunden, 214 Humans angelegt, 0 ungültig, **107 Agents verknüpft** |
| 2. Lauf (Idempotenz) | 0 Humans angelegt, 0 Agents verknüpft |
| Agents ohne `owner_id` | 0 von 107 |
| doppelte Bindungen `(provider, subject)` | 0 |
| Humans ohne Bindung (Waisen) | 0 |
| `owner_id` passt nicht zu `owner_wallet` | 0 |
| bestehende Agent-Spalten (id, wallet, status, caps, label, timestamps) | unverändert (Hash-Vergleich) |
| `agent_keys`, `users`, `agent_enrollments`, `owner_challenges`, `a2a_peer_credentials` | unverändert (Hash-Vergleich) |
| `PRAGMA integrity_check` | ok |

Hinweis: Die DB ist seit dem ersten Test gewachsen (damals 101 Agents/208
Wallets, jetzt 107/214) – beide Läufe waren vollständig.

`PRAGMA foreign_key_check` meldet eine Verletzung in der **Alt-Tabelle
`owner_gate_configs_old`** (→ `users`). Diese Tabelle wird von Phase 0.1 nicht
angefasst; der Befund ist vorbestehend und unabhängig von der Migration.

Die Migration ist zusätzlich gegen eine leere DB und gegen minimale
Test-Schemata (`agents` mit nur 2 Spalten, ungültige Wallets wie `0xOwner`)
getestet.

---

## 5. Ist `agent_runtime` wirklich unverändert kompatibel?

**Ja.**

- **Code:** `agent_runtime/` ist seit dem Stand vor Phase 0.1 (`5473c0c4a17d`)
  laut Git-Diff **byte-identisch** – keine Datei geändert.
- **Protokoll:** Agent-JWT (`agent/tokens.py`, Claim `owner_wallet`),
  Challenge/Authenticate, Enrollment-Claim/Status/Complete und der signierte
  Owner-Challenge-Payload sind unverändert. `owner_id` wird von keinem
  Runtime-Pfad gelesen oder benötigt.
- **Tests:** `test_agent_runtime.py` 55 passed, `test_agent_enrollment.py`
  44 passed, `negproof_agent_runtime.py` 14/14, E2E 114/114 (inkl.
  Enrollment → Runtime → Authentifizierung).
- **Bestehende Agents:** behalten `agent_id`, Keys und `owner_wallet`;
  Integrationstest `test_existing_agent_still_authenticates` belegt, dass ein
  Agent nach Verknüpfung weiterhin authentifiziert.

---

## 6. Funktioniert A2A weiterhin zu 100 %?

**Alle vorhandenen A2A-Prüfungen sind grün; `a2a_gateway/` ist byte-identisch
zum Stand vor Phase 0.1.**

- Tests: credentials 87, gateway 61, ratelimit 36, trust 71 – alle passed.
- Negproofs: 29/29, 32/32, 10/10, 7/7; extern 6/6.
- E2E 114/114.
- Agent Card: `owner_id` / `did:aera:human` erscheinen nicht in öffentlichen
  Antworten (Test `test_public_agent_view_does_not_expose_owner_id`); die
  bestehende Card-Sperrliste (`owner_wallet`, `0x`) ist unverändert aktiv.

**Einschränkung:** „100 %“ kann nur für die vorhandene Testabdeckung gesagt
werden. Ein Live-Test gegen Produktion ist nicht erfolgt, weil Phase 0.1 noch
nicht deployt ist.

---

## 7. Gibt es noch sicherheitsrelevante Ownership-Pfade, die nur `owner_wallet` nutzen?

**Ja, mehrere – aber keiner ist heute ausnutzbar.**

**Begründung:** In Phase 0.1 gibt es nur den Wallet-Provider. Eine Wallet ist
1:1 und unveränderlich an genau einen Human gebunden; jeder neue Agent bekommt
`owner_id` aus genau dieser Wallet, und alle Bestandsagents sind konsistent
verknüpft (0 Mismatches). Damit ist „`owner_wallet` stimmt“ heute
**gleichwertig** zu „`owner_id` stimmt“. Ein Abweichen wäre nur durch direkten
DB-Schreibzugriff möglich.

### Pfade, die nur `owner_wallet` prüfen

| Pfad | Datei | Prüfung heute |
|---|---|---|
| Key hinzufügen `POST /api/agents/{id}/keys` | `agent/routes.py:305` | Owner-Signatur + `owner_wallet` |
| Key rotieren `POST /{id}/keys/rotate` | `agent/routes.py:346` | dito |
| Key widerrufen `DELETE /{id}/keys/{key}` | `agent/routes.py:396` | dito |
| Agent widerrufen `DELETE /{id}` | `agent/routes.py:430` | dito |
| Capabilities `PATCH /{id}/capabilities` | `agent/routes.py:463` | dito |
| Enrollment ansehen/abbrechen/abschließen | `agent/enrollment.py:270` (`_owned_row`) | `owner_wallet` aus Session bzw. Signatur |
| Dashboard Enrollments | `server.py` `/api/dashboard/agents/enrollments*` | Session-Wallet |
| A2A-Credentials anlegen/widerrufen | `a2a_gateway/credentials.py:443` (`verify_owns_agents`) | `lower(owner_wallet)` |
| Dashboard A2A-Credentials / Peer-Trust | `server.py` `/api/dashboard/a2a-*` | Session-Wallet |
| Agent-JWT-Verifikation | `agent/tokens.py:165` | Claim `owner_wallet` == DB |

Bereits auf `owner_id` umgestellt (zusätzlich zur Wallet): Dashboard-Liste und
-Detail (`/api/dashboard/agents`, `/api/dashboard/agents/{id}`) sowie
Agent-Erzeugung (`create_agent`).

### Bewertung

1. **Kein aktuelles Sicherheitsloch.** Alle Pfade verlangen eine
   serverseitig verifizierte Wallet (Owner-Signatur oder Session-JWT); keiner
   vertraut einer Client-Angabe.
2. **Inkonsistenz – Status `disabled`:** Ein deaktivierter Human verliert
   heute nur Dashboard-Sicht und Agent-Erzeugung. Die mutierenden Agent-Routen,
   Enrollment und A2A-Credentials prüfen den Human-Status nicht. Da es in
   Phase 0.1 **keinen Code-Pfad zum Deaktivieren** gibt, ist das nicht
   ausnutzbar – muss aber vor Einführung einer Sperrfunktion geschlossen werden.
3. **Inkonsistenz – manipulierte `owner_id`:** Bei einem DB-seitig
   abweichenden `owner_id` verweigert das Dashboard den Zugriff, die
   mutierenden Routen erlauben ihn weiter (sie kennen nur die Wallet).
   Voraussetzung wäre DB-Schreibzugriff.
4. **Wird relevant, sobald** (a) ein Human mehrere Provider/Wallets haben kann,
   (b) eine Wallet einem anderen Human zugeordnet werden kann (Recovery,
   Wallet-Wechsel) oder (c) Humans gesperrt werden können. Dann müssen alle
   Pfade der Tabelle über `identity.authorization.owns_agent()` (prüft Wallet
   **und** `owner_id`, Status aktiv) laufen.

### Empfehlung für die nächste Phase (nicht umgesetzt)

- Die 5 mutierenden Routen in `agent/routes.py` sowie `verify_owns_agents`
  und `_owned_row` auf eine gemeinsame Prüfung umstellen:
  Owner-Signatur bzw. Session → Wallet → aktiver Human → `owns_agent()`.
- Der signierte Owner-Challenge-Payload und das Agent-JWT können dabei
  unverändert bleiben (Wallet bleibt der Beweis; `owner_id` wird nur
  serverseitig nachgeschlagen).
- Zu jedem umgestellten Pfad einen Mutanten in `negproof_human_identity.py`
  ergänzen.

---

## 8. Offene Punkte außerhalb von Phase 0.1

- Produktion nicht neu gestartet; Phase 0.1 und die Release-Audit-Fixes
  (S-03, Gateway-`request_id`, `/resonance` 404) sind dort noch nicht live.
- Secret-Rotation nach der früheren öffentlichen `.env`/`aera.db`-Exposition
  steht weiterhin aus (inkl. `ADMIN_PRIVATE_KEY`, `BACKEND_PRIVATE_KEY`).
- Implementierung noch nicht formal gegen
  `docs/PHASE_0_1_MIGRATION_MATRIX.md` abgeglichen (Datei kam erst mit dem
  Merge in das lokale Repo).
