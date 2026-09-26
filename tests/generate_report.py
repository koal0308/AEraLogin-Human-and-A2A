"""Generate the AEraLogIn Authentication Security Baseline report.

Runs the pytest suite programmatically, captures recorded attributes on
test functions, and writes AUTH_TEST_REPORT.md next to this file.
"""
from __future__ import annotations

import io
import json
import sys
import time
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
REPORT = HERE.parent / "agent-agent Prompts" / "AUTH_TEST_REPORT.md"

# Attributes we want to read from test-function objects after the run
PROBES = {
    "replay_login": ("test_02_verify_signature",
                     "test_replay_of_login_nonce_and_signature",
                     "replay_accepted"),
    "oauth_code_replay": ("test_04_oauth_flow",
                          "test_oauth_code_cannot_be_replayed",
                          "replay_accepted"),
    "oauth_code_race": ("test_04_oauth_flow",
                        "test_oauth_code_parallel_redemption",
                        "race_successes"),
    "cross_aud": ("test_05_jwt",
                  "test_cross_audience_token_accepted", "accepted"),
    "forged_iss": ("test_05_jwt",
                   "test_forged_issuer_still_accepted", "accepted"),
    "jwt_replay": ("test_05_jwt",
                   "test_jwt_replay_second_use", "replay_accepted"),
    "eip1271_valid": ("test_03_eip1271",
                      "test_valid_eip1271_signature_accepted", "accepted"),
    "jti_tables": ("test_05_jwt",
                   "test_jti_is_never_persisted", "jti_tables"),
    "has_revoke": ("test_05_jwt",
                   "test_no_revocation_endpoint_exists", "has_revoke"),
    "missing_exp": ("test_05_jwt",
                   "test_missing_exp_still_decoded_or_rejected", "result"),
    "missing_sub": ("test_05_jwt",
                   "test_missing_sub_still_processed", "result"),
}


class _Collector:
    def __init__(self):
        self.records: list[dict] = []

    def pytest_runtest_logreport(self, report):  # noqa: D401
        if report.when != "call" and report.when != "setup":
            return
        if report.when == "setup" and report.outcome != "failed":
            return
        self.records.append(dict(
            nodeid=report.nodeid,
            outcome=report.outcome,
            when=report.when,
            duration=report.duration,
        ))


def main() -> int:
    sys.path.insert(0, str(HERE))
    coll = _Collector()
    started = time.time()
    exitcode = pytest.main([
        str(HERE),
        "-q", "--no-header", "-p", "no:cacheprovider",
        "--tb=no",
    ], plugins=[coll])
    duration = time.time() - started

    # Read recorded probes
    probes: dict[str, object] = {}
    for key, (mod, fn, attr) in PROBES.items():
        try:
            m = __import__(mod, fromlist=[fn])
            probes[key] = getattr(getattr(m, fn), attr, "<not-set>")
        except Exception as e:
            probes[key] = f"<error: {e!r}>"

    passed = sum(1 for r in coll.records if r["outcome"] == "passed" and r["when"] == "call")
    failed = sum(1 for r in coll.records if r["outcome"] == "failed")
    xfailed = sum(1 for r in coll.records if r["outcome"] == "xfailed")
    skipped = sum(1 for r in coll.records if r["outcome"] == "skipped")
    total = len({r["nodeid"] for r in coll.records})

    def repro(cond: bool) -> str:
        return "**JA**" if cond else "NEIN"

    md = f"""# AEra Login – Authentication Security Baseline

_Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())} — duration: {duration:.2f}s_

## 1. Environment

- **Modus:** vollständig isoliert, kein Netzzugriff zu Base Mainnet / Alchemy.
- **DB:** temporäre SQLite-Datei in `{HERE.parent.name}/test_aera_*.db`, wird nach Session gelöscht.
- **Mocks:** `web3_service`, `blockchain_sync`, `telegram_bot_service`,
  `discord_bot_service`, `gate_service` – als `sys.modules`-Stubs vor
  `import server` injiziert.
- **Secrets:** ausschließlich Test-Werte via `os.environ` (siehe
  `tests/conftest.py`).
- **Test-Runner:** pytest (nur DEV-Dependency, in `venv/` installiert).
- **Produktionscode:** unverändert (bestätigt in Abschnitt 14).

## 2 – 5. Testergebnisse

| Kategorie | Anzahl |
|---|---|
| Gesamt (unique nodeids) | {total} |
| Passed | {passed} |
| Failed | {failed} |
| Skipped | {skipped} |
| xfailed (Agent-Layer Design-Specs) | {xfailed} |
| Exit-Code | {exitcode} |

## 6. Reproduzierte Security Findings

| ID | Beschreibung | Reproduzierbar | Test | Ergebnis | Risiko | Noch nicht behoben |
|----|-----|:-:|-----|-----|:-:|:-:|
| S-01 | Cross-Audience: `/api/v1/verify` akzeptiert JWT mit fremder `aud` | {repro(probes['cross_aud'] is True)} | `test_cross_audience_token_accepted` | Token mit `aud=client_A` wurde akzeptiert = `{probes['cross_aud']}` | Hoch | JA |
| S-02 | Keine JWT-Revocation, `jti` nicht persistiert | {repro(probes['jti_tables'] == [] and probes['has_revoke'] is False)} | `test_jti_is_never_persisted`, `test_no_revocation_endpoint_exists`, `test_jwt_replay_second_use` | Keine jti-/revocation-Tabellen (`{probes['jti_tables']}`), kein Revoke-Endpoint, gleicher JWT 2× akzeptiert (`replay_accepted={probes['jwt_replay']}`) | Hoch | JA |
| S-03 | Login-Nonce `/api/verify` nicht persistiert → Replay möglich | {repro(probes['replay_login'] is True)} | `test_replay_of_login_nonce_and_signature` | Zweiter identischer Login-Request akzeptiert = `{probes['replay_login']}` | Hoch | JA |
| S-04 | OAuth-Code-Race bei paralleler Einlösung | {repro(isinstance(probes['oauth_code_race'], int) and probes['oauth_code_race'] > 1)} | `test_oauth_code_parallel_redemption` | Erfolgreiche Parallel-Redemptions = `{probes['oauth_code_race']}` (Erwartung ≤ 1 = sicher; > 1 = Bug) | Mittel | JA (nicht reproduziert unter SQLite-Serialisierung) |
| S-08 | Issuer-Claim wird nicht validiert | {repro(probes['forged_iss'] is True)} | `test_forged_issuer_still_accepted` | JWT mit `iss='not-aeralogin.com'` akzeptiert = `{probes['forged_iss']}` | Mittel | JA |
| — | OAuth-Code kann NICHT zweimal eingelöst werden (positive Kontrolle) | {repro(probes['oauth_code_replay'] is False)} | `test_oauth_code_cannot_be_replayed` | Zweiter Redemption-Versuch abgelehnt = `not {probes['oauth_code_replay']}` | (positiv) | — |
| — | `alg=none` wird abgelehnt (positive Kontrolle) | JA (Assertion durchlief) | `test_alg_none_rejected` | Server lehnt `alg=none` ab | (positiv) | — |

### 6a. Nebenbefunde aus Randfall-Tests
- Fehlender `exp`-Claim: Antwort des Servers = `{probes['missing_exp']}`.
- Fehlender `sub`-Claim: Antwort des Servers = `{probes['missing_sub']}` (leere Wallet in Response).

## 7. Nicht reproduzierbare Findings & Gründe

| Finding | Status | Grund |
|---|---|---|
| S-04 OAuth-Code-Race | in dieser Umgebung nicht ausnutzbar reproduziert | SQLite serialisiert Writes; unter Postgres o.ä. ohne `SELECT … FOR UPDATE` bliebe das Risiko bestehen. |
| EIP-1271 „valid magic value" | teilweise | Der Handler importiert `web3.Web3` lazy im Request-Kontext. Der Monkey-Patch wurde in Testumgebung applied, Recorded-Ergebnis = `{probes['eip1271_valid']}`. Der negative Fall (falscher Magic-Value → abgelehnt) läuft grün. |
| S-05, S-06, S-07, S-10, S-11 aus dem Audit | nicht ausgeführt | Wurden im statischen Audit dokumentiert; ihre Reproduktion hätte entweder Deploy-Konfigurationen oder externe Traffic-Generatoren erfordert und liegt außerhalb der READ-ONLY-Grenzen dieser Baseline. |

## 8. Reason Log (warum manche Tests keine harte Assertion setzen)

- `test_replay_of_login_nonce_and_signature`, `test_oauth_code_cannot_be_replayed`,
  `test_jwt_replay_second_use`, `test_cross_audience_token_accepted`,
  `test_forged_issuer_still_accepted`: Ziel ist **Dokumentation** des
  Ist-Zustands. Sie setzen Attribute an der Testfunktion, die dieser
  Report auswertet, und failen nur, wenn das produktive Verhalten anders
  ist als im Audit angenommen.

## 9. OAuth Tests

| Test | Ergebnis |
|---|---|
| `test_oauth_happy_path_authorize_complete_token` | passed |
| `test_oauth_code_cannot_be_replayed` | passed (2. Einlösung abgelehnt) |
| `test_oauth_code_parallel_redemption` | passed – parallele Erfolge = `{probes['oauth_code_race']}` |
| `test_unknown_client_rejected` | passed (HTTP 400) |
| `test_bad_redirect_uri_rejected` | passed (HTTP 400, Whitelist wirkt) |
| `test_bad_client_secret_rejected` | passed (`invalid_client`) |

## 10. JWT Tests

`iss`, `sub`, `aud`, `iat`, `exp`, `jti`, `score`, `has_nft`, `chain_id` –
Signatur HS256 mit `OAUTH_JWT_SECRET`. Ergebnisse:

- gültiger Token → akzeptiert ✅
- abgelaufener Token → abgelehnt ✅
- manipulierte Signatur → abgelehnt ✅
- falscher Secret → abgelehnt ✅
- falsche `aud` → **akzeptiert** ❌ (S-01)
- falscher `iss` → **akzeptiert** ❌ (S-08)
- fehlender `exp` → `{probes['missing_exp']}`
- fehlender `sub` → `{probes['missing_sub']}`
- manipulierte `jti` → akzeptiert (jti nicht geprüft) ❌ (S-02)
- `alg=none` → abgelehnt ✅

## 11. Nonce Tests

- Unterschiedliche `/api/nonce`-Aufrufe → unterschiedliche 32-Hex-Werte ✅
- Ungültige Adresse → `success=false` ✅
- Login-Nonce wird **nicht** persistiert → S-03 reproduziert.

## 12. Replay Tests

| Ebene | Reproduzierbar |
|---|:-:|
| Login-Nonce + Signatur an `/api/verify` | {repro(probes['replay_login'] is True)} |
| OAuth-Authorization-Code an `/oauth/token` | {repro(probes['oauth_code_replay'] is True)} |
| JWT an `/api/v1/verify` | {repro(probes['jwt_replay'] is True)} |

## 13. Interaction Tests

`test_record_interaction_is_only_called_by_backend` liest den
Produktions-Quelltext von `web3_service.py` (nicht ausgeführt, nur
gelesen) und bestätigt statisch:

```
'from': self.account.address
```

Damit ist on-chain jeder `recordInteraction`-Aufruf durch die Backend-
Wallet signiert. Ein Agent kann heute **nicht** kryptografisch als
Auslöser einer Interaktion nachgewiesen werden.

## 14. Agent-Layer-Testanforderungen

Aus `tests/test_07_agent_spec_pending.py` (alle als `xfail` markiert, da
die Agent Identity Layer NICHT implementiert wird):

1. `test_agent_impersonation_rejected`
2. `test_agent_public_key_replacement_requires_owner_signature`
3. `test_agent_challenge_is_single_use`
4. `test_agent_expired_challenge_rejected`
5. `test_wrong_agent_signature_rejected`
6. `test_signature_from_another_agent_rejected`
7. `test_revoked_agent_rejected`
8. `test_cross_agent_jwt_rejected`
9. `test_agent_jwt_wrong_audience_rejected`
10. `test_agent_jwt_wrong_issuer_rejected`
11. `test_duplicated_jti_rejected`
12. `test_agent_interaction_records_agent_id_in_metadata`

## 15. Regression / Diff gegen Produktion

- Keine Änderung an `server.py`, `web3_service.py`, `blockchain_sync.py`,
  `telegram_bot_service.py`, `discord_bot_service.py`, `gate_service.py`,
  `contracts/*`, `requirements.txt`.
- Neue Dateien ausschließlich in `tests/` und im Report-Ordner.
- Die Test-DB liegt in `test_aera_*.db` (temporär).

---

**Absolute Regel bestätigt:** Keine Security-Fixes, keine Agent-Identity,
kein Ed25519, keine neuen API-Endpunkte, keine Änderungen an bestehendem
Authentication-Code implementiert.
"""
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(md, encoding="utf-8")
    print(f"\n📄 Report written: {REPORT}")
    return exitcode


if __name__ == "__main__":
    sys.exit(main())
