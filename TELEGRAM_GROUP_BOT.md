# 🤖 Telegram Group Bot - Setup Guide

## Übersicht

Der **Telegram Group Bot** verwaltet Schreibrechte und Polls basierend auf dem Resonance Score der User.

### Features

| Feature | Beschreibung |
|---------|--------------|
| 🔐 **Score-Gated Access** | Schreibrechte nur ab bestimmtem Score |
| 📊 **Score-Gated Polls** | Abstimmungen mit Mindest-Score |
| ⏱️ **Session-Management** | Automatische Session-Verlängerung |
| 🔒 **Privacy First** | Keine Wallet-Adressen im Bot! |
| 🎛️ **Admin-Befehle** | Konfigurierbar per Telegram |

### Sicherheitsarchitektur (9/10)

```
┌─────────────────────────────────────────────────────────────────┐
│                     PRIVACY BY DESIGN                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ❌ NICHT im Bot gespeichert:                                   │
│     • Wallet-Adressen                                           │
│     • Exakter Resonance Score                                   │
│     • Transaktionsdaten                                         │
│                                                                 │
│  ✅ NUR im Bot (RAM, temporär):                                 │
│     • Telegram User ID                                          │
│     • Capabilities (z.B. "write", "poll_60")                    │
│     • Session-Ablaufzeit                                        │
│                                                                 │
│  🔐 Sicherheitsmaßnahmen:                                       │
│     • HMAC-signierte Capability Tokens                          │
│     • Sessions nur im RAM (bei Neustart weg)                    │
│     • Kurzes Zeitfenster (2 Min) für Token-Claim                │
│     • Score wird in Capabilities umgewandelt (nicht gespeichert)│
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Setup

### 1. Zweiten Bot bei @BotFather erstellen

```
1. Öffne @BotFather in Telegram
2. /newbot
3. Name: "AEra Group Manager" (oder ähnlich)
4. Username: z.B. "AEraGroupManager_bot"
5. Kopiere den Token
```

**Wichtig:** Dies ist ein SEPARATER Bot vom Gate-Bot!
- **Gate Bot** (`TELEGRAM_BOT_TOKEN`): Erstellt Invite-Links
- **Group Bot** (`TELEGRAM_GROUP_BOT_TOKEN`): Verwaltet Gruppe

### 2. Bot zur Gruppe hinzufügen

```
1. Öffne deine Telegram-Gruppe
2. Gruppe bearbeiten → Administratoren → Administrator hinzufügen
3. Suche nach deinem Bot (@AEraGroupManager_bot)
4. Aktiviere diese Rechte:
   ✅ Nachrichten löschen
   ✅ Nutzer sperren
   ✅ Nutzer einladen
   ✅ Nachrichten anheften
```

### 3. .env konfigurieren

Füge zu deiner `.env` hinzu:

```env
# Group Bot (separater Bot!)
TELEGRAM_GROUP_BOT_TOKEN=1234567890:ABCdefGHIjklMNOpqrsTUVwxyz

# Gleiche Gruppe wie Gate Bot
TELEGRAM_GROUP_ID=-1001234567890

# HMAC Secret für Token-Signatur (optional, nutzt TOKEN_SECRET als Fallback)
TELEGRAM_BOT_HMAC_SECRET=your-secret-key-here
```

### 4. Dependencies installieren

```bash
pip install python-telegram-bot>=20.0
```

### 5. Bot starten

**Option A: Standalone**
```bash
python telegram_group_bot.py
```

**Option B: Mit Server (empfohlen)**

Der Bot startet automatisch mit dem Server wenn konfiguriert.
(TODO: Integration in server.py startup)

---

## Befehle

### Für alle User

| Befehl | Beschreibung |
|--------|--------------|
| `/help` | Zeigt Hilfe |
| `/mystatus` | Session-Status anzeigen |
| `/verify` | Link zur Verifizierung |

### Für Admins

| Befehl | Beschreibung | Beispiel |
|--------|--------------|----------|
| `/setminscore <score>` | Mindest-Score für Schreibrechte | `/setminscore 55` |
| `/settimeout <min>` | Session-Timeout in Minuten | `/settimeout 60` |
| `/setwelcome <text>` | Begrüßungstext ändern | `/setwelcome Willkommen!` |
| `/status` | Bot-Status anzeigen | `/status` |
| `/poll <frage> \| <opt1> \| <opt2> [min_score]` | Poll erstellen | `/poll Welche Farbe? \| Rot \| Blau 60` |
| `/closepoll <id>` | Poll schließen | `/closepoll abc123` |

---

## Ablauf für User

```
┌─────────────────────────────────────────────────────────────────┐
│                        USER FLOW                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. User geht zu /join-telegram                                 │
│     → Verbindet Wallet                                          │
│     → NFT wird geprüft                                          │
│     → Score wird abgerufen                                      │
│                                                                 │
│  2. Server erstellt:                                            │
│     → One-Time Invite Link (member_limit=1)                     │
│     → Capability Token (basierend auf Score)                    │
│        z.B. Score 65 → ["write", "poll_50", "poll_55", ...]     │
│                                                                 │
│  3. User klickt Link → tritt Gruppe bei                         │
│                                                                 │
│  4. Bot empfängt "new_chat_member" Event                        │
│     → Prüft Invite-Link                                         │
│     → Holt Capabilities für diesen Link                         │
│     → Erstellt Session                                          │
│                                                                 │
│  5. Wenn "write" Capability vorhanden:                          │
│     → Schreibrechte werden aktiviert                            │
│     → Begrüßung wird gesendet                                   │
│                                                                 │
│  6. Session bleibt aktiv solange User aktiv ist                 │
│     → Automatische Verlängerung bei Nachrichten                 │
│     → Warnung 5 Min vor Ablauf                                  │
│                                                                 │
│  7. Session abgelaufen → User muss neu verifizieren             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Poll-System

### Poll erstellen (Admin)

```
/poll Welche Blockchain bevorzugst du? | Ethereum | Base | Polygon 60
```

- Frage und Optionen mit `|` trennen
- Letzte Zahl = Mindest-Score (optional, default: 50)
- Nur User mit Score ≥ 60 können abstimmen

### Abstimmen (User)

1. Auf Poll-Nachricht antworten
2. Nummer der Option eingeben (1, 2, 3...)
3. Bot prüft Capability (`poll_60`)
4. Stimme wird gezählt (oder abgelehnt)

### Poll schließen (Admin)

```
/closepoll abc123
```

→ Zeigt Ergebnisse an

---

## Technische Details

### Capability-System

Statt den Score zu speichern, werden **Capabilities** abgeleitet:

| Score | Capabilities |
|-------|--------------|
| 50 | `write`, `poll_50` |
| 55 | `write`, `poll_50`, `poll_55` |
| 60 | `write`, `poll_50`, `poll_55`, `poll_60` |
| ... | ... |

**Vorteil:** Bot kennt nur Berechtigungen, nicht den genauen Score!

### Session-Struktur (RAM only)

```python
UserSession:
    telegram_id: int
    capabilities: ["write", "poll_50", ...]
    session_start: timestamp
    last_activity: timestamp
    expires: timestamp
```

### HMAC-signierte Tokens

Tokens werden mit HMAC-SHA256 signiert:

```
Token = Base64(payload) + "." + HMAC(payload, secret)

payload = {
    "caps": ["write", "poll_50"],
    "exp": 1702150000,
    "link": "https://t.me/+ABC123"
}
```

→ Manipulation wird erkannt!

---

## Troubleshooting

### Bot reagiert nicht

1. Prüfe `TELEGRAM_GROUP_BOT_TOKEN` in .env
2. Prüfe ob Bot Admin in der Gruppe ist
3. Prüfe Logs: `python telegram_group_bot.py`

### User bekommt keine Schreibrechte

1. Prüfe ob User über Gate-Link beigetreten ist (nicht manuell)
2. Prüfe ob Score ≥ min_score (default: 50)
3. Prüfe ob Token noch gültig war (2 Min Fenster)

### Session läuft sofort ab

1. Prüfe `/settimeout` Einstellung
2. Prüfe ob User aktiv war (Nachrichten verlängern Session)

---

## Dateien

| Datei | Beschreibung |
|-------|--------------|
| `telegram_group_bot.py` | Hauptbot mit allen Features |
| `telegram_bot_service.py` | Gate-Bot + Capability-Integration |
| `server.py` | Backend mit Gate-Endpoints |
| `.env` | Konfiguration (NICHT committen!) |

---

## Zusammenfassung

✅ **Privacy:** Keine Wallet-Adressen im Bot
✅ **Sicherheit:** HMAC-signierte Tokens, RAM-only Sessions
✅ **Benutzerfreundlich:** Automatische Verlängerung, Warnungen
✅ **Flexibel:** Admin-Befehle für Konfiguration
✅ **Score-Gated:** Polls und Schreibrechte nach Score

**Sicherheitsbewertung: 9/10**
