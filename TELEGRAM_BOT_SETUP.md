# 🤖 Telegram Bot Setup für Echte Einmal-Links

## Übersicht

Der Telegram Bot ermöglicht es, **echte Einmal-Links** zu generieren, die:
- ✅ Nur von **EINER Person** verwendet werden können
- ✅ Nach 5 Minuten automatisch ablaufen
- ✅ **Kein Kopieren und Weiterleiten** mehr möglich!

---

## 🚀 Schnellstart

### 1. Bot bei @BotFather erstellen

1. Öffne Telegram und suche nach `@BotFather`
2. Schreibe `/newbot`
3. Wähle einen Namen (z.B. `VEra Community Bot`)
4. Wähle einen Username (z.B. `vera_community_bot`)
5. **Kopiere den Token** (sieht so aus: `7123456789:AAHqP...xyz`)

### 2. Bot als Admin zur Gruppe hinzufügen

1. Öffne deine private Telegram Gruppe
2. Gehe zu **Gruppeninfo → Administratoren → Admin hinzufügen**
3. Suche nach deinem Bot (@vera_community_bot)
4. **WICHTIG:** Aktiviere die Berechtigung **"Nutzer über Links einladen"**
5. Speichern

### 3. Group ID herausfinden

**Option A: Web Telegram**
1. Öffne die Gruppe in [web.telegram.org](https://web.telegram.org)
2. Die URL zeigt die ID: `https://web.telegram.org/k/#-1001234567890`
3. Die Group ID ist: `-1001234567890` (mit dem Minus!)

**Option B: Bot API**
1. Schreibe eine Nachricht in die Gruppe
2. Rufe auf: `https://api.telegram.org/bot<TOKEN>/getUpdates`
3. Suche nach `"chat":{"id":-1001234567890...}`

### 4. In .env eintragen

```env
# Telegram Bot für echte Einmal-Links
TELEGRAM_BOT_TOKEN=7123456789:AAHqP...xyz
TELEGRAM_GROUP_ID=-1001234567890
```

### 5. Server neustarten

```bash
# Im aeralogin Ordner
source venv/bin/activate
pkill -f "uvicorn.*8840"
python server.py &
```

### 6. Status prüfen

```bash
curl http://localhost:8840/api/telegram-bot/status
```

Erwartete Antwort bei erfolgreicher Konfiguration:
```json
{
  "configured": true,
  "ready": true,
  "bot_username": "@vera_community_bot",
  "can_create_one_time_links": true,
  "message": "✅ Bot @vera_community_bot ready!"
}
```

---

## ⚙️ Wie es funktioniert

```
┌─────────────────┐
│  User verifies  │
│  with MetaMask  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ /api/telegram/  │
│    invite       │
└────────┬────────┘
         │
         ▼
┌─────────────────────────────────────┐
│  Telegram Bot configured?           │
│                                     │
│  YES → Create one-time link         │
│        (member_limit=1, 5min expiry)│
│                                     │
│  NO → Fallback to static link       │
│       from TELEGRAM_INVITE_LINK     │
└────────┬────────────────────────────┘
         │
         ▼
┌─────────────────┐
│ One-time Token  │
│ generated       │
│ (30 sec valid)  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ User clicks     │
│ redirect link   │
└────────┬────────┘
         │
         ▼
┌─────────────────────────────────────┐
│ HTTP 302 Redirect to Telegram       │
│                                     │
│ Link works ONCE and expires in 5min │
└─────────────────────────────────────┘
```

---

## 🔐 Sicherheitsvorteile

| Feature | Statischer Link | Bot Einmal-Link |
|---------|----------------|-----------------|
| Kopieren möglich | ✅ Ja | ❌ Nein |
| Weiterleiten | ✅ Ja | ❌ Nein |
| Multi-Use | ✅ Unbegrenzt | ❌ 1x |
| Gültigkeit | ♾️ Für immer | ⏰ 5 Minuten |
| Tracking | ❌ Nein | ✅ Ja |

---

## 🔧 Fehlerbehebung

### "Bot lacks invite permissions"
→ Bot ist nicht Admin oder hat keine Invite-Berechtigung
→ Lösung: Bot als Admin hinzufügen mit "Nutzer einladen" Recht

### "TELEGRAM_GROUP_ID not set"
→ Group ID fehlt in .env
→ Lösung: ID herausfinden (siehe Schritt 3) und eintragen

### "Connection error"
→ Netzwerkproblem oder ungültiger Token
→ Lösung: Token prüfen, ggf. bei @BotFather neu generieren

### Bot funktioniert nicht, aber statische Links schon
→ System fällt automatisch auf TELEGRAM_INVITE_LINK zurück
→ Das ist das gewollte Fallback-Verhalten

---

## 📋 Checkliste

- [ ] Bot bei @BotFather erstellt
- [ ] Token in .env unter `TELEGRAM_BOT_TOKEN` eingetragen
- [ ] Bot als Admin zur Gruppe hinzugefügt
- [ ] "Nutzer über Links einladen" aktiviert
- [ ] Group ID in .env unter `TELEGRAM_GROUP_ID` eingetragen
- [ ] Server neugestartet
- [ ] `/api/telegram-bot/status` zeigt `"ready": true`

---

## 🧪 Manueller Test

```bash
# Bot-Status prüfen
curl http://localhost:8840/api/telegram-bot/status

# Einmal-Link direkt testen (mit Python)
cd /var/local/aeralogin+imp.../aeralogin+implement/aeralogin
source venv/bin/activate
python telegram_bot_service.py
```

---

*VEra-Resonance © 2025*
