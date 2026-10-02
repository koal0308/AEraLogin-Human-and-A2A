# ========================================
# TELEGRAM GROUP ID FINDEN - ANLEITUNG
# ========================================

## 🎯 EMPFOHLENE METHODE: @RawDataBot

1. Gehe zu Telegram und öffne deine Gruppe
2. Suche nach @RawDataBot
3. Füge @RawDataBot zur Gruppe hinzu
4. Der Bot sendet SOFORT alle Gruppen-Informationen
5. Suche nach: "id": -1001234567890
6. Das ist deine GROUP ID!

Beispiel Ausgabe von @RawDataBot:
```json
{
  "message_id": 123,
  "from": {...},
  "chat": {
    "id": -1001234567890,    <-- DAS IST DEINE GROUP ID!
    "title": "Meine Gruppe",
    "type": "supergroup"
  }
}
```

## 📝 ALTERNATIVE: Via Telegram Web

1. Öffne https://web.telegram.org
2. Klicke auf deine Gruppe
3. Schau in die Browser-URL
4. Format: web.telegram.org/k/#-1001234567890
5. Die Zahl nach # ist deine Group ID

## 🤖 ALTERNATIVE: Via Bot-Updates

```bash
# Führe diesen Befehl aus (ersetze YOUR_BOT_TOKEN):
curl "https://api.telegram.org/botYOUR_BOT_TOKEN/getUpdates"

# Suche in der Antwort nach:
# "chat":{"id":-1001234567890
```

## ⚠️ WICHTIG:

- Group IDs für Supergroups beginnen mit -100
- Format: -1001234567890 (13 Ziffern)
- NICHT die User ID oder Bot ID verwechseln!

## 🔧 VERWENDUNG IN AERALOGIN:

Nach dem du die Group ID hast:

1. Gehe zu deinem User Dashboard
2. Klicke auf "NFT-Gated Community Gate"
3. Wähle "Advanced Security (Bot Setup)"
4. Trage die Group ID ein (mit -100 Präfix!)
5. Beispiel: -1001234567890
