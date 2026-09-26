# 🚀 Quick Start Guide - Telegram-Gate Testing

## ⚡ Schnellstart (5 Minuten)

### 1️⃣ Test-Server ist bereits gestartet ✅
```bash
# Server läuft auf Port 8841
curl http://localhost:8841/api/health
```

### 2️⃣ Telegram Gate testen

**Im Browser öffnen:**
```
http://localhost:8841/join-telegram
```

**Was passiert:**
1. Seite lädt → "Connect Wallet" Button
2. Wallet verbinden (MetaMask)
3. System prüft automatisch NFT-Besitz
4. **Mit NFT:** "Join AEra Telegram" Button erscheint
5. **Ohne NFT:** "Mint Identity NFT" Button erscheint

---

## 🧪 API-Tests mit curl

### Test 1: NFT-Check (mit Wallet-Adresse)
```bash
curl -X POST http://localhost:8841/api/check-rft \
  -H "Content-Type: application/json" \
  -d '{"address":"0x984eDaCf233b37FC2E63aBC7168bDE8652f55C65"}'
```

**Erwartete Response (ohne NFT):**
```json
{
  "allowed": false,
  "has_nft": false,
  "reason": "No Identity NFT found",
  "mint_required": true
}
```

**Mit NFT (wenn vorhanden):**
```json
{
  "allowed": true,
  "has_nft": true,
  "token_id": 123,
  "reason": "Identity NFT verified"
}
```

### Test 2: Invite Link (nur mit NFT)
```bash
curl -X POST http://localhost:8841/api/telegram/invite \
  -H "Content-Type: application/json" \
  -d '{"address":"WALLET_MIT_NFT"}'
```

**Response (mit NFT):**
```json
{
  "success": true,
  "invite_link": "https://t.me/+XXXXXX",
  "message": "Welcome to AEra Telegram community!"
}
```

**Response (ohne NFT):**
```json
{
  "success": false,
  "error": "No Identity NFT found",
  "mint_required": true
}
```

---

## 📱 Frontend-Test mit echtem Wallet

### Option A: Lokaler Browser (empfohlen für erste Tests)
```bash
# 1. Im Browser öffnen
http://localhost:8841/join-telegram

# 2. MetaMask installiert haben
# 3. Auf BASE Mainnet Network sein
# 4. "Connect Wallet" klicken
# 5. NFT-Check läuft automatisch
```

### Option B: Port-Forwarding für Remote-Tests
```bash
# Falls du von außen testen willst
ssh -L 8841:localhost:8841 user@server

# Dann im lokalen Browser:
http://localhost:8841/join-telegram
```

---

## 🔧 VERA-Chat Widget testen

### Voraussetzung: VERA-KI Server starten
```bash
cd /var/www/aeralogin+implement/vera-ki-api
nohup python3 server.py > vera_ki.log 2>&1 &

# Prüfen ob läuft
curl http://localhost:8850/
```

### Test im Browser
```bash
# Landing Page mit Chat Widget öffnen
http://localhost:8841/

# Chat-Button sollte unten rechts erscheinen
# Klick öffnet Chat-Popup
```

---

## 📊 Logs überwachen

### Test-Server Logs (live)
```bash
tail -f /var/www/aeralogin+implement/aeralogin/server_test.log
```

### Nach Telegram-Gate Aktivitäten filtern
```bash
grep "TELEGRAM_GATE" /var/www/aeralogin+implement/aeralogin/server_test.log
```

### VERA-Chat Logs
```bash
grep "VERA-Chat" /var/www/aeralogin+implement/aeralogin/server_test.log
```

---

## 🗄️ Datenbank checken

### Telegram Invites abrufen
```bash
sqlite3 /var/www/aeralogin+implement/aeralogin/aera.db \
  "SELECT * FROM telegram_invites ORDER BY invited_at DESC LIMIT 5;"
```

### User mit NFTs prüfen
```bash
sqlite3 /var/www/aeralogin+implement/aeralogin/aera.db \
  "SELECT address, identity_status, identity_nft_token_id FROM users WHERE identity_status='active' LIMIT 5;"
```

---

## 🛠️ Troubleshooting

### Problem: Server antwortet nicht
```bash
# Prozess prüfen
ps aux | grep "python3 server.py"

# Logs prüfen
tail -50 /var/www/aeralogin+implement/aeralogin/server_test.log

# Neu starten
cd /var/www/aeralogin+implement/aeralogin
nohup python3 server.py > server_test.log 2>&1 &
```

### Problem: "Not Found" bei /join-telegram
```bash
# Prüfe ob Route registriert ist
grep "join-telegram" /var/www/aeralogin+implement/aeralogin/server.py

# Prüfe ob HTML-Datei existiert
ls -la /var/www/aeralogin+implement/aeralogin/join-telegram.html
```

### Problem: NFT-Check schlägt fehl
```bash
# Prüfe web3_service
grep "web3_service" /var/www/aeralogin+implement/aeralogin/server_test.log

# Prüfe Contract-Adressen in .env
grep "IDENTITY_NFT_ADDRESS" /var/www/aeralogin+implement/aeralogin/.env
```

---

## ✅ Checkliste für vollständigen Test

- [ ] Test-Server läuft (Port 8841)
- [ ] Health-Check erfolgreich
- [ ] `/join-telegram` Seite lädt
- [ ] "Connect Wallet" funktioniert
- [ ] NFT-Check läuft durch
- [ ] UI zeigt korrekten Status (mit/ohne NFT)
- [ ] Logs zeigen TELEGRAM_GATE Einträge
- [ ] Datenbank-Eintrag in `telegram_invites` erscheint

---

## 🎯 Nächster Schritt: Production

Wenn alle Tests erfolgreich sind:

```bash
# 1. Telegram Gruppe erstellen & Invite Link holen
# 2. .env anpassen: TELEGRAM_INVITE_LINK=https://t.me/+XXXXXX
# 3. Dateien nach /var/www/aeralogin/ kopieren
# 4. Produktions-Server neu starten
# 5. Live-Tests durchführen
```

Siehe: `TELEGRAM_GATE_DEPLOYMENT.md` für Details

---

**Test-Server:** http://localhost:8841  
**Status:** 🟢 Ready  
**Dokumentation:** Vollständig  
**Bereit für:** Production Deployment
