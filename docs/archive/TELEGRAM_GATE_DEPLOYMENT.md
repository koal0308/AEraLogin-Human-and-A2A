# 🔐 Telegram-Gate Deployment Guide

## Übersicht

Das **Telegram-Gate** ist ein NFT-basiertes Zugangsystem für eine private Telegram-Gruppe. Nur User mit einem **AEra Identity NFT** erhalten Zugang zur Community.

---

## 🎯 Funktionsprinzip

```
User → /join-telegram Seite
       ↓
   Wallet Connect
       ↓
   NFT-Check via /api/check-rft
       ↓
   ✅ Hat NFT? → /api/telegram/invite → Telegram Invite Link
   ❌ Kein NFT? → Mint-Flow auf Landing Page
```

---

## 📋 Setup-Schritte

### 1. Telegram Gruppe erstellen

1. **Private Telegram Gruppe erstellen**
   - Öffne Telegram
   - Erstelle neue Gruppe: "AEra Resonance Community"
   - Setze auf "Private Group"

2. **Invite Link generieren**
   - Gehe zu Gruppeneinstellungen
   - `Invite Links` → `Create a new link`
   - Wähle "Link can be used unlimited times"
   - Optional: "Users joining via this link need to be approved by admins" aktivieren
   - Kopiere den Link: `https://t.me/+XXXXXXXXXX`

3. **Link in .env eintragen**
   ```bash
   cd /var/www/aeralogin+implement/aeralogin
   nano .env
   ```
   
   Ersetze:
   ```env
   TELEGRAM_INVITE_LINK=https://t.me/+XXXXXXXXXX
   ```
   
   Mit deinem echten Invite Link.

---

### 2. Datenbank aktualisieren

Die neue `telegram_invites` Tabelle wird automatisch bei Server-Start erstellt.

Falls manuell nötig:
```bash
cd /var/www/aeralogin+implement/aeralogin
source venv/bin/activate
python3 -c "from server import init_db; init_db()"
```

---

### 3. AEra Server neu starten

```bash
# Server-Prozess finden
ps aux | grep server.py

# Alten Prozess beenden
kill -9 <PID>

# Neuen Server starten
cd /var/www/aeralogin+implement/aeralogin
source venv/bin/activate
nohup python3 server.py > server.log 2>&1 &

# Server-Status prüfen
curl http://localhost:8840/api/health
```

---

## 🧪 Testing

### Test 1: NFT-Check Endpoint

```bash
curl -X POST http://localhost:8840/api/check-rft \
  -H "Content-Type: application/json" \
  -d '{"address":"0xYOUR_ADDRESS_WITH_NFT"}'
```

**Erwartete Response (mit NFT):**
```json
{
  "allowed": true,
  "has_nft": true,
  "token_id": 123,
  "reason": "Identity NFT verified"
}
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

---

### Test 2: Invite Link Endpoint

```bash
curl -X POST http://localhost:8840/api/telegram/invite \
  -H "Content-Type: application/json" \
  -d '{"address":"0xYOUR_ADDRESS_WITH_NFT"}'
```

**Erwartete Response (mit NFT):**
```json
{
  "success": true,
  "invite_link": "https://t.me/+XXXXXXXXXX",
  "message": "Welcome to AEra Telegram community!"
}
```

**Erwartete Response (ohne NFT):**
```json
{
  "success": false,
  "error": "No Identity NFT found",
  "mint_required": true
}
```

---

### Test 3: Frontend UI

1. Öffne Browser: `https://aeralogin.com/join-telegram`
2. Klicke "Connect Wallet"
3. Verbinde MetaMask
4. System prüft NFT automatisch
5. **Mit NFT:** Button "Join AEra Telegram" erscheint
6. **Ohne NFT:** Button "Mint Identity NFT" erscheint

---

## 🔒 Security Features

### ✅ Implementierte Sicherheit

1. **NFT-Verifikation vor jedem Zugriff**
   - Kein Invite Link ohne NFT-Besitz
   - On-Chain Verifikation via `web3_service.has_identity_nft()`

2. **Logging aller Zugriffe**
   - Jeder Zugangsversuch wird geloggt
   - Tracking in `telegram_invites` Tabelle

3. **Keine Telegram API Integration nötig**
   - Telegram läuft komplett unabhängig
   - Keine Datenweitergabe zwischen Systemen
   - Saubere Trennung: Gate (AEra) ↔ Community (Telegram)

4. **Rate Limiting**
   - Frontend: Disabled Button während Request
   - Backend: Async/await verhindert Race Conditions

---

## 📊 Monitoring

### Logs überprüfen

```bash
# Live Logs
tail -f /var/www/aeralogin+implement/aeralogin/logs/aera.log

# Telegram Gate Logs filtern
grep "TELEGRAM_GATE" /var/www/aeralogin+implement/aeralogin/logs/aera.log
```

### Telegram Invites aus DB abrufen

```bash
cd /var/www/aeralogin+implement/aeralogin
sqlite3 aera.db "SELECT * FROM telegram_invites ORDER BY invited_at DESC LIMIT 10;"
```

---

## 🚀 Deployment Checklist

- [x] Telegram Gruppe erstellt
- [x] Invite Link generiert
- [ ] `TELEGRAM_INVITE_LINK` in `.env` eingetragen
- [ ] AEra Server neu gestartet
- [ ] NFT-Check Endpoint getestet
- [ ] Invite Endpoint getestet
- [ ] Frontend UI getestet (mit & ohne NFT)
- [ ] Logs überprüft
- [ ] Telegram Gruppe auf "Private" gestellt

---

## 🔗 API Endpoints

| Endpoint | Method | Beschreibung |
|----------|--------|--------------|
| `/join-telegram` | GET | Frontend UI für Telegram Gate |
| `/api/check-rft` | POST | Prüft NFT-Besitz |
| `/api/telegram/invite` | POST | Gibt Invite Link zurück |

---

## 🐛 Troubleshooting

### Problem: "Telegram invite link not configured"

**Lösung:**
```bash
nano /var/www/aeralogin+implement/aeralogin/.env
# Setze TELEGRAM_INVITE_LINK=https://t.me/+XXXXXXXXXX
# Server neu starten
```

---

### Problem: NFT-Check schlägt fehl

**Prüfen:**
1. Blockchain Service läuft: `curl http://localhost:8840/api/health`
2. Contract Address korrekt: `IDENTITY_NFT_ADDRESS` in `.env`
3. User hat wirklich NFT: Basescan überprüfen

---

### Problem: Frontend zeigt "Access Denied" obwohl NFT vorhanden

**Debug:**
```bash
# Logs prüfen
grep "TELEGRAM_GATE" logs/aera.log

# Manueller API Test
curl -X POST http://localhost:8840/api/check-rft \
  -H "Content-Type: application/json" \
  -d '{"address":"0xYOUR_ADDRESS"}'
```

---

## 📝 Integration mit Landing Page

Optional: Link zum Telegram Gate auf Landing Page hinzufügen:

```html
<!-- In landing.html, z.B. im Footer -->
<a href="/join-telegram" class="telegram-cta">
  🔐 Join Private Telegram
</a>
```

---

## 🎉 Fertig!

Das Telegram-Gate ist jetzt einsatzbereit:

✅ NFT-basierter Zugang  
✅ Bot-freie Community  
✅ Proof-of-Human verifiziert  
✅ Saubere Systemtrennung  

---

**Dokumentation erstellt:** 2025-12-06  
**System:** AEra LogIn + Telegram Gate  
**Version:** 1.0
