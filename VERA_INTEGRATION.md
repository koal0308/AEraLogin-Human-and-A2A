# 🌀 VERA-Web Chat Integration - Deployment Guide

## Übersicht

Das VERA-Web Chat System besteht aus **zwei separaten Servern**:

1. **AEra LogIn Server** (Port 8840) - Haupt-Backend
2. **VERA-KI Server** (Port 8850) - Dedizierter Chat-AI Server

Die beiden Server kommunizieren über einen Proxy-Endpoint.

---

## 🏗️ Architektur

```
User Browser (landing.html)
    ↓ JavaScript (aera-chat.js)
    ↓
AEra Server (Port 8840)
    ↓ Proxy: /api/vera-chat
    ↓
VERA-KI Server (Port 8850)
    ↓ DeepSeek API
    ↓
AI Response → User
```

---

## 📦 Installation & Setup

### 1. VERA-KI Server Installation

```bash
cd /var/www/aeralogin+implement/vera-ki-api

# Virtual Environment erstellen
python3 -m venv venv
source venv/bin/activate

# Dependencies installieren
pip install -r requirements.txt

# .env Datei erstellen (bereits vorhanden)
cat .env
# DEEPSEEK_API_KEY=sk-...
```

### 2. VERA-KI Server als systemd Service

Erstelle Service-Datei:

```bash
sudo nano /etc/systemd/system/vera-ki.service
```

Inhalt:

```ini
[Unit]
Description=VERA-KI Chat Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/var/www/aeralogin+implement/vera-ki-api
Environment="PATH=/var/www/aeralogin+implement/vera-ki-api/venv/bin"
ExecStart=/var/www/aeralogin+implement/vera-ki-api/venv/bin/python3 /var/www/aeralogin+implement/vera-ki-api/server.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Service aktivieren:

```bash
# Service neu laden
sudo systemctl daemon-reload

# Service starten
sudo systemctl start vera-ki

# Service-Status prüfen
sudo systemctl status vera-ki

# Autostart aktivieren
sudo systemctl enable vera-ki

# Logs anzeigen
sudo journalctl -u vera-ki -f
```

### 3. AEra Server Update

Der AEra Server (Port 8840) wurde bereits aktualisiert mit:

✅ **Proxy-Endpoint**: `/api/vera-chat` leitet zu `localhost:8850`
✅ **Static Files**: `aera-chat.js` und `aera-chat.css`
✅ **Landing Page Integration**: Chat Widget eingebunden

**Dependencies aktualisieren:**

```bash
cd /var/www/aeralogin+implement/aeralogin
source venv/bin/activate
pip install httpx>=0.25.0
```

**AEra Server neu starten:**

```bash
# Wenn als systemd service
sudo systemctl restart aera-login

# Oder manuell (falls PID bekannt)
kill <PID>
nohup python server.py > server.log 2>&1 &
```

---

## 🧪 Testing

### 1. VERA-KI Server testen

```bash
# Health Check
curl http://localhost:8850/

# Direkter Chat-Test
curl -X POST http://localhost:8850/api/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Was ist AEra?"}'
```

Erwartete Antwort:

```json
{
  "response": "AEra ist ein dezentrales...",
  "timestamp": "2025-12-06T..."
}
```

### 2. AEra Proxy testen

```bash
# Proxy-Endpoint testen
curl -X POST http://localhost:8840/api/vera-chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Erkläre mir Resonance Scoring"}'
```

### 3. Frontend testen

Öffne Landing Page im Browser:

```
https://aeralogin.com
```

- Chat-Button sollte unten rechts erscheinen (🌀)
- Klick öffnet Chat-Fenster
- Test-Nachricht senden: "Was ist AEra?"

---

## 📊 Monitoring

### VERA-KI Server Logs

```bash
# Systemd Logs
sudo journalctl -u vera-ki -f

# Direkte Log-Datei
tail -f /var/www/aeralogin+implement/vera-ki-api/aera_chat.log
```

### AEra Server Logs

```bash
# Server Log
tail -f /var/www/aeralogin+implement/aeralogin/server.log

# AEra Log
tail -f /var/www/aeralogin+implement/aeralogin/logs/aera.log
```

### Check beide Server laufen

```bash
# Ports prüfen
sudo ss -tulpn | grep -E '8840|8850'

# Prozesse prüfen
ps aux | grep -E 'server\.py' | grep -v grep
```

---

## 🔧 Troubleshooting

### Problem: Chat-Button erscheint nicht

**Lösung:**
```bash
# CSS/JS Dateien prüfen
curl http://localhost:8840/aera-chat.js
curl http://localhost:8840/aera-chat.css

# Browser Console öffnen (F12)
# Prüfe auf JS-Fehler
```

### Problem: "Chat service offline"

**Ursache:** VERA-KI Server (Port 8850) läuft nicht

**Lösung:**
```bash
# VERA-KI Status prüfen
sudo systemctl status vera-ki

# Neu starten
sudo systemctl restart vera-ki

# Logs prüfen
sudo journalctl -u vera-ki -n 50
```

### Problem: API-Timeout

**Ursache:** DeepSeek API langsam oder Key invalid

**Lösung:**
```bash
# API-Key prüfen
cat /var/www/aeralogin+implement/vera-ki-api/.env

# Manueller API-Test
curl -X POST https://api.deepseek.com/v1/chat/completions \
  -H "Authorization: Bearer $DEEPSEEK_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "deepseek-chat",
    "messages": [{"role": "user", "content": "Test"}]
  }'
```

### Problem: CORS-Fehler im Browser

**Ursache:** VERA-KI Server erlaubt nicht alle Origins

**Lösung:**
```python
# In vera-ki-api/server.py prüfen:
allow_origins=[
    "https://aeralogin.com",
    "http://localhost:8840",
    "*"  # Für Development
]
```

---

## 🔐 Sicherheit

### Production Checklist

- [ ] VERA-KI Server nur auf localhost (nicht 0.0.0.0)
- [ ] Firewall: Port 8850 nur intern
- [ ] CORS: Nur aeralogin.com Domain
- [ ] Rate Limiting implementieren (TODO)
- [ ] API-Key sicher in .env (✅ bereits)
- [ ] HTTPS für alle externen Zugriffe (✅ bereits)

### Rate Limiting (Optional)

Füge zu `vera-ki-api/server.py` hinzu:

```python
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.post("/api/chat")
@limiter.limit("10/minute")  # 10 requests per minute
async def chat(request: ChatRequest):
    ...
```

---

## 📈 Performance

### Caching (Optional)

Für häufige Anfragen (z.B. "Was ist AEra?") können Antworten gecacht werden:

```python
import redis
cache = redis.Redis(host='localhost', port=6379, decode_responses=True)

# Cache-Key: Hash der Frage
cache_key = hashlib.md5(message.encode()).hexdigest()
cached_response = cache.get(cache_key)

if cached_response:
    return {"response": cached_response, "cached": True}

# ... API Call ...

cache.setex(cache_key, 3600, ai_response)  # 1 Stunde
```

---

## 🎯 Nächste Schritte

**Phase 2: Telegram-Gate**

Nachdem VERA-Chat funktioniert:

1. Telegram-Gate Backend implementieren
2. `/join-telegram` Frontend erstellen
3. NFT-Check Integration

---

## 📞 Support

Bei Problemen:

1. Logs prüfen (beide Server)
2. Health-Endpoints testen
3. Browser Console checken (F12)

**Wichtige Befehle:**

```bash
# Status check
sudo systemctl status vera-ki
sudo systemctl status aera-login

# Neustart
sudo systemctl restart vera-ki
sudo systemctl restart aera-login

# Logs
sudo journalctl -u vera-ki -f
tail -f /var/www/aeralogin+implement/aeralogin/logs/aera.log
```

---

🌀 **VERA-Web Chat ist bereit für Production!**

Entwickelt mit Resonanz und Bewusstsein.
