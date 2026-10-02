# AEraLogIn OAuth 2.0 Token Response - Dokumentation

## 📋 Übersicht

Dieses Dokument beschreibt die `/oauth/token` Endpoint Response von AEraLogIn für die Integration mit externen Anwendungen.

---

## 🔐 OAuth Flow

### 1. Authorization URL

Leite den User zu dieser URL weiter:

```
https://aeralogin.com/oauth/authorize
  ?client_id=YOUR_CLIENT_ID
  &redirect_uri=https://yoursite.com/callback
  &response_type=code
  &state=RANDOM_STATE
```

**Parameter:**
- `client_id` - Deine registrierte Client ID (z.B. `aera_e8f59072e51167d83b61c5bab6f71651`)
- `redirect_uri` - Callback URL deiner Anwendung (muss in Whitelist sein)
- `response_type` - Immer `code`
- `state` - CSRF-Schutz Token (optional aber empfohlen)

---

### 2. Token Exchange

Nach dem Callback tauschst du den Authorization Code gegen ein Access Token:

**Request:**
```http
POST https://aeralogin.com/oauth/token
Content-Type: application/json

{
  "grant_type": "authorization_code",
  "code": "<authorization_code_from_callback>",
  "redirect_uri": "https://yoursite.com/callback",
  "client_id": "YOUR_CLIENT_ID",
  "client_secret": "YOUR_CLIENT_SECRET"
}
```

**Response (Success):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 86400,
  "wallet": "0x58bfb2d7e89f9553e1bb05b15c2d20f051dfb929",
  "score": 50,
  "has_nft": true
}
```

---

## 📊 Response Felder (Detailliert)

| Feld | Typ | Beschreibung | Beispiel |
|------|-----|--------------|----------|
| `access_token` | string | JWT Access Token (24h gültig) | `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...` |
| `token_type` | string | Token-Typ (immer "Bearer") | `Bearer` |
| `expires_in` | number | Gültigkeit in Sekunden | `86400` (24 Stunden) |
| `wallet` | string | Ethereum Wallet-Adresse des Users | `0x58bfb2d7e89f9553e1bb05b15c2d20f051dfb929` |
| `score` | number | AEra Resonance Score des Users | `50` |
| `has_nft` | boolean | Hat User ein AEra Identity NFT? | `true` |

---

## 🔍 NFT Verification (Optional)

Wenn du zusätzlich die NFT-Daten verifizieren willst:

**Request:**
```http
POST https://aeralogin.com/api/oauth/verify-nft
Content-Type: application/json

{
  "access_token": "<access_token_from_previous_step>",
  "client_id": "YOUR_CLIENT_ID",
  "client_secret": "YOUR_CLIENT_SECRET"
}
```

**Response:**
```json
{
  "valid": true,
  "wallet": "0x58bfb2d7e89f9553e1bb05b15c2d20f051dfb929",
  "has_nft": true,
  "score": 50,
  "chain_id": 8453,
  "client_id": "aera_..."
}
```

---

## 💡 Beispiel-Implementation (Node.js/Express)

```javascript
// 1. Redirect zu AEra Authorization
app.get('/auth/aera', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  req.session.oauthState = state;
  
  const authUrl = new URL('https://aeralogin.com/oauth/authorize');
  authUrl.searchParams.append('client_id', process.env.AERA_CLIENT_ID);
  authUrl.searchParams.append('redirect_uri', 'https://yoursite.com/auth/aera/callback');
  authUrl.searchParams.append('response_type', 'code');
  authUrl.searchParams.append('state', state);
  
  res.redirect(authUrl.toString());
});

// 2. Callback Handler
app.get('/auth/aera/callback', async (req, res) => {
  const { code, state } = req.query;
  
  // Verify state
  if (state !== req.session.oauthState) {
    return res.status(400).send('Invalid state parameter');
  }
  
  // Exchange code for token
  const tokenResponse = await fetch('https://aeralogin.com/oauth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: 'https://yoursite.com/auth/aera/callback',
      client_id: process.env.AERA_CLIENT_ID,
      client_secret: process.env.AERA_CLIENT_SECRET
    })
  });
  
  const tokenData = await tokenResponse.json();
  
  // Token Data enthält:
  // - access_token (JWT)
  // - token_type ("Bearer")
  // - expires_in (86400)
  // - wallet (User's Ethereum Address)
  // - score (Resonance Score)
  // - has_nft (boolean)
  
  // Speichere User-Daten in Session
  req.session.user = {
    wallet: tokenData.wallet,
    score: tokenData.score,
    hasNFT: tokenData.has_nft,
    accessToken: tokenData.access_token
  };
  
  res.redirect('/dashboard');
});

// 3. Protected Route Example
app.get('/dashboard', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/auth/aera');
  }
  
  res.json({
    message: 'Welcome to your dashboard',
    user: req.session.user
  });
});
```

---

## ⚠️ Wichtige Hinweise

### Token-Gültigkeit
- **Authorization Code:** 10 Minuten (einmalige Verwendung)
- **Access Token:** 24 Stunden

### Fehlerbehandlung

**"Invalid or expired authorization request"**
- Authorization Code ist abgelaufen (>10 Minuten)
- Code wurde bereits verwendet
- Lösung: Neuen OAuth-Flow starten

**"Unknown Application"**
- `client_id` ist nicht registriert oder inaktiv
- Lösung: Client im AEra Dashboard registrieren

**"Invalid Redirect URI"**
- `redirect_uri` ist nicht in der Whitelist
- Lösung: URI im Dashboard zur Whitelist hinzufügen

---

## 🧪 Test-Logs vom Server

**Erfolgreiche Token Exchange (21.12.2025, 06:49 UTC):**

```
🔐 /oauth/token RESPONSE:
============================================================
  access_token: eyJhbGciOiJIUzI1NiIsInR5cCI6Ik... (JWT Token)
  token_type: Bearer
  expires_in: 86400
  wallet: 0x58bfb2d7e89f9553e1bb05b15c2d20f051dfb929
  score: 50
  has_nft: True
============================================================
```

---

## 📝 Checklist für Integration

- [ ] Client ID und Secret im Dashboard generieren
- [ ] Redirect URI in Whitelist eintragen
- [ ] Authorization URL implementieren
- [ ] Callback-Handler implementieren
- [ ] Token Exchange Request implementieren
- [ ] User-Daten in Session speichern
- [ ] Protected Routes absichern
- [ ] Error Handling implementieren
- [ ] Token-Refresh implementieren (nach 24h)

---

## � Session Token Verification (WICHTIG!)

### `/api/v1/verify` Endpoint - GEFIXT!

**Problem vorher:**
- Endpoint gab nur `"valid": true/false` zurück
- Feld `"authenticated"` hat gefehlt
- Client-Code erwartete beide Felder

**✅ FIX (21.12.2025):**
Endpoint gibt jetzt **beide Felder** zurück:

**Request:**
```http
POST https://aeralogin.com/api/v1/verify
Authorization: Bearer <access_token>
```

**Response (Success):**
```json
{
  "valid": true,
  "authenticated": true,         // ← NEU! Jetzt vorhanden
  "wallet": "0x58bfb2d7e89f9553e1bb05b15c2d20f051dfb929",
  "score": 50,
  "has_nft": true,
  "chain_id": 8453,
  "issued_at": "2025-12-21T06:49:10Z",
  "expires_at": "2025-12-22T06:49:10Z",
  "client_id": "aera_...",
  "jti": "unique-token-id"
}
```

**Response (Error):**
```json
{
  "valid": false,
  "authenticated": false,        // ← NEU! Jetzt vorhanden
  "error": "Token expired"
}
```

### Wichtige Änderungen:

1. **`authenticated` Feld hinzugefügt** - Alias für `valid` (Kompatibilität mit bestehenden Clients)
2. **Zusätzliche Felder** - `issued_at`, `expires_at`, `client_id`, `jti` für bessere Token-Verwaltung
3. **Error Response** - Beide Felder auch bei Fehlern vorhanden

### Migration für bestehende Implementierungen:

**Vorher (alt):**
```javascript
const result = await verifyToken(token);
if (result.valid) {
  // User authenticated
}
```

**Jetzt (neu - beide Felder verfügbar):**
```javascript
const result = await verifyToken(token);
if (result.valid && result.authenticated) {
  // User authenticated
}
// ODER einfach:
if (result.authenticated) {
  // User authenticated (empfohlen)
}
```

---

## 📋 Zusammenfassung der Änderungen

### Was wurde gefixt?

| Endpoint | Änderung | Status |
|----------|----------|--------|
| `/oauth/token` | Gibt jetzt `wallet`, `score`, `has_nft` direkt zurück | ✅ Live |
| `/api/v1/verify` | Gibt jetzt `authenticated` UND `valid` zurück | ✅ Live |
| `/api/oauth/verify-nft` | Gibt jetzt `chain_id` zusätzlich zurück | ✅ Live |

### Was musst du anpassen?

**Nichts! Abwärtskompatibel!**
- Alte Code mit nur `valid` funktioniert weiterhin
- Neuer Code kann `authenticated` nutzen
- Zusätzliche Felder sind optional

### Empfehlung:

Nutze `authenticated` in neuem Code für bessere Lesbarkeit:

```javascript
// ✅ Empfohlen (semantisch klarer)
if (result.authenticated) {
  console.log('User is logged in');
}

// ✅ Funktioniert auch weiterhin
if (result.valid) {
  console.log('Token is valid');
}
```

---

## �🔗 Weitere Ressourcen

- **SDK-Dokumentation:** https://aeralogin.com/sdk-docs
- **Dashboard:** https://aeralogin.com/user-dashboard
- **Support:** https://aeralogin.com (Chat Widget)

---

## 📞 Support-Kontakt

Bei Fragen zur Integration:
1. Chat Widget auf aeralogin.com nutzen
2. Dashboard → Support
3. Dokumentation: https://aeralogin.com/sdk-docs

---

**Erstellt:** 21. Dezember 2025  
**Version:** 1.1  
**Letzte Änderung:** 21.12.2025, 07:00 UTC  
**Status:** ✅ Getestet und funktionsfähig  
**Änderungen:** `/api/v1/verify` gibt jetzt `authenticated` Feld zurück
