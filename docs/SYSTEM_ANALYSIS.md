# AEraLogIn System Analysis
## Current Implementation Documentation

**Analyzed: December 2025**

---

## 1. Authentication Flow Overview

### Wallet Connection
- **Library:** Native `window.ethereum` (EIP-1193 Provider)
- **Supported Wallets:** MetaMask, Coinbase Wallet, Base Wallet, Rainbow, Trust Wallet
- **Smart Contract Wallets:** Supported via EIP-1271 signature verification

### SIWE (Sign-In With Ethereum) Format
```
{domain} wants you to sign in with your Ethereum account:
{wallet_address}

Sign in to AEraLogIn Dashboard

URI: {origin}
Version: 1
Chain ID: 8453
Nonce: {nonce}
Issued At: {timestamp}
```

### Signature Verification
1. **EOA Wallets:** Standard `eth_account.Account.recover_message()`
2. **Smart Contract Wallets:** EIP-1271 `isValidSignature()` check on BASE mainnet

---

## 2. Backend Endpoints (Existing)

### Authentication
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/nonce` | POST | Generate random nonce for signing |
| `/api/verify` | POST | Verify signature, create/update user, mint NFT if new |
| `/api/verify-token` | POST | Verify stored token + fresh signature for auto-login |
| `/admin/challenge` | POST | Get challenge nonce for dashboard login |
| `/admin/verify-signature` | POST | Verify dashboard login signature |

### User Data
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/user/{address}` | GET | Get user data by address |
| `/api/user/profile` | POST | Get full user profile with NFT status |
| `/api/blockchain/identity/{address}` | GET | Check NFT ownership on-chain |
| `/api/blockchain/score/{address}` | GET | Get on-chain Resonance score |

### NFT & Score
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/check-rft` | POST | Check if user has Identity NFT |
| `/api/blockchain/interactions/{address}` | GET | Get interaction history |
| `/api/stats` | GET | Get platform statistics |

---

## 3. Token System

### Token Format
```
{address}:{expiry_timestamp}:{hmac_sha256_signature}
```

### Token Generation (server.py)
```python
def generate_token(address: str, duration_minutes = None) -> str:
    if duration_minutes is None:
        duration_minutes = TOKEN_EXPIRY_MINUTES  # Default: 2 minutes
    expiry = (datetime.now(timezone.utc) + timedelta(minutes=int(duration_minutes))).timestamp()
    token_data = f"{address}:{expiry}"
    signature = hashlib.sha256((token_data + TOKEN_SECRET).encode()).hexdigest()
    return f"{token_data}:{signature}"
```

### Token Verification
```python
def verify_token(token: str) -> dict:
    parts = token.split(":")
    address, expiry_str, signature = parts
    expected_sig = hashlib.sha256((f"{address}:{expiry_str}" + TOKEN_SECRET).encode()).hexdigest()
    if signature != expected_sig:
        return {"valid": False, "error": "Invalid signature"}
    # Check expiry...
    return {"valid": True, "address": address, "expiry": expiry}
```

---

## 4. Session Storage (Frontend)

### Dashboard → User Dashboard Flow
```javascript
// After successful wallet connect + signature verification:
sessionStorage.setItem('aeraDashboardWallet', walletAddress);
sessionStorage.setItem('aeraDashboardToken', signature);  // Uses wallet signature as token

// On User Dashboard (protected area):
const storedWallet = sessionStorage.getItem('aeraDashboardWallet');
const storedToken = sessionStorage.getItem('aeraDashboardToken');
if (!storedWallet || !storedToken) {
    showAccessDenied();  // Redirect to dashboard
}
```

### Join-Telegram Flow
```javascript
// Uses localStorage for longer persistence:
localStorage.setItem('aera_token', token);
localStorage.setItem('aera_address', address);
```

---

## 5. Access Control

### Current Implementation
- **Frontend-only:** sessionStorage/localStorage check
- **Backend validation:** `/api/user/profile` verifies user exists
- **No server-side session:** Token is signature-based, verified on each request

### Security Gaps (addressed by new OAuth system)
1. No httpOnly cookies → token exposed to XSS
2. No CSRF protection on API calls
3. No cross-origin session support for third-party sites
4. Token in sessionStorage → cleared on tab close

---

## 6. NFT Minting Flow

### Trigger Points
1. **Dashboard Login:** First-time users get NFT minted automatically
2. **Follower Link:** Users following via `/follow?ref=...` get NFT

### Backend Minting (server.py `/api/verify`)
```python
# After signature verification:
if not existing_user:
    # Create user in DB
    # Trigger gasless NFT mint via web3_service
    # Gas paid by backend wallet (community-funded)
```

---

## 7. Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                     USER BROWSER                             │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. User clicks "Connect Wallet"                             │
│          │                                                   │
│          ▼                                                   │
│  2. window.ethereum.request({method: 'eth_requestAccounts'}) │
│          │                                                   │
│          ▼                                                   │
│  3. POST /api/nonce → Get random nonce                       │
│          │                                                   │
│          ▼                                                   │
│  4. Build SIWE message with nonce                            │
│          │                                                   │
│          ▼                                                   │
│  5. personal_sign(message, address) → Wallet signature       │
│          │                                                   │
│          ▼                                                   │
│  6. POST /api/verify {address, nonce, signature, message}    │
│          │                                                   │
│          ▼                                                   │
│  ┌───────────────────────────────────────────────────────┐   │
│  │                  BACKEND (FastAPI)                     │   │
│  ├───────────────────────────────────────────────────────┤   │
│  │  7. Verify signature (EOA or EIP-1271)                │   │
│  │  8. Check/create user in SQLite DB                    │   │
│  │  9. Mint NFT if new user (gasless)                    │   │
│  │  10. Generate token (address:expiry:hmac)             │   │
│  │  11. Return {is_human: true, token, score, ...}       │   │
│  └───────────────────────────────────────────────────────┘   │
│          │                                                   │
│          ▼                                                   │
│  7. Store token in sessionStorage                            │
│          │                                                   │
│          ▼                                                   │
│  8. User can access protected areas                          │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## 8. Smart Contracts (BASE Mainnet)

| Contract | Address | Purpose |
|----------|---------|---------|
| AEraIdentityNFT | `0xF9ff5DC523927B9632049bd19e17B610E9197d53` | Soul-bound identity NFTs |
| AEraResonanceScore | `0x9A814DBF7E2352CE9eA6293b4b731B2a24800102` | On-chain score storage |
| AEraResonanceRegistry | `0xAAf30d96382D2409Cf1626095e97BEc1C59e5cdF` | Interaction logging |

---

## 9. Environment Configuration

```env
HOST=0.0.0.0
PORT=8840
PUBLIC_URL=https://aeralogin.com
CORS_ORIGINS=*
TOKEN_SECRET=<secret-key>
TOKEN_EXPIRY_MINUTES=2
DATABASE_PATH=./aera.db
```

---

## 10. Files Modified for OAuth Integration

The following files will be modified/created:

### New Files
- `sdk/aera-gate.js` - Client-side protection SDK
- `sdk/aera-gate.min.js` - Minified version
- `docs/embed.md` - Integration documentation
- `examples/express-protected-site/` - Example Node.js app

### Modified Files
- `server.py` - Add OAuth endpoints (/oauth/authorize, /oauth/token, /api/v1/verify)
- New DB table: `oauth_clients` for client_id/secret management

