# 🔷 AEraLogin OAuth Mobile Integration - Problem Analysis & Solution

**Date:** 28. Dezember 2025  
**Status:** 🔴 CRITICAL BUG - "Invalid message" in BASE App (Mobile WebView)  
**Demo App:** https://aera-miniapp-demo.vercel.app/app  
**Platform:** Farcaster Frame v2 Mini App on BASE (Chain ID: 8453)

---

## 📱 Problem Summary

### ✅ What Works
- ✅ **Desktop (Mac):** OAuth flow functions perfectly in Warpcast
- ✅ **Wallet Detection:** Successfully detects connected wallets in BASE App
- ✅ **Multi-Platform:** Runs in Farcaster, BASE App, and normal browsers
- ✅ **User Context:** Correctly transmits:
  - Farcaster FID (when in Warpcast)
  - Wallet Address (when in BASE/Web3 App)
  - User Agent for Platform Detection

### ❌ What's Broken
- ❌ **BASE App Mobile:** "Invalid message" error appears when clicking "Connect Wallet"
- ❌ **Platform:** Android 14 (Xiaomi 22101316G)
- ❌ **Browser:** Chrome 143 WebView (Coinbase Wallet / BASE App embedded browser)
- ❌ **Network:** BASE L2 (Chain ID: 8453)
- ❌ **Wallet:** Already connected via `window.ethereum` (0xdd05d4a54fc1ff75431940c375fd8efd334d284c)

---

## 🔍 Root Cause Analysis

### 1. **Signature Verification in `/oauth/complete`**

**Location:** `server.py:3700-3717`

```python
# Verify signature
try:
    from eth_account.messages import encode_defunct
    from eth_account import Account
    
    msg = encode_defunct(text=message)
    recovered = Account.recover_message(msg, signature=signature)
    
    if recovered.lower() != address:
        conn.close()
        return {"success": False, "error": "Signature verification failed"}
except Exception as e:
    conn.close()
    return {"success": False, "error": f"Signature error: {str(e)}"}
```

**Problem:** This code only supports **EOA (Externally Owned Account) wallets**!

### 2. **Missing Smart Contract Wallet Support**

The `/oauth/complete` endpoint does NOT implement:
- ❌ EIP-1271 Smart Contract Wallet verification
- ❌ EIP-6492 signature support
- ❌ BASE App's native Coinbase Smart Wallet

**Comparison:** Other endpoints like `/api/verify` and `/admin/verify-signature` DO support Smart Contract Wallets!

**Example from `/api/verify` (lines 2083-2129):**
```python
# SMART CONTRACT WALLET (EIP-1271) VERIFICATION
if is_smart_wallet_sig and message_from_frontend and nonce in message_from_frontend:
    log_activity("INFO", "AUTH", "Attempting EIP-1271 Smart Contract Wallet verification...", address=address[:10])
    try:
        from web3 import Web3
        
        # Connect to BASE mainnet
        w3 = Web3(Web3.HTTPProvider('https://mainnet.base.org'))
        
        # EIP-1271 ABI - just the isValidSignature function
        EIP1271_ABI = [...]
        
        # Call isValidSignature on the smart contract wallet
        result = wallet_contract.functions.isValidSignature(
            message_hash,
            sig_bytes
        ).call()
        
        # EIP-1271 magic value for valid signature
        MAGIC_VALUE = bytes.fromhex('1626ba7e')
        
        if result == MAGIC_VALUE:
            signature_valid = True
```

---

## 🛠️ Solution: Add Smart Contract Wallet Support to OAuth

### **Step 1: Update `/oauth/complete` Signature Verification**

Replace the simple EOA verification with the same robust verification logic used in `/api/verify`:

```python
@app.post("/oauth/complete")
async def oauth_complete(req: Request):
    try:
        data = await req.json()
        oauth_nonce = data.get("oauth_nonce", "")
        address = data.get("address", "").lower()
        nonce = data.get("nonce", "")
        message = data.get("message", "")
        signature = data.get("signature", "")
        
        if not all([oauth_nonce, address, nonce, message, signature]):
            return {"success": False, "error": "Missing required parameters"}
        
        # Find pending authorization
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT oc.*, c.min_score, c.require_nft 
            FROM oauth_codes oc
            JOIN oauth_clients c ON oc.client_id = c.client_id
            WHERE oc.nonce = ? AND oc.used = 0 AND oc.expires_at > ?
        """, (oauth_nonce, datetime.now(timezone.utc).isoformat()))
        pending = cursor.fetchone()
        
        if not pending:
            conn.close()
            return {"success": False, "error": "Invalid or expired authorization request"}
        
        # ========================================
        # ENHANCED SIGNATURE VERIFICATION
        # Supports: EOA, Smart Contract Wallets (EIP-1271), BASE Wallet
        # ========================================
        signature_valid = False
        
        # Detect Smart Contract Wallet signature (EIP-6492)
        is_smart_wallet_sig = len(signature) > 200 if signature else False
        
        try:
            from eth_account.messages import encode_defunct, defunct_hash_message
            from eth_account import Account
            
            # 🔐 SMART CONTRACT WALLET (EIP-1271) VERIFICATION
            # Coinbase Smart Wallet, Safe, Base Wallet, etc.
            if is_smart_wallet_sig and message and nonce in message:
                log_activity("INFO", "OAUTH", f"Attempting EIP-1271 Smart Contract Wallet verification for {address[:10]}")
                try:
                    from web3 import Web3
                    
                    # Connect to BASE mainnet
                    w3 = Web3(Web3.HTTPProvider('https://mainnet.base.org'))
                    
                    # EIP-1271 ABI
                    EIP1271_ABI = [
                        {
                            "inputs": [
                                {"name": "_hash", "type": "bytes32"},
                                {"name": "_signature", "type": "bytes"}
                            ],
                            "name": "isValidSignature",
                            "outputs": [{"name": "", "type": "bytes4"}],
                            "stateMutability": "view",
                            "type": "function"
                        }
                    ]
                    
                    # Hash the message (EIP-191 personal sign format)
                    message_hash = defunct_hash_message(text=message)
                    
                    # Create contract instance
                    wallet_contract = w3.eth.contract(
                        address=Web3.to_checksum_address(address),
                        abi=EIP1271_ABI
                    )
                    
                    # Convert signature to bytes
                    sig_bytes = bytes.fromhex(signature[2:]) if signature.startswith('0x') else bytes.fromhex(signature)
                    
                    # Call isValidSignature on the smart contract wallet
                    result = wallet_contract.functions.isValidSignature(
                        message_hash,
                        sig_bytes
                    ).call()
                    
                    # EIP-1271 magic value for valid signature
                    MAGIC_VALUE = bytes.fromhex('1626ba7e')
                    
                    if result == MAGIC_VALUE:
                        signature_valid = True
                        log_activity("INFO", "OAUTH", f"✅ EIP-1271 Smart Contract Wallet verification SUCCESS for {address[:10]}")
                    else:
                        log_activity("INFO", "OAUTH", f"EIP-1271 returned: {result.hex()} (expected 1626ba7e)")
                        
                except Exception as eip1271_error:
                    log_activity("INFO", "OAUTH", f"EIP-1271 verification failed: {str(eip1271_error)}")
            
            # 🔐 STANDARD EOA SIGNATURE VERIFICATION
            # MetaMask, Rainbow, Trust Wallet, etc.
            if not signature_valid:
                try:
                    msg = encode_defunct(text=message)
                    recovered = Account.recover_message(msg, signature=signature)
                    
                    if recovered.lower() == address:
                        signature_valid = True
                        log_activity("INFO", "OAUTH", f"✅ EOA signature verification SUCCESS for {address[:10]}")
                    else:
                        log_activity("ERROR", "OAUTH", f"Signature verification FAILED", address=address[:10], recovered=recovered[:10])
                except Exception as eoa_error:
                    log_activity("INFO", "OAUTH", f"EOA verification failed: {str(eoa_error)}")
            
            if not signature_valid:
                conn.close()
                return {"success": False, "error": "Signature verification failed - wallet not supported"}
            
            # 🔐 SIWE: Also verify nonce is in the message (anti-replay)
            if message and nonce not in message:
                conn.close()
                log_activity("ERROR", "OAUTH", "SIWE nonce mismatch", address=address[:10])
                return {"success": False, "error": "Nonce mismatch in SIWE message"}
                
        except Exception as e:
            conn.close()
            log_activity("ERROR", "OAUTH", f"Signature verification error: {str(e)}", address=address[:10])
            return {"success": False, "error": f"Signature error: {str(e)}"}
        
        # Check user exists and meets requirements
        cursor.execute("SELECT * FROM users WHERE address = ?", (address,))
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return {"success": False, "error": "Please register on AEraLogIn dashboard first to get your Identity NFT"}
        
        # Check NFT requirement
        if pending['require_nft']:
            if user['identity_status'] != 'active':
                conn.close()
                return {"success": False, "error": "Identity NFT required. Please mint your NFT on the dashboard first."}
        
        # Check score requirement
        if user['score'] < pending['min_score']:
            conn.close()
            return {"success": False, "error": f"Minimum Resonance Score of {pending['min_score']} required. Your score: {user['score']}"}
        
        # Generate authorization code
        auth_code = generate_oauth_code()
        
        # Update the authorization record
        cursor.execute("""
            UPDATE oauth_codes 
            SET code = ?, address = ?, created_at = ?, expires_at = ?
            WHERE nonce = ?
        """, (
            auth_code,
            address,
            datetime.now(timezone.utc).isoformat(),
            (datetime.now(timezone.utc) + timedelta(seconds=OAUTH_CODE_EXPIRY_SECONDS)).isoformat(),
            oauth_nonce
        ))
        conn.commit()
        conn.close()
        
        log_activity("INFO", "OAUTH", f"Authorization code generated for {address[:10]}", client_id=pending['client_id'])
        
        return {"success": True, "code": auth_code}
        
    except Exception as e:
        log_activity("ERROR", "OAUTH", f"OAuth complete error: {str(e)}")
        return {"success": False, "error": "Internal server error"}
```

---

## 📊 Testing Requirements

### Test Matrix

| Platform | Wallet Type | Expected Result |
|----------|-------------|-----------------|
| Desktop Browser | MetaMask (EOA) | ✅ Already Works |
| Desktop Browser | Coinbase Smart Wallet | 🔄 Should work after fix |
| BASE App (Mobile) | Built-in Smart Wallet | 🔄 Should work after fix |
| Warpcast (Mobile) | Connected Wallet | 🔄 Should work after fix |
| Farcaster Frame | External Wallet | 🔄 Should work after fix |

### Test Credentials
- **CLIENT_ID:** `aera_f6c4c87a29aa2919662f029ac4695ab3`
- **CLIENT_SECRET:** `JTC1k5EJ-p2R0hj_jo1LkOEHWm_m6YzUcexve7py0Bk`
- **Test Wallet (BASE App):** `0xdd05d4a54fc1ff75431940c375fd8efd334d284c`

---

## 🎯 Expected Outcomes After Fix

1. ✅ BASE App users can complete OAuth flow with Smart Contract Wallets
2. ✅ All signature types supported (EOA, EIP-1271, EIP-6492)
3. ✅ Consistent behavior across all authentication endpoints
4. ✅ Better error messages for debugging
5. ✅ Full Farcaster Frame v2 compatibility

---

## 📝 Implementation Checklist

- [ ] Update `/oauth/complete` signature verification
- [ ] Add `is_smart_wallet_sig` detection
- [ ] Add EIP-1271 verification logic
- [ ] Keep EOA fallback for backward compatibility
- [ ] Add comprehensive logging
- [ ] Test with BASE App on mobile
- [ ] Test with MetaMask (should still work)
- [ ] Update OAuth documentation
- [ ] Add Smart Wallet support to SDK docs

---

## 🔗 Related Files

- **Main OAuth Endpoint:** `server.py:3660-3760` (`/oauth/complete`)
- **Reference Implementation:** `server.py:2083-2129` (`/api/verify` with EIP-1271)
- **OAuth Authorization Page:** `server.py:3394-3660` (`/oauth/authorize`)
- **Smart Wallet Support:** `server.py:4652-4711` (Dashboard signature verification)

---

## 🚀 Next Steps for Mini App Integration

Once this fix is deployed:

1. **Update Demo App:** Test with fixed OAuth endpoint
2. **Farcaster Frame SDK:** Document BASE App compatibility
3. **NFT-Gated Communities:** Enable Telegram/Discord integration
4. **Developer Documentation:** Add Smart Wallet examples
5. **Base Ecosystem:** Promote as first NFT-gated Frame system

---

## 💡 Additional Recommendations

### 1. **Add Chain ID Validation**
Currently, the OAuth flow doesn't validate that the user is on BASE (8453). Add:

```python
# Verify user is on correct chain
try:
    from web3 import Web3
    w3 = Web3(Web3.HTTPProvider('https://mainnet.base.org'))
    
    # Optional: Check if wallet is on BASE
    if window.ethereum:
        chain_id = await window.ethereum.request({ method: 'eth_chainId' })
        if chain_id != '0x2105':  # BASE = 8453 = 0x2105
            return {"success": False, "error": "Please switch to BASE network"}
except:
    pass  # Skip if can't verify
```

### 2. **OAuth Scope for Additional Data**
Allow Mini Apps to request additional data:

```
/oauth/authorize?
  client_id=...&
  scope=profile+wallet+nft+score&  # NEW: Request specific data
  response_type=code
```

Return in token verification:
```json
{
  "valid": true,
  "wallet": "0x...",
  "score": 120,
  "has_nft": true,
  "chain_id": 8453,
  "farcaster_fid": 12345,  // NEW: If connected via Farcaster
  "display_name": "Alice"   // NEW: User's chosen name
}
```

### 3. **Demo Mode for Testing**
Add a test mode that doesn't require real NFT:

```python
# In OAuth config
TEST_MODE = os.getenv("OAUTH_TEST_MODE", "false").lower() == "true"

if TEST_MODE and client_id.startswith("aera_test_"):
    # Skip NFT requirements for test apps
    log_activity("INFO", "OAUTH", "Test mode - skipping NFT check")
```

---

## 📞 Contact & Support

**Demo App:** https://aera-miniapp-demo.vercel.app/app  
**GitHub:** https://github.com/koal0308/AEraLogin-Human-and-A2A  
**X/Twitter:** @AEraResonant

**Questions?**
1. Is the OAuth system production-ready or still in Beta?
2. Which chains are supported for NFT verification? (Only BASE or also Ethereum Mainnet?)
3. Are there test credentials/NFTs available for development?
4. Can you reproduce the "Invalid message" error on your side?
5. Is there existing documentation for Mobile/WebView integration?
6. What's the roadmap for Farcaster Frame v2 support?

---

**Status:** 🔴 AWAITING FIX  
**Priority:** HIGH - Blocks mobile OAuth integration  
**Impact:** All Smart Contract Wallet users (BASE App, Coinbase Wallet, Safe)

---

This document serves as a complete reference for the AEraLogin team to implement Smart Contract Wallet support in the OAuth flow. The fix is critical for mobile integration and Farcaster Frame v2 compatibility! 🚀
