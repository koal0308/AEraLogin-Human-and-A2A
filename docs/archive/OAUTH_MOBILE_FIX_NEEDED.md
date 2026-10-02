# 🔧 OAuth Mobile/In-App Browser Fix Required

## 🎯 Problem

Der OAuth Authorization Flow (`/oauth/authorize`) verwendet aktuell **nur** eine einfache `personal_sign` Methode ohne Fallback-Strategien. Das führt zu Problemen bei:

- ❌ **Coinbase Smart Wallet** (BASE App)
- ❌ **Base Wallet In-App Browser**
- ❌ **Mobile Geräte** (Android/iOS)
- ❌ **Verschiedene Wallet-Implementierungen**

## ✅ Lösung aus `join-telegram.html`

Die Join-Telegram Seite hat bereits eine **robuste Implementierung** mit:

### 1. `robustWalletSign()` Funktion

```javascript
async function robustWalletSign(message, address) {
    // Strategy 1: Base Wallet SIWE Capabilities
    if (isBaseWallet && window.ethereum) {
        try {
            const result = await window.ethereum.request({
                method: 'wallet_connect',
                params: [{
                    version: '1',
                    capabilities: {
                        signInWithEthereum: {
                            nonce: nonce,
                            chainId: '0x2105'
                        }
                    }
                }]
            });
            if (result && result.signature) return result.signature;
        } catch (e) { /* Fallback */ }
    }
    
    // Strategy 2: Standard personal_sign [message, address]
    try {
        return await window.ethereum.request({
            method: 'personal_sign',
            params: [message, address]
        });
    } catch (error1) {
        // Strategy 3: Reversed personal_sign [address, message]
        try {
            return await window.ethereum.request({
                method: 'personal_sign',
                params: [address, message]
            });
        } catch (error2) {
            // Strategy 4: Hex-encoded personal_sign
            const hexMessage = '0x' + Array.from(new TextEncoder().encode(message))
                .map(b => b.toString(16).padStart(2, '0')).join('');
            return await window.ethereum.request({
                method: 'personal_sign',
                params: [hexMessage, address]
            });
        }
    }
}
```

### 2. Mobile/Device Detection

```javascript
function detectAndShowMobileInfo() {
    const ua = navigator.userAgent;
    const isAndroid = /Android/i.test(ua);
    const isIOS = /iPhone|iPad|iPod/i.test(ua);
    const isInAppBrowser = /MetaMask|Trust|Coinbase|CoinbaseWallet|Base|Rainbow|Phantom/i.test(ua);
    
    if (isAndroid && isInAppBrowser) {
        // Android + Wallet Browser (Intent-Bridge ready)
        log('📱 Device: Android + In-App Browser');
    } else if (isIOS && isInAppBrowser) {
        // iOS + Wallet Browser (Universal Link ready)
        log('📱 Device: iOS + In-App Browser');
    }
}
```

### 3. Base Wallet Spezial-Behandlung

```javascript
const ua = navigator.userAgent.toLowerCase();
const isBaseWallet = ua.includes('base') || 
                     ua.includes('coinbasewallet') || 
                     (window.ethereum && window.ethereum.isCoinbaseWallet);
```

## 🚀 Implementierung in OAuth

### Aktueller Code in `server.py` (Zeile 3607):

```javascript
// Sign message
const signature = await window.ethereum.request({
    method: 'personal_sign',
    params: [messageToSign, address]
});
```

### ✅ Verbesserter Code (mit Fallbacks):

```javascript
// ========================================
// ROBUST WALLET SIGNING (Multi-Strategy)
// ========================================
async function robustWalletSign(message, address) {
    const ua = navigator.userAgent.toLowerCase();
    const isBaseWallet = ua.includes('base') || 
                         ua.includes('coinbasewallet') || 
                         (window.ethereum && window.ethereum.isCoinbaseWallet);
    
    console.log('[OAuth] Attempting signature (Base/Coinbase detected:', isBaseWallet, ')');
    
    // Extract nonce
    const nonceMatch = message.match(/Nonce: ([a-zA-Z0-9]+)/);
    const nonce = nonceMatch ? nonceMatch[1] : Date.now().toString();
    
    // Strategy 1: Base Wallet SIWE Capabilities
    if (isBaseWallet && window.ethereum) {
        try {
            console.log('[OAuth] Trying Base Wallet SIWE Capabilities...');
            const result = await window.ethereum.request({
                method: 'wallet_connect',
                params: [{
                    version: '1',
                    capabilities: {
                        signInWithEthereum: {
                            nonce: nonce,
                            chainId: '0x2105'
                        }
                    }
                }]
            });
            if (result && result.signature) {
                console.log('[OAuth] ✅ Base Wallet SIWE successful!');
                return result.signature;
            }
        } catch (e) {
            console.log('[OAuth] Base SIWE not supported:', e.message);
        }
    }
    
    // Strategy 2: Standard personal_sign [message, address]
    try {
        console.log('[OAuth] Trying standard personal_sign...');
        return await window.ethereum.request({
            method: 'personal_sign',
            params: [message, address]
        });
    } catch (error1) {
        console.log('[OAuth] Standard method failed:', error1.message);
        
        // Strategy 3: Reversed personal_sign [address, message]
        try {
            console.log('[OAuth] Trying reversed personal_sign...');
            return await window.ethereum.request({
                method: 'personal_sign',
                params: [address, message]
            });
        } catch (error2) {
            console.log('[OAuth] Reversed method failed:', error2.message);
            
            // Strategy 4: Hex-encoded personal_sign
            try {
                console.log('[OAuth] Trying hex-encoded personal_sign...');
                const hexMessage = '0x' + Array.from(new TextEncoder().encode(message))
                    .map(b => b.toString(16).padStart(2, '0')).join('');
                return await window.ethereum.request({
                    method: 'personal_sign',
                    params: [hexMessage, address]
                });
            } catch (error3) {
                throw new Error('All signature methods failed: ' + error1.message);
            }
        }
    }
}

// Dann beim Sign-Aufruf:
showStatus('⏳ Please sign the message in your wallet...', 'success');
const signature = await robustWalletSign(messageToSign, address);
```

## 📝 Änderungen in `server.py`

### Zeile 3395 - `/oauth/authorize` Endpoint

**Ersetze den kompletten `<script>` Block** (Zeilen ~3550-3665) mit der robusten Version:

1. Füge `robustWalletSign()` Funktion hinzu
2. Füge `detectMobileDevice()` Funktion hinzu  
3. Ersetze `personal_sign` Aufruf durch `robustWalletSign()`
4. Füge Mobile-Info UI hinzu
5. Füge Base Wallet Detection hinzu

## ✅ Testing Checklist

Nach Implementierung testen mit:

- [ ] **Desktop MetaMask** (Standard-Fall)
- [ ] **BASE App Android** (Coinbase Smart Wallet)
- [ ] **BASE App iOS** (Coinbase Smart Wallet)
- [ ] **Rainbow Wallet** (Mobile)
- [ ] **Trust Wallet** (Mobile)
- [ ] **Phantom Wallet** (wenn verfügbar)

## 🎯 Erwartete Verbesserungen

✅ Coinbase Smart Wallet funktioniert (EIP-1271 + robuste Signatur)  
✅ Mobile In-App Browser werden erkannt und optimiert  
✅ Fallback-Strategien verhindern Fehler bei verschiedenen Wallets  
✅ Base Wallet wird speziell behandelt  
✅ Besseres User-Feedback bei Fehlern  

## 📚 Referenzen

- **Implementierung**: `/var/local/aeralogin+imp. backup-07.12.2025/aeralogin+implement/aeralogin/join-telegram.html`
  - Zeile 816-900: `detectAndShowMobileInfo()`
  - Zeile 854-954: `robustWalletSign()`

- **OAuth Code**: `/var/local/aeralogin+imp. backup-07.12.2025/aeralogin+implement/aeralogin/server.py`
  - Zeile 3395-3665: `/oauth/authorize` Endpoint
  - Zeile 3607: Aktueller `personal_sign` Aufruf (zu ersetzen)

---

**Erstellt**: 2025-12-28  
**Status**: 🔴 OFFEN - Implementierung erforderlich  
**Priorität**: 🔥 HOCH - Betrifft Mobile OAuth Flow
