"""
🔷 AEraLogin OAuth Smart Contract Wallet Support
================================================

This file contains the FIXED version of the /oauth/complete endpoint
with full Smart Contract Wallet support (EIP-1271).

PROBLEM: Current implementation only supports EOA wallets
SOLUTION: Add EIP-1271 verification like in /api/verify endpoint

FILE TO UPDATE: server.py
LINES TO REPLACE: 3660-3760 (oauth_complete function)
"""

# ========================================
# PASTE THIS CODE INTO server.py at line 3660
# ========================================

@app.post("/oauth/complete")
async def oauth_complete(req: Request):
    """
    Complete OAuth authorization after wallet signature
    
    ✅ FIXED: Now supports Smart Contract Wallets (EIP-1271)
    
    Request:
        {{
            "oauth_nonce": "...",
            "address": "0x...",
            "nonce": "...",
            "message": "...",
            "signature": "0x..."
        }}
    
    Response:
        {{
            "success": true,
            "code": "authorization_code"
        }}
    """
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
        # These signatures are much longer than 65 bytes
        is_smart_wallet_sig = len(signature) > 200 if signature else False
        
        log_activity("INFO", "OAUTH", f"Signature verification start", 
                    address=address[:10],
                    sig_length=len(signature) if signature else 0,
                    is_smart_wallet=is_smart_wallet_sig)
        
        try:
            from eth_account.messages import encode_defunct, defunct_hash_message
            from eth_account import Account
            
            # ========================================
            # SMART CONTRACT WALLET (EIP-1271) VERIFICATION
            # Coinbase Smart Wallet, Safe, Base Wallet, etc.
            # ========================================
            if is_smart_wallet_sig and message and nonce in message:
                log_activity("INFO", "OAUTH", f"Attempting EIP-1271 Smart Contract Wallet verification...")
                try:
                    from web3 import Web3
                    
                    # Connect to BASE mainnet
                    w3 = Web3(Web3.HTTPProvider('https://mainnet.base.org'))
                    
                    # EIP-1271 ABI - just the isValidSignature function
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
                    log_activity("INFO", "OAUTH", f"Message hash: {message_hash.hex()[:20]}...")
                    
                    # Create contract instance
                    wallet_contract = w3.eth.contract(
                        address=Web3.to_checksum_address(address),
                        abi=EIP1271_ABI
                    )
                    
                    # Convert signature to bytes
                    sig_bytes = bytes.fromhex(signature[2:]) if signature.startswith('0x') else bytes.fromhex(signature)
                    
                    # Call isValidSignature on the smart contract wallet
                    try:
                        result = wallet_contract.functions.isValidSignature(
                            message_hash,
                            sig_bytes
                        ).call()
                        
                        # EIP-1271 magic value for valid signature
                        MAGIC_VALUE = bytes.fromhex('1626ba7e')
                        
                        if result == MAGIC_VALUE:
                            signature_valid = True
                            log_activity("INFO", "OAUTH", f"✅ EIP-1271 Smart Contract Wallet verification SUCCESS!")
                        else:
                            log_activity("INFO", "OAUTH", f"EIP-1271 returned: {result.hex()} (expected 1626ba7e)")
                    except Exception as contract_error:
                        log_activity("INFO", "OAUTH", f"EIP-1271 contract call failed: {str(contract_error)}")
                        
                except Exception as eip1271_error:
                    log_activity("INFO", "OAUTH", f"EIP-1271 verification error: {str(eip1271_error)}")
            
            # ========================================
            # STANDARD EOA SIGNATURE VERIFICATION
            # MetaMask, Rainbow, Trust, etc.
            # ========================================
            if not signature_valid:
                # If frontend sent the message, use it directly
                if message and nonce in message:
                    try:
                        msg = encode_defunct(text=message)
                        recovered = Account.recover_message(msg, signature=signature)
                        
                        if recovered.lower() == address:
                            signature_valid = True
                            log_activity("INFO", "OAUTH", f"✅ EOA signature verification SUCCESS")
                        else:
                            log_activity("ERROR", "OAUTH", f"Signature verification FAILED", 
                                       address=address[:10], 
                                       recovered=recovered[:10])
                    except Exception as e:
                        log_activity("ERROR", "OAUTH", f"EOA verification error: {str(e)}")
            
            if not signature_valid:
                conn.close()
                return {"success": False, "error": "Signature verification failed - wallet signature invalid"}
            
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
            # Create user if doesn't exist (triggers NFT minting)
            conn.close()
            return {"success": False, "error": "Please register on AEraLogIn dashboard first to get your Identity NFT"}
        
        # Check NFT requirement (using identity_status from users table)
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
        
        # Update the authorization record with actual data
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
        
        log_activity("INFO", "OAUTH", f"✅ Authorization code generated for {address[:10]}", client_id=pending['client_id'])
        
        return {"success": True, "code": auth_code}
        
    except Exception as e:
        log_activity("ERROR", "OAUTH", f"OAuth complete error: {str(e)}")
        return {"success": False, "error": "Internal server error"}


# ========================================
# END OF FIX
# ========================================

"""
TESTING INSTRUCTIONS:
=====================

1. Backup current server.py:
   cp server.py server.py.backup-before-oauth-fix

2. Replace /oauth/complete function (lines 3660-3760) with the code above

3. Restart server:
   sudo systemctl restart aeralogin

4. Test with:
   - Desktop Browser + MetaMask (should still work - EOA)
   - BASE App Mobile + Smart Wallet (should now work - EIP-1271)
   - Warpcast + Connected Wallet (should work)

5. Check logs:
   tail -f /var/log/aeralogin/server.log | grep OAUTH

EXPECTED LOG OUTPUT (Success):
================================
INFO OAUTH Signature verification start address=0xdd05d4a5 sig_length=420 is_smart_wallet=True
INFO OAUTH Attempting EIP-1271 Smart Contract Wallet verification...
INFO OAUTH Message hash: 0x1a2b3c4d5e6f7890...
INFO OAUTH ✅ EIP-1271 Smart Contract Wallet verification SUCCESS!
INFO OAUTH ✅ Authorization code generated for 0xdd05d4a5 client_id=aera_f6c4c87a29aa2919662f029ac4695ab3

EXPECTED LOG OUTPUT (EOA):
===========================
INFO OAUTH Signature verification start address=0x742d35cc sig_length=132 is_smart_wallet=False
INFO OAUTH ✅ EOA signature verification SUCCESS
INFO OAUTH ✅ Authorization code generated for 0x742d35cc client_id=aera_f6c4c87a29aa2919662f029ac4695ab3
"""
