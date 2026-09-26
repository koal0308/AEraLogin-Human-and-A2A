#!/usr/bin/env python3
"""
Manual Score Update Test mit vollständiger Error-Analyse
"""
from web3 import Web3
from dotenv import load_dotenv
import os
import json

load_dotenv()

rpc_url = os.getenv("BASE_ALCHEMY_API_URL") or os.getenv("BASE_RPC_URL", "https://mainnet.base.org")
score_address = os.getenv("RESONANCE_SCORE_ADDRESS", "0x9A814DBF7E2352CE9eA6293b4b731B2a24800102")
backend_key = os.getenv("BACKEND_PRIVATE_KEY")

w3 = Web3(Web3.HTTPProvider(rpc_url))
account = w3.eth.account.from_key(backend_key)

# Erweiterte Score ABI mit mehr Funktionen
abi = json.loads('[{"inputs":[{"internalType":"address","name":"user","type":"address"},{"internalType":"uint256","name":"score","type":"uint256"}],"name":"updateScore","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"user","type":"address"}],"name":"getScore","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"paused","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"}]')

contract = w3.eth.contract(address=score_address, abi=abi)

test_user = "0x9AD57E3950CA5dc763EF15cE4B271dcb6005983b"
test_score = 75  # Neuer Score zum Testen

print("🧪 MANUELLER SCORE UPDATE TEST")
print("=" * 70)
print(f"Contract:      {score_address}")
print(f"Backend:       {account.address}")
print(f"Backend ETH:   {w3.eth.get_balance(account.address) / 1e18:.6f}")
print(f"Test User:     {test_user}")
print(f"New Score:     {test_score}")
print("=" * 70)

# 1. Prüfe ob Contract pausiert ist
print(f"\n1️⃣ PAUSE STATUS:")
try:
    is_paused = contract.functions.paused().call()
    if is_paused:
        print(f"   ❌ Contract ist PAUSIERT!")
    else:
        print(f"   ✅ Contract ist AKTIV")
except Exception as e:
    print(f"   ⚠️  Keine paused() Funktion: {str(e)[:50]}")

# 2. Prüfe UPDATER_ROLE
print(f"\n2️⃣ UPDATER_ROLE CHECK:")
try:
    role_abi = json.loads('[{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"account","type":"address"}],"name":"hasRole","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"}]')
    role_contract = w3.eth.contract(address=score_address, abi=role_abi)
    UPDATER_ROLE = w3.keccak(text="UPDATER_ROLE")
    has_role = role_contract.functions.hasRole(UPDATER_ROLE, account.address).call()
    if has_role:
        print(f"   ✅ Backend HAT UPDATER_ROLE")
    else:
        print(f"   ❌ Backend HAT KEINE UPDATER_ROLE!")
except Exception as e:
    print(f"   ❌ Role-Check gescheitert: {str(e)[:50]}")

# 3. Versuche Score-Update mit besserer Error-Handlung
print(f"\n3️⃣ SCORE UPDATE VERSUCH:")
try:
    # Build Transaction
    tx = contract.functions.updateScore(test_user, test_score).build_transaction({
        'from': account.address,
        'nonce': w3.eth.get_transaction_count(account.address),
        'gas': 150000,
        'gasPrice': w3.eth.gas_price,
    })
    
    print(f"   📤 Transaction gebaut:")
    print(f"      Gas: {tx['gas']:,}")
    print(f"      Gas Price: {tx['gasPrice'] / 1e9:.2f} Gwei")
    print(f"      Nonce: {tx['nonce']}")
    
    # Sign
    signed_tx = w3.eth.account.sign_transaction(tx, backend_key)
    
    # Send
    print(f"\n   ⏳ Sende Transaction...")
    tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
    print(f"   📤 TX gesendet: {tx_hash.hex()}")
    print(f"   🔗 https://basescan.org/tx/{tx_hash.hex()}")
    
    # Wait for receipt
    print(f"\n   ⏳ Warte auf Bestätigung...")
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
    
    if receipt['status'] == 1:
        print(f"\n   ✅ ✅ ✅  SUCCESS! ✅ ✅ ✅")
        print(f"   Block: {receipt['blockNumber']}")
        print(f"   Gas Used: {receipt['gasUsed']:,}")
        
        # Prüfe neuen Score
        try:
            new_score = contract.functions.getScore(test_user).call()
            print(f"   �� Neuer Score on-chain: {new_score}")
        except:
            print(f"   ⚠️  Score-Abfrage gescheitert (aber TX war erfolgreich!)")
            
    else:
        print(f"\n   ❌ ❌ ❌  FAILED! ❌ ❌ ❌")
        print(f"   Block: {receipt['blockNumber']}")
        print(f"   Gas Used: {receipt['gasUsed']:,}")
        print(f"\n   💡 Prüfe Transaction auf BaseScan für Details:")
        print(f"      https://basescan.org/tx/{tx_hash.hex()}")
        
except Exception as e:
    print(f"   ❌ Error: {str(e)}")
    
    # Detaillierte Error-Analyse
    if "insufficient funds" in str(e).lower():
        print(f"\n   💡 PROBLEM: Nicht genug ETH für Gas")
    elif "nonce" in str(e).lower():
        print(f"\n   💡 PROBLEM: Nonce-Fehler (Transaction conflict)")
    elif "gas" in str(e).lower():
        print(f"\n   💡 PROBLEM: Gas-bezogenes Problem")
    else:
        print(f"\n   💡 Unbekannter Fehler - siehe Details oben")

print("\n" + "=" * 70)

