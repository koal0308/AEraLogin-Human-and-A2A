#!/usr/bin/env python3
"""Test adminAdjust Score Update"""
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

# Richtige ABI mit adminAdjust und getResonance
abi = json.loads('[{"inputs":[{"internalType":"address","name":"user","type":"address"},{"internalType":"uint256","name":"newAmount","type":"uint256"}],"name":"adminAdjust","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"user","type":"address"}],"name":"getResonance","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"}]')

contract = w3.eth.contract(address=score_address, abi=abi)

test_user = "0x9AD57E3950CA5dc763EF15cE4B271dcb6005983b"
test_score = 99  # Test mit neuem Score-Wert

print("🧪 TEST: adminAdjust() SCORE UPDATE")
print("=" * 70)
print(f"Contract:      {score_address}")
print(f"Backend:       {account.address}")
print(f"Backend ETH:   {w3.eth.get_balance(account.address) / 1e18:.6f}")
print(f"Test User:     {test_user}")
print(f"New Score:     {test_score}")
print("=" * 70)

# 1. Aktueller Score
print(f"\n1️⃣ AKTUELLER SCORE:")
try:
    current_score = contract.functions.getResonance(test_user).call()
    print(f"   Current: {current_score}")
except Exception as e:
    print(f"   Current: 0 (nicht gesetzt oder Error: {str(e)[:50]})")
    current_score = 0

# 2. adminAdjust aufrufen
print(f"\n2️⃣ SCORE UPDATE MIT adminAdjust:")
try:
    tx = contract.functions.adminAdjust(test_user, test_score).build_transaction({
        'from': account.address,
        'nonce': w3.eth.get_transaction_count(account.address),
        'gas': 150000,
        'gasPrice': w3.eth.gas_price,
    })
    
    print(f"   📤 Transaction gebaut")
    print(f"      Gas: {tx['gas']:,}")
    print(f"      Nonce: {tx['nonce']}")
    
    signed_tx = w3.eth.account.sign_transaction(tx, backend_key)
    
    print(f"\n   ⏳ Sende Transaction...")
    tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
    print(f"   📤 TX: {tx_hash.hex()}")
    print(f"   🔗 https://basescan.org/tx/{tx_hash.hex()}")
    
    print(f"\n   ⏳ Warte auf Bestätigung...")
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
    
    if receipt['status'] == 1:
        print(f"\n   ✅ ✅ ✅  SUCCESS! ✅ ✅ ✅")
        print(f"   Block: {receipt['blockNumber']}")
        print(f"   Gas Used: {receipt['gasUsed']:,}")
        
        # Prüfe neuen Score
        try:
            new_score = contract.functions.getResonance(test_user).call()
            print(f"\n   �� SCORE UPDATE:")
            print(f"      Vorher: {current_score}")
            print(f"      Nachher: {new_score}")
            
            if new_score == test_score:
                print(f"\n   🎉 🎉 🎉  PERFEKT! Score ist auf Blockchain! 🎉 �� 🎉")
            else:
                print(f"\n   ⚠️  Score stimmt nicht überein (erwartet {test_score}, bekommen {new_score})")
        except Exception as e:
            print(f"\n   ⚠️  Score-Abfrage fehlgeschlagen: {str(e)}")
            
    else:
        print(f"\n   ❌ FAILED!")
        print(f"   Block: {receipt['blockNumber']}")
        print(f"   Gas Used: {receipt['gasUsed']:,}")
        
except Exception as e:
    print(f"   ❌ Error: {str(e)}")

print("\n" + "=" * 70)

