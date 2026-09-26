#!/usr/bin/env python3
"""
Grant UPDATER_ROLE to Backend Wallet
"""
from web3 import Web3
from dotenv import load_dotenv
import os
import json

load_dotenv()

# Config
rpc_url = os.getenv("BASE_ALCHEMY_API_URL") or os.getenv("BASE_RPC_URL", "https://mainnet.base.org")
score_address = os.getenv("RESONANCE_SCORE_ADDRESS", "0x9A814DBF7E2352CE9eA6293b4b731B2a24800102")
backend_key = os.getenv("BACKEND_PRIVATE_KEY")

if not backend_key:
    print("❌ BACKEND_PRIVATE_KEY nicht gefunden!")
    exit(1)

# Connect
w3 = Web3(Web3.HTTPProvider(rpc_url))
account = w3.eth.account.from_key(backend_key)

print("\n" + "="*70)
print("🔑 UPDATER_ROLE AUTOMATISCH VERGEBEN")
print("="*70 + "\n")

print(f"Backend Wallet: {account.address}")
print(f"Score Contract: {score_address}\n")

# Contract ABI
abi = json.loads('[{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"account","type":"address"}],"name":"grantRole","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"account","type":"address"}],"name":"hasRole","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"}]')

contract = w3.eth.contract(address=score_address, abi=abi)

# UPDATER_ROLE
UPDATER_ROLE = w3.keccak(text="UPDATER_ROLE")

print(f"UPDATER_ROLE Hash: {UPDATER_ROLE.hex()}\n")

# Check if already has role
has_role = contract.functions.hasRole(UPDATER_ROLE, account.address).call()

if has_role:
    print("✅ Backend Wallet hat bereits UPDATER_ROLE!")
    print("   Keine Aktion erforderlich.\n")
else:
    print("⏳ Vergebe UPDATER_ROLE...\n")
    
    # Build transaction
    nonce = w3.eth.get_transaction_count(account.address)
    
    tx = contract.functions.grantRole(UPDATER_ROLE, account.address).build_transaction({
        'from': account.address,
        'nonce': nonce,
        'gas': 100000,
        'maxFeePerGas': w3.eth.gas_price * 2,
        'maxPriorityFeePerGas': w3.eth.gas_price,
        'chainId': 84532
    })
    
    # Sign and send
    signed_tx = w3.eth.account.sign_transaction(tx, backend_key)
    raw_tx = getattr(signed_tx, 'rawTransaction', getattr(signed_tx, 'raw_transaction', None))
    tx_hash = w3.eth.send_raw_transaction(raw_tx)
    
    print(f"📤 Transaction gesendet: {tx_hash.hex()}")
    print(f"🔗 BaseScan: https://basescan.org/tx/{tx_hash.hex()}\n")
    
    print("⏳ Warte auf Bestätigung...")
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
    
    if receipt['status'] == 1:
        print("✅ ✅ ✅  UPDATER_ROLE ERFOLGREICH VERGEBEN!  ✅ ✅ ✅\n")
        print("🎉 Score Updates funktionieren jetzt!\n")
    else:
        print("❌ Transaction fehlgeschlagen!\n")
        print(f"   Gas Used: {receipt['gasUsed']}")
        print(f"   → Prüfe auf BaseScan für Details\n")

print("="*70 + "\n")
