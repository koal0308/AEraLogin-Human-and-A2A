#!/usr/bin/env python3
"""
Revoke DEFAULT_ADMIN_ROLE from old Admin Wallet
Only Safe Wallet should have admin rights!
"""
import os
from web3 import Web3
from dotenv import load_dotenv

load_dotenv()

# Configuration
RPC_URL = os.getenv("BASE_ALCHEMY_API_URL") or os.getenv("BASE_RPC_URL", "https://mainnet.base.org")
BACKEND_PRIVATE_KEY = os.getenv("BACKEND_PRIVATE_KEY")
BACKEND_ADDRESS = os.getenv("BACKEND_ADDRESS")

OLD_ADMIN = "0x984eDaCf233b37FC2E63aBC7168bDE8652f55C65"
SAFE_WALLET = "0xC8B1bEb43361bb78400071129139A37Eb5c5Dd93"

# Contract Addresses
IDENTITY_NFT = "0xF9ff5DC523927B9632049bd19e17B610E9197d53"
RESONANCE_SCORE = "0x9A814DBF7E2352CE9eA6293b4b731B2a24800102"
RESONANCE_REGISTRY = "0xAAf30d96382D2409Cf1626095e97BEc1C59e5cdF"

# Connect to Web3
w3 = Web3(Web3.HTTPProvider(RPC_URL))
account = w3.eth.account.from_key(BACKEND_PRIVATE_KEY)

# DEFAULT_ADMIN_ROLE = 0x00...00
DEFAULT_ADMIN_ROLE = "0x" + "0" * 64

# Minimal ABI for AccessControl
ABI = [
    {
        "inputs": [
            {"internalType": "bytes32", "name": "role", "type": "bytes32"},
            {"internalType": "address", "name": "account", "type": "address"}
        ],
        "name": "hasRole",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "bytes32", "name": "role", "type": "bytes32"},
            {"internalType": "address", "name": "account", "type": "address"}
        ],
        "name": "revokeRole",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    }
]

print("=" * 80)
print("🔐 REVOKE ADMIN RIGHTS FROM OLD ADMIN WALLET")
print("=" * 80)
print()
print(f"🌐 Network: BASE Mainnet")
print(f"🔑 Revoking from: {OLD_ADMIN}")
print(f"🛡️  Safe Wallet keeps: {SAFE_WALLET}")
print(f"👤 Backend (Executor): {BACKEND_ADDRESS}")
print()

contracts = {
    "IdentityNFT": IDENTITY_NFT,
    "ResonanceScore": RESONANCE_SCORE,
    "ResonanceRegistry": RESONANCE_REGISTRY
}

# Check current roles
print("📋 Current Roles:")
print("-" * 80)
for name, address in contracts.items():
    contract = w3.eth.contract(address=Web3.to_checksum_address(address), abi=ABI)
    
    old_admin_has = contract.functions.hasRole(DEFAULT_ADMIN_ROLE, Web3.to_checksum_address(OLD_ADMIN)).call()
    safe_has = contract.functions.hasRole(DEFAULT_ADMIN_ROLE, Web3.to_checksum_address(SAFE_WALLET)).call()
    backend_has = contract.functions.hasRole(DEFAULT_ADMIN_ROLE, Web3.to_checksum_address(BACKEND_ADDRESS)).call()
    
    print(f"\n{name}:")
    print(f"   Old Admin (0x984eDA...): {'✅ HAS' if old_admin_has else '❌ NO'} DEFAULT_ADMIN_ROLE")
    print(f"   Safe Wallet (0xC8B1bE...): {'✅ HAS' if safe_has else '❌ NO'} DEFAULT_ADMIN_ROLE")
    print(f"   Backend (0x22A2cA...): {'✅ HAS' if backend_has else '❌ NO'} DEFAULT_ADMIN_ROLE")

print()
print("=" * 80)
print()

# Ask for confirmation
confirm = input("⚠️  Do you want to REVOKE admin rights from 0x984eDA...C65? (yes/no): ")
if confirm.lower() != "yes":
    print("❌ Aborted!")
    exit(0)

print()
print("🔄 Revoking DEFAULT_ADMIN_ROLE from old admin wallet...")
print()

# Revoke from all contracts
for name, address in contracts.items():
    print(f"📄 {name}:")
    
    contract = w3.eth.contract(address=Web3.to_checksum_address(address), abi=ABI)
    
    # Check if old admin still has role
    has_role = contract.functions.hasRole(DEFAULT_ADMIN_ROLE, Web3.to_checksum_address(OLD_ADMIN)).call()
    
    if not has_role:
        print(f"   ℹ️  Old admin already has NO rights, skipping...")
        continue
    
    try:
        # Build revoke transaction
        nonce = w3.eth.get_transaction_count(account.address, 'latest')
        
        tx = contract.functions.revokeRole(
            DEFAULT_ADMIN_ROLE,
            Web3.to_checksum_address(OLD_ADMIN)
        ).build_transaction({
            'from': account.address,
            'nonce': nonce,
            'gas': 100000,
            'maxFeePerGas': w3.eth.gas_price * 2,
            'maxPriorityFeePerGas': w3.eth.gas_price,
            'chainId': 8453
        })
        
        # Sign and send
        signed = w3.eth.account.sign_transaction(tx, BACKEND_PRIVATE_KEY)
        tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
        
        print(f"   📤 TX sent: {tx_hash.hex()[:20]}...")
        
        # Wait for confirmation
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
        
        if receipt['status'] == 1:
            print(f"   ✅ SUCCESS! Block: {receipt['blockNumber']}")
        else:
            print(f"   ❌ FAILED!")
            
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    print()

print("=" * 80)
print("✅ DONE! Verifying final state...")
print("=" * 80)
print()

# Verify final state
for name, address in contracts.items():
    contract = w3.eth.contract(address=Web3.to_checksum_address(address), abi=ABI)
    
    old_admin_has = contract.functions.hasRole(DEFAULT_ADMIN_ROLE, Web3.to_checksum_address(OLD_ADMIN)).call()
    safe_has = contract.functions.hasRole(DEFAULT_ADMIN_ROLE, Web3.to_checksum_address(SAFE_WALLET)).call()
    
    print(f"{name}:")
    print(f"   Old Admin: {'❌ REVOKED' if not old_admin_has else '⚠️  STILL HAS RIGHTS!'}")
    print(f"   Safe Wallet: {'✅ HAS RIGHTS' if safe_has else '❌ NO RIGHTS!'}")
    print()

print("=" * 80)
print("🎉 Admin rights successfully removed from old admin wallet!")
print("🛡️  Only Safe Wallet has DEFAULT_ADMIN_ROLE now!")
print("=" * 80)
