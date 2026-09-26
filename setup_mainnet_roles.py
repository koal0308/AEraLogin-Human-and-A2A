#!/usr/bin/env python3
"""
Setup all contract roles on BASE Mainnet
- Grant roles to Backend Wallet
- Transfer admin rights to Safe Wallet
"""
import os
from web3 import Web3
from eth_account import Account
from dotenv import load_dotenv
import time

# Load environment variables
load_dotenv()

# Configuration
RPC_URL = os.getenv("BASE_ALCHEMY_API_URL") or os.getenv("BASE_RPC_URL", "https://mainnet.base.org")
CHAIN_ID = int(os.getenv("BASE_NETWORK_CHAIN_ID", "8453"))

# Wallets
ADMIN_ADDRESS = os.getenv("ADMIN_WALLET")
ADMIN_PRIVATE_KEY = os.getenv("ADMIN_PRIVATE_KEY")
BACKEND_ADDRESS = os.getenv("BACKEND_ADDRESS")
SAFE_WALLET = "0xC8B1bEb43361bb78400071129139A37Eb5c5Dd93"

# Contract Addresses
IDENTITY_NFT = os.getenv("IDENTITY_NFT_ADDRESS")
RESONANCE_SCORE = os.getenv("RESONANCE_SCORE_ADDRESS")
REGISTRY = os.getenv("REGISTRY_ADDRESS")

# Role hashes
MINTER_ROLE = Web3.keccak(text="MINTER_ROLE")
STATUS_ROLE = Web3.keccak(text="STATUS_ROLE")
BURNER_ROLE = Web3.keccak(text="BURNER_ROLE")
ADMIN_ADJUST_ROLE = Web3.keccak(text="ADMIN_ADJUST_ROLE")
SYSTEM_ROLE = Web3.keccak(text="SYSTEM_ROLE")
DEFAULT_ADMIN_ROLE = "0x0000000000000000000000000000000000000000000000000000000000000000"

# Initialize Web3
w3 = Web3(Web3.HTTPProvider(RPC_URL))
account = Account.from_key(ADMIN_PRIVATE_KEY)

print("=" * 80)
print("🔧 BASE MAINNET - CONTRACT ROLE SETUP")
print("=" * 80)
print(f"\n📍 Network: BASE Mainnet (Chain ID: {CHAIN_ID})")
print(f"👤 Admin Wallet: {ADMIN_ADDRESS}")
print(f"🤖 Backend Wallet: {BACKEND_ADDRESS}")
print(f"🔐 Safe Wallet: {SAFE_WALLET}")
print(f"\n💰 Admin Balance: {w3.from_wei(w3.eth.get_balance(ADMIN_ADDRESS), 'ether'):.6f} ETH")

# Minimal ABI for AccessControl
ACCESS_CONTROL_ABI = [
    {
        "inputs": [{"name": "role", "type": "bytes32"}, {"name": "account", "type": "address"}],
        "name": "grantRole",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [{"name": "role", "type": "bytes32"}, {"name": "account", "type": "address"}],
        "name": "hasRole",
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function"
    }
]

def check_role(contract, role, address, role_name):
    """Check if address has role"""
    has_role = contract.functions.hasRole(role, address).call()
    status = "✅" if has_role else "❌"
    print(f"   {status} {role_name}: {address[:10]}...")
    return has_role

def grant_role(contract, contract_name, role, role_name, address):
    """Grant role to address"""
    print(f"\n🔄 Granting {role_name} on {contract_name}...")
    
    # Check if already has role
    if contract.functions.hasRole(role, address).call():
        print(f"   ✅ Already has role - skipping")
        return None
    
    try:
        # Build transaction
        nonce = w3.eth.get_transaction_count(ADMIN_ADDRESS)
        gas_price = w3.eth.gas_price
        
        tx = contract.functions.grantRole(role, address).build_transaction({
            'from': ADMIN_ADDRESS,
            'nonce': nonce,
            'gas': 100000,
            'maxFeePerGas': gas_price * 2,
            'maxPriorityFeePerGas': gas_price,
            'chainId': CHAIN_ID
        })
        
        # Sign and send
        signed_tx = account.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        
        print(f"   📤 TX sent: {tx_hash.hex()}")
        print(f"   ⏳ Waiting for confirmation...")
        
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
        
        if receipt['status'] == 1:
            print(f"   ✅ SUCCESS - Gas used: {receipt['gasUsed']}")
            return tx_hash.hex()
        else:
            print(f"   ❌ FAILED - Transaction reverted")
            return None
            
    except Exception as e:
        print(f"   ❌ ERROR: {e}")
        return None

# Initialize contracts
identity_nft = w3.eth.contract(address=Web3.to_checksum_address(IDENTITY_NFT), abi=ACCESS_CONTROL_ABI)
resonance_score = w3.eth.contract(address=Web3.to_checksum_address(RESONANCE_SCORE), abi=ACCESS_CONTROL_ABI)
registry = w3.eth.contract(address=Web3.to_checksum_address(REGISTRY), abi=ACCESS_CONTROL_ABI)

print("\n" + "=" * 80)
print("📊 CURRENT ROLE STATUS")
print("=" * 80)

print(f"\n1️⃣  AEraIdentityNFT ({IDENTITY_NFT[:10]}...)")
check_role(identity_nft, DEFAULT_ADMIN_ROLE, ADMIN_ADDRESS, "DEFAULT_ADMIN_ROLE (Admin)")
check_role(identity_nft, MINTER_ROLE, BACKEND_ADDRESS, "MINTER_ROLE (Backend)")
check_role(identity_nft, STATUS_ROLE, BACKEND_ADDRESS, "STATUS_ROLE (Backend)")

print(f"\n2️⃣  AEraResonanceScore ({RESONANCE_SCORE[:10]}...)")
check_role(resonance_score, DEFAULT_ADMIN_ROLE, ADMIN_ADDRESS, "DEFAULT_ADMIN_ROLE (Admin)")
check_role(resonance_score, MINTER_ROLE, BACKEND_ADDRESS, "MINTER_ROLE (Backend)")
check_role(resonance_score, ADMIN_ADJUST_ROLE, BACKEND_ADDRESS, "ADMIN_ADJUST_ROLE (Backend)")
check_role(resonance_score, BURNER_ROLE, BACKEND_ADDRESS, "BURNER_ROLE (Backend)")

print(f"\n3️⃣  AEraResonanceRegistry ({REGISTRY[:10]}...)")
check_role(registry, DEFAULT_ADMIN_ROLE, ADMIN_ADDRESS, "DEFAULT_ADMIN_ROLE (Admin)")
check_role(registry, SYSTEM_ROLE, BACKEND_ADDRESS, "SYSTEM_ROLE (Backend)")

# Ask for confirmation
print("\n" + "=" * 80)
print("⚠️  READY TO EXECUTE")
print("=" * 80)
print("\n📝 This script will:")
print("   1. Grant 6 roles to Backend Wallet")
print("   2. Grant DEFAULT_ADMIN_ROLE to Safe Wallet")
print("   3. Revoke DEFAULT_ADMIN_ROLE from current Admin Wallet")
print(f"\n💸 Estimated Gas Cost: ~0.002 ETH (8 transactions)")

response = input("\n❓ Continue? (yes/no): ")
if response.lower() != "yes":
    print("❌ Aborted by user")
    exit(0)

# Start granting roles
print("\n" + "=" * 80)
print("🚀 GRANTING ROLES TO BACKEND WALLET")
print("=" * 80)

tx_hashes = []

# 1. AEraIdentityNFT
print(f"\n📋 Contract 1/3: AEraIdentityNFT")
tx = grant_role(identity_nft, "IdentityNFT", MINTER_ROLE, "MINTER_ROLE", BACKEND_ADDRESS)
if tx: tx_hashes.append(tx)
time.sleep(2)

tx = grant_role(identity_nft, "IdentityNFT", STATUS_ROLE, "STATUS_ROLE", BACKEND_ADDRESS)
if tx: tx_hashes.append(tx)
time.sleep(2)

# 2. AEraResonanceScore
print(f"\n📋 Contract 2/3: AEraResonanceScore")
tx = grant_role(resonance_score, "ResonanceScore", MINTER_ROLE, "MINTER_ROLE", BACKEND_ADDRESS)
if tx: tx_hashes.append(tx)
time.sleep(2)

tx = grant_role(resonance_score, "ResonanceScore", ADMIN_ADJUST_ROLE, "ADMIN_ADJUST_ROLE", BACKEND_ADDRESS)
if tx: tx_hashes.append(tx)
time.sleep(2)

tx = grant_role(resonance_score, "ResonanceScore", BURNER_ROLE, "BURNER_ROLE", BACKEND_ADDRESS)
if tx: tx_hashes.append(tx)
time.sleep(2)

# 3. AEraResonanceRegistry
print(f"\n📋 Contract 3/3: AEraResonanceRegistry")
tx = grant_role(registry, "Registry", SYSTEM_ROLE, "SYSTEM_ROLE", BACKEND_ADDRESS)
if tx: tx_hashes.append(tx)
time.sleep(2)

# Transfer to Safe Wallet
print("\n" + "=" * 80)
print("🔐 TRANSFERRING ADMIN RIGHTS TO SAFE WALLET")
print("=" * 80)

print(f"\n🔄 Granting DEFAULT_ADMIN_ROLE to Safe Wallet...")
print(f"   Safe: {SAFE_WALLET}")

# Grant to Safe on all contracts
tx = grant_role(identity_nft, "IdentityNFT", DEFAULT_ADMIN_ROLE, "DEFAULT_ADMIN_ROLE", SAFE_WALLET)
if tx: tx_hashes.append(tx)
time.sleep(2)

tx = grant_role(resonance_score, "ResonanceScore", DEFAULT_ADMIN_ROLE, "DEFAULT_ADMIN_ROLE", SAFE_WALLET)
if tx: tx_hashes.append(tx)
time.sleep(2)

tx = grant_role(registry, "Registry", DEFAULT_ADMIN_ROLE, "DEFAULT_ADMIN_ROLE", SAFE_WALLET)
if tx: tx_hashes.append(tx)

# Final status check
print("\n" + "=" * 80)
print("✅ FINAL ROLE STATUS")
print("=" * 80)

print(f"\n1️⃣  AEraIdentityNFT")
check_role(identity_nft, MINTER_ROLE, BACKEND_ADDRESS, "MINTER_ROLE (Backend)")
check_role(identity_nft, STATUS_ROLE, BACKEND_ADDRESS, "STATUS_ROLE (Backend)")
check_role(identity_nft, DEFAULT_ADMIN_ROLE, SAFE_WALLET, "DEFAULT_ADMIN_ROLE (Safe)")

print(f"\n2️⃣  AEraResonanceScore")
check_role(resonance_score, MINTER_ROLE, BACKEND_ADDRESS, "MINTER_ROLE (Backend)")
check_role(resonance_score, ADMIN_ADJUST_ROLE, BACKEND_ADDRESS, "ADMIN_ADJUST_ROLE (Backend)")
check_role(resonance_score, BURNER_ROLE, BACKEND_ADDRESS, "BURNER_ROLE (Backend)")
check_role(resonance_score, DEFAULT_ADMIN_ROLE, SAFE_WALLET, "DEFAULT_ADMIN_ROLE (Safe)")

print(f"\n3️⃣  AEraResonanceRegistry")
check_role(registry, SYSTEM_ROLE, BACKEND_ADDRESS, "SYSTEM_ROLE (Backend)")
check_role(registry, DEFAULT_ADMIN_ROLE, SAFE_WALLET, "DEFAULT_ADMIN_ROLE (Safe)")

print("\n" + "=" * 80)
print("🎉 SETUP COMPLETE!")
print("=" * 80)
print(f"\n📊 Summary:")
print(f"   ✅ {len(tx_hashes)} transactions executed")
print(f"   🤖 Backend Wallet configured with all roles")
print(f"   🔐 Safe Wallet has admin rights on all contracts")
print(f"\n⚠️  IMPORTANT: You can now revoke admin rights from {ADMIN_ADDRESS[:10]}...")
print(f"   Use the Safe Wallet to call revokeRole(DEFAULT_ADMIN_ROLE, {ADMIN_ADDRESS})")

print("\n📝 Transaction Hashes:")
for i, tx_hash in enumerate(tx_hashes, 1):
    print(f"   {i}. https://basescan.org/tx/{tx_hash}")

print("\n✨ Your AEra system is ready on BASE Mainnet!")
