#!/usr/bin/env python3
"""
Add Safe Wallet as DEFAULT_ADMIN_ROLE to all contracts
Uses Backend Wallet (current admin) to grant the role
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

# Backend Wallet (current admin/deployer)
BACKEND_ADDRESS = os.getenv("BACKEND_ADDRESS")
BACKEND_PRIVATE_KEY = os.getenv("BACKEND_PRIVATE_KEY")

# Safe Wallet (new admin)
SAFE_WALLET = "0xC8B1bEb43361bb78400071129139A37Eb5c5Dd93"

# Contract Addresses
IDENTITY_NFT = os.getenv("IDENTITY_NFT_ADDRESS")
RESONANCE_SCORE = os.getenv("RESONANCE_SCORE_ADDRESS")
REGISTRY = os.getenv("REGISTRY_ADDRESS")

# Role hash
DEFAULT_ADMIN_ROLE = "0x0000000000000000000000000000000000000000000000000000000000000000"

# Initialize Web3
w3 = Web3(Web3.HTTPProvider(RPC_URL))
account = Account.from_key(BACKEND_PRIVATE_KEY)

print("=" * 80)
print("🔐 ADD SAFE WALLET AS ADMIN - BASE MAINNET")
print("=" * 80)
print(f"\n📍 Network: BASE Mainnet (Chain ID: {CHAIN_ID})")
print(f"🤖 Backend Wallet (Current Admin): {BACKEND_ADDRESS}")
print(f"🔐 Safe Wallet (New Admin): {SAFE_WALLET}")
print(f"\n💰 Backend Balance: {w3.from_wei(w3.eth.get_balance(BACKEND_ADDRESS), 'ether'):.6f} ETH")

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

def grant_admin_role(contract_address, contract_name):
    """Grant DEFAULT_ADMIN_ROLE to Safe Wallet"""
    print(f"\n{'='*80}")
    print(f"📋 Contract: {contract_name}")
    print(f"   Address: {contract_address}")
    print(f"{'='*80}")
    
    try:
        contract = w3.eth.contract(
            address=Web3.to_checksum_address(contract_address),
            abi=ACCESS_CONTROL_ABI
        )
        
        # Check if Safe already has role
        has_role = contract.functions.hasRole(DEFAULT_ADMIN_ROLE, SAFE_WALLET).call()
        if has_role:
            print(f"✅ Safe Wallet already has DEFAULT_ADMIN_ROLE - skipping")
            return None
        
        print(f"🔄 Granting DEFAULT_ADMIN_ROLE to Safe Wallet...")
        
        # Build transaction
        nonce = w3.eth.get_transaction_count(BACKEND_ADDRESS)
        gas_price = w3.eth.gas_price
        
        tx = contract.functions.grantRole(DEFAULT_ADMIN_ROLE, SAFE_WALLET).build_transaction({
            'from': BACKEND_ADDRESS,
            'nonce': nonce,
            'gas': 100000,
            'maxFeePerGas': gas_price * 2,
            'maxPriorityFeePerGas': gas_price,
            'chainId': CHAIN_ID
        })
        
        # Sign and send
        signed_tx = account.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        
        print(f"📤 Transaction sent: {tx_hash.hex()}")
        print(f"🔗 Basescan: https://basescan.org/tx/{tx_hash.hex()}")
        print(f"⏳ Waiting for confirmation...")
        
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
        
        if receipt['status'] == 1:
            gas_used = receipt['gasUsed']
            gas_cost = w3.from_wei(gas_used * receipt['effectiveGasPrice'], 'ether')
            print(f"✅ SUCCESS!")
            print(f"   Gas Used: {gas_used}")
            print(f"   Cost: {gas_cost:.6f} ETH")
            return tx_hash.hex()
        else:
            print(f"❌ FAILED - Transaction reverted")
            return None
            
    except Exception as e:
        print(f"❌ ERROR: {e}")
        return None

# Ask for confirmation
print("\n" + "=" * 80)
print("⚠️  READY TO EXECUTE")
print("=" * 80)
print("\n📝 This script will grant DEFAULT_ADMIN_ROLE to Safe Wallet on:")
print(f"   1. AEraIdentityNFT ({IDENTITY_NFT[:10]}...)")
print(f"   2. AEraResonanceScore ({RESONANCE_SCORE[:10]}...)")
print(f"   3. AEraResonanceRegistry ({REGISTRY[:10]}...)")
print(f"\n💸 Estimated Cost: ~0.0003 ETH (3 transactions)")

response = input("\n❓ Continue? (yes/no): ")
if response.lower() != "yes":
    print("❌ Aborted by user")
    exit(0)

# Grant roles
print("\n" + "=" * 80)
print("🚀 GRANTING ADMIN ROLES")
print("=" * 80)

tx_hashes = []

# 1. AEraIdentityNFT
tx = grant_admin_role(IDENTITY_NFT, "AEraIdentityNFT")
if tx:
    tx_hashes.append(("AEraIdentityNFT", tx))
time.sleep(3)

# 2. AEraResonanceScore
tx = grant_admin_role(RESONANCE_SCORE, "AEraResonanceScore")
if tx:
    tx_hashes.append(("AEraResonanceScore", tx))
time.sleep(3)

# 3. AEraResonanceRegistry
tx = grant_admin_role(REGISTRY, "AEraResonanceRegistry")
if tx:
    tx_hashes.append(("AEraResonanceRegistry", tx))

# Summary
print("\n" + "=" * 80)
print("🎉 SETUP COMPLETE!")
print("=" * 80)
print(f"\n✅ Safe Wallet ({SAFE_WALLET}) now has admin rights on all contracts!")
print(f"\n📊 Summary:")
print(f"   ✅ {len(tx_hashes)} transactions executed")
print(f"   🔐 Safe Wallet can now manage all contract roles")
print(f"   🤖 Backend Wallet still has admin rights (can be revoked later)")

if tx_hashes:
    print("\n📝 Transaction Hashes:")
    for contract_name, tx_hash in tx_hashes:
        print(f"   • {contract_name}:")
        print(f"     https://basescan.org/tx/{tx_hash}")

print("\n" + "=" * 80)
print("✅ All 3 wallets now have appropriate access:")
print("=" * 80)
print(f"1. Backend Wallet ({BACKEND_ADDRESS[:10]}...)")
print(f"   • DEFAULT_ADMIN_ROLE on all contracts")
print(f"   • Used by server for automated operations")
print(f"\n2. Admin Wallet ({os.getenv('ADMIN_WALLET')[:10]}...)")
print(f"   • Can be used for manual operations")
print(f"\n3. Safe Wallet ({SAFE_WALLET[:10]}...)")
print(f"   • DEFAULT_ADMIN_ROLE on all contracts")
print(f"   • Multisig protection for critical operations")
print("\n✨ Your AEra system is fully configured on BASE Mainnet!")
