#!/usr/bin/env python3
"""
Set Base URIs for AEra Profile NFT Contract

This script configures the metadata endpoints for the Profile NFT contract.
Run this ONCE after deployment to point the contract to your metadata server.

Requirements:
- Backend wallet must have DEFAULT_ADMIN_ROLE on the Profile NFT contract
- Run from the aeralogin directory with .env loaded

Usage:
    python set_profile_base_uris.py
"""

import os
import sys
from dotenv import load_dotenv
from web3 import Web3
from eth_account import Account

# Load environment variables
load_dotenv()

# Configuration
PROFILE_NFT_ADDRESS = os.getenv("PROFILE_NFT_ADDRESS", "0x0a630A3Dc0C7387e0226D1b285C43B753506b27E")
PRIVATE_KEY = os.getenv("BACKEND_PRIVATE_KEY")
RPC_URL = os.getenv("BASE_ALCHEMY_API_URL") or os.getenv("BASE_RPC_URL", "https://mainnet.base.org")
CHAIN_ID = int(os.getenv("BASE_NETWORK_CHAIN_ID", 8453))

# Your metadata server URLs
PUBLIC_BASE_URI = "https://aeralogin.com/api/profile/public/"
PRIVATE_BASE_URI = "https://aeralogin.com/api/profile/private/"
CONTRACT_URI = "https://aeralogin.com/api/profile/contract.json"

# Minimal ABI for admin functions
ABI = [
    {
        "inputs": [
            {"internalType": "string", "name": "publicURI", "type": "string"},
            {"internalType": "string", "name": "privateURI", "type": "string"}
        ],
        "name": "setBaseURIs",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "string", "name": "uri", "type": "string"}],
        "name": "setContractURI",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "contractURI",
        "outputs": [{"internalType": "string", "name": "", "type": "string"}],
        "stateMutability": "view",
        "type": "function"
    }
]


def main():
    print("=" * 60)
    print("🎨 AEra Profile NFT - Set Base URIs")
    print("=" * 60)
    
    if not PRIVATE_KEY:
        print("❌ Error: BACKEND_PRIVATE_KEY not set in .env")
        sys.exit(1)
    
    # Connect to blockchain
    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    if not w3.is_connected():
        print("❌ Error: Could not connect to blockchain")
        sys.exit(1)
    
    print(f"✅ Connected to chain: {w3.eth.chain_id}")
    
    # Setup account
    account = Account.from_key(PRIVATE_KEY)
    print(f"💳 Using wallet: {account.address}")
    
    # Check balance
    balance = w3.eth.get_balance(account.address)
    balance_eth = Web3.from_wei(balance, 'ether')
    print(f"💰 Balance: {balance_eth:.6f} ETH")
    
    if balance_eth < 0.001:
        print("⚠️ Warning: Low balance, transaction might fail")
    
    # Setup contract
    contract = w3.eth.contract(
        address=Web3.to_checksum_address(PROFILE_NFT_ADDRESS),
        abi=ABI
    )
    
    print(f"\n📜 Profile NFT Contract: {PROFILE_NFT_ADDRESS}")
    print(f"\n🔗 URIs to set:")
    print(f"   Public:   {PUBLIC_BASE_URI}")
    print(f"   Private:  {PRIVATE_BASE_URI}")
    print(f"   Contract: {CONTRACT_URI}")
    
    # Confirm
    print("\n" + "=" * 60)
    response = input("Continue? (y/n): ").strip().lower()
    if response != 'y':
        print("Aborted.")
        sys.exit(0)
    
    # Transaction 1: Set Base URIs
    print("\n📤 Setting Base URIs...")
    try:
        nonce = w3.eth.get_transaction_count(account.address)
        
        tx = contract.functions.setBaseURIs(
            PUBLIC_BASE_URI,
            PRIVATE_BASE_URI
        ).build_transaction({
            'from': account.address,
            'nonce': nonce,
            'gas': 150000,
            'maxFeePerGas': w3.eth.gas_price * 2,
            'maxPriorityFeePerGas': w3.to_wei(0.001, 'gwei'),
            'chainId': CHAIN_ID
        })
        
        signed_tx = account.sign_transaction(tx)
        # Handle both old and new web3.py versions
        raw_tx = getattr(signed_tx, 'rawTransaction', None) or getattr(signed_tx, 'raw_transaction', None)
        tx_hash = w3.eth.send_raw_transaction(raw_tx)
        print(f"   TX Hash: {tx_hash.hex()}")
        
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
        if receipt['status'] == 1:
            print("   ✅ Base URIs set successfully!")
        else:
            print("   ❌ Transaction failed!")
            sys.exit(1)
            
    except Exception as e:
        print(f"   ❌ Error: {e}")
        sys.exit(1)
    
    # Transaction 2: Set Contract URI
    print("\n📤 Setting Contract URI...")
    try:
        nonce = w3.eth.get_transaction_count(account.address)
        
        tx = contract.functions.setContractURI(CONTRACT_URI).build_transaction({
            'from': account.address,
            'nonce': nonce,
            'gas': 100000,
            'maxFeePerGas': w3.eth.gas_price * 2,
            'maxPriorityFeePerGas': w3.to_wei(0.001, 'gwei'),
            'chainId': CHAIN_ID
        })
        
        signed_tx = account.sign_transaction(tx)
        # Handle both old and new web3.py versions
        raw_tx = getattr(signed_tx, 'rawTransaction', None) or getattr(signed_tx, 'raw_transaction', None)
        tx_hash = w3.eth.send_raw_transaction(raw_tx)
        print(f"   TX Hash: {tx_hash.hex()}")
        
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
        if receipt['status'] == 1:
            print("   ✅ Contract URI set successfully!")
        else:
            print("   ❌ Transaction failed!")
            sys.exit(1)
            
    except Exception as e:
        print(f"   ❌ Error: {e}")
        sys.exit(1)
    
    # Verify
    print("\n🔍 Verifying...")
    try:
        contract_uri = contract.functions.contractURI().call()
        print(f"   Contract URI: {contract_uri}")
    except Exception as e:
        print(f"   Could not verify: {e}")
    
    print("\n" + "=" * 60)
    print("✅ All URIs configured successfully!")
    print("\nNext steps:")
    print("1. Wait 24-48h for OpenSea to index the collection")
    print("2. Or manually refresh at: https://opensea.io/collection/aera-profile")
    print("=" * 60)


if __name__ == "__main__":
    main()
