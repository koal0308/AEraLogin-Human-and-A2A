#!/usr/bin/env python3
"""
Enable Soulbound Mode for AEra Profile NFT

This script activates soulbound mode on the Profile NFT contract,
which blocks all transfers (except mint/burn).

Usage: python3 enable_soulbound_mode.py
"""

import os
import sys
from web3 import Web3
from eth_account import Account
from dotenv import load_dotenv

# Load environment
load_dotenv()

# Configuration
RPC_URL = os.getenv("BASE_ALCHEMY_API_URL") or os.getenv("BASE_RPC_URL", "https://mainnet.base.org")
PRIVATE_KEY = os.getenv("BACKEND_PRIVATE_KEY") or os.getenv("PRIVATE_KEY")
PROFILE_NFT_ADDRESS = os.getenv("PROFILE_NFT_ADDRESS", "0x0a630A3Dc0C7387e0226D1b285C43B753506b27E")

# Profile NFT ABI (minimal - only what we need)
PROFILE_NFT_ABI = [
    {
        "inputs": [],
        "name": "soulboundMode",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "bool", "name": "enabled", "type": "bool"}],
        "name": "setSoulboundMode",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    }
]

def main():
    """Enable soulbound mode on Profile NFT contract"""
    
    # Validate config
    if not PRIVATE_KEY:
        print("❌ ERROR: BACKEND_PRIVATE_KEY or PRIVATE_KEY not found in .env")
        sys.exit(1)
    
    # Connect to blockchain
    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    if not w3.is_connected():
        print(f"❌ ERROR: Cannot connect to RPC: {RPC_URL}")
        sys.exit(1)
    
    account = Account.from_key(PRIVATE_KEY)
    print(f"🌐 Connected to BASE Mainnet")
    print(f"💳 Admin Wallet: {account.address}")
    print(f"📄 Profile NFT: {PROFILE_NFT_ADDRESS}")
    print()
    
    # Load contract
    profile_nft = w3.eth.contract(
        address=Web3.to_checksum_address(PROFILE_NFT_ADDRESS),
        abi=PROFILE_NFT_ABI
    )
    
    # Check current soulbound status
    try:
        current_status = profile_nft.functions.soulboundMode().call()
        print(f"📊 Current soulbound mode: {current_status}")
        
        if current_status:
            print("✅ Soulbound mode already enabled. Nothing to do.")
            return
    except Exception as e:
        print(f"⚠️  Warning: Could not read current status: {e}")
    
    # Enable soulbound mode
    print("\n🔒 Enabling soulbound mode...")
    print("⏳ Building transaction...")
    
    try:
        # Get current gas price and nonce
        gas_price = w3.eth.gas_price
        nonce = w3.eth.get_transaction_count(account.address)
        
        print(f"⛽ Current gas price: {w3.from_wei(gas_price, 'gwei')} gwei")
        print(f"📊 Nonce: {nonce}")
        
        # Build transaction
        tx = profile_nft.functions.setSoulboundMode(True).build_transaction({
            'from': account.address,
            'nonce': nonce,
            'gas': 100000,
            'maxFeePerGas': int(gas_price * 1.5),
            'maxPriorityFeePerGas': w3.to_wei(0.001, 'gwei'),
            'chainId': w3.eth.chain_id
        })
        
        # Sign transaction
        print("✍️  Signing transaction...")
        signed_tx = account.sign_transaction(tx)
        
        # Send transaction
        print("📤 Sending transaction...")
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        print(f"📝 Transaction hash: {tx_hash.hex()}")
        
        # Wait for confirmation
        print("⏳ Waiting for confirmation (max 180 seconds)...")
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=180)
        
        if receipt['status'] == 1:
            print(f"✅ SUCCESS! Soulbound mode enabled.")
            print(f"🔗 Block: {receipt['blockNumber']}")
            print(f"⛽ Gas used: {receipt['gasUsed']:,}")
            
            # Verify new status
            new_status = profile_nft.functions.soulboundMode().call()
            print(f"📊 Verified soulbound mode: {new_status}")
            
            print("\n🎉 Profile NFTs are now SOULBOUND - transfers are blocked!")
        else:
            print(f"❌ Transaction failed!")
            print(f"Receipt: {receipt}")
            sys.exit(1)
            
    except Exception as e:
        print(f"❌ ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
