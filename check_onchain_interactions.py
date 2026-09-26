#!/usr/bin/env python3
"""
Check all onchain interactions from BASE Mainnet Registry
"""
import os
from web3 import Web3
from dotenv import load_dotenv

load_dotenv()

RPC_URL = os.getenv("BASE_ALCHEMY_API_URL") or os.getenv("BASE_RPC_URL", "https://mainnet.base.org")
REGISTRY_ADDRESS = os.getenv("REGISTRY_ADDRESS")

w3 = Web3(Web3.HTTPProvider(RPC_URL))

# Registry ABI - minimal for reading interactions
REGISTRY_ABI = [
    {
        "inputs": [],
        "name": "getTotalInteractions",
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [{"name": "index", "type": "uint256"}],
        "name": "getInteraction",
        "outputs": [{
            "components": [
                {"name": "follower", "type": "address"},
                {"name": "creator", "type": "address"},
                {"name": "linkId", "type": "bytes32"},
                {"name": "actionType", "type": "uint8"},
                {"name": "weightFollower", "type": "uint256"},
                {"name": "weightCreator", "type": "uint256"},
                {"name": "timestamp", "type": "uint256"}
            ],
            "name": "",
            "type": "tuple"
        }],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [{"name": "user", "type": "address"}],
        "name": "getUserInteractions",
        "outputs": [{
            "components": [
                {"name": "follower", "type": "address"},
                {"name": "creator", "type": "address"},
                {"name": "linkId", "type": "bytes32"},
                {"name": "actionType", "type": "uint8"},
                {"name": "weightFollower", "type": "uint256"},
                {"name": "weightCreator", "type": "uint256"},
                {"name": "timestamp", "type": "uint256"}
            ],
            "name": "",
            "type": "tuple[]"
        }],
        "stateMutability": "view",
        "type": "function"
    }
]

print("=" * 80)
print("🔍 ONCHAIN INTERACTION CHECK - BASE MAINNET")
print("=" * 80)
print(f"\n📍 Registry Contract: {REGISTRY_ADDRESS}")
print(f"🌐 RPC: {RPC_URL}")

contract = w3.eth.contract(
    address=Web3.to_checksum_address(REGISTRY_ADDRESS),
    abi=REGISTRY_ABI
)

try:
    total = contract.functions.getTotalInteractions().call()
    print(f"\n📊 Total Interactions on-chain: {total}")
    
    if total == 0:
        print("\n⚠️  NO INTERACTIONS FOUND ON-CHAIN!")
        print("   This means recordInteraction() was never called successfully")
    else:
        print(f"\n📋 Last 10 Interactions:")
        print("=" * 80)
        
        start = max(0, total - 10)
        for i in range(start, total):
            try:
                interaction = contract.functions.getInteraction(i).call()
                follower, creator, link_id, action_type, weight_f, weight_c, timestamp = interaction
                
                action_types = ["FOLLOW", "LIKE", "COMMENT", "SHARE", "REFERRAL"]
                action = action_types[action_type] if action_type < len(action_types) else f"UNKNOWN({action_type})"
                
                from datetime import datetime
                time_str = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
                
                print(f"\n{i+1}. {action} | {time_str}")
                print(f"   Follower: {follower[:10]}... → Creator: {creator[:10]}...")
                print(f"   Weights: Follower={weight_f}, Creator={weight_c}")
                
            except Exception as e:
                print(f"\n{i+1}. Error reading interaction: {e}")
    
    # Check specific test wallets
    test_wallets = [
        "0x5cfffa13fb26f38b56522ac14ef39c63eb27f42b",
        "0x41807aa96b12a677cc7919c0068ea8d51763fa72"
    ]
    
    print("\n" + "=" * 80)
    print("🔍 CHECKING TEST WALLETS")
    print("=" * 80)
    
    for wallet in test_wallets:
        try:
            interactions = contract.functions.getUserInteractions(wallet).call()
            print(f"\n👤 {wallet[:10]}... has {len(interactions)} interactions")
            
            for idx, interaction in enumerate(interactions[:5], 1):
                follower, creator, link_id, action_type, weight_f, weight_c, timestamp = interaction
                action_types = ["FOLLOW", "LIKE", "COMMENT", "SHARE", "REFERRAL"]
                action = action_types[action_type]
                print(f"   {idx}. {action} | Follower: {follower[:10]}... | Creator: {creator[:10]}...")
                
        except Exception as e:
            print(f"\n👤 {wallet[:10]}... - Error: {e}")
    
except Exception as e:
    print(f"\n❌ ERROR: {e}")
    print("\nPossible causes:")
    print("  1. Contract not deployed at this address")
    print("  2. RPC connection issue")
    print("  3. Contract ABI mismatch")

print("\n" + "=" * 80)
