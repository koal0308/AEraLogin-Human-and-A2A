#!/usr/bin/env python3
"""
Sync blockchain score with database score using admin function
"""
import asyncio
import os
import sys
from web3_service import Web3Service

async def fix_score():
    # User address and target score
    user_address = "0x9de3772a1b2e958561d8371ee34364dcd90967ba"
    target_score = 56  # Match DB score
    
    print(f"\n🔧 Fixing Blockchain Score")
    print(f"═══════════════════════════════════════")
    print(f"📍 Address: {user_address}")
    print(f"🎯 Target Score: {target_score}")
    print(f"═══════════════════════════════════════\n")
    
    # Initialize Web3 service
    web3_service = Web3Service()
    await web3_service.initialize()
    
    # Get current blockchain score
    current_score = await web3_service.get_blockchain_score(user_address)
    print(f"📊 Current Blockchain Score: {current_score}")
    print(f"📊 Target Score: {target_score}\n")
    
    if current_score == target_score:
        print(f"✅ Already synced! Nothing to do.\n")
        return
    
    # Update score on blockchain
    print(f"⏳ Updating blockchain score to {target_score}...")
    success, result = await web3_service.update_blockchain_score(user_address, target_score)
    
    if success:
        tx_hash = result.get('tx_hash')
        print(f"\n✅ Transaction sent successfully!")
        print(f"📝 TX Hash: {tx_hash}")
        print(f"🔗 BaseScan: {result.get('basescan_url')}")
        print(f"\n⏳ Waiting for confirmation...")
        
        # Wait for transaction receipt
        receipt = web3_service.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
        
        if receipt['status'] == 1:
            print(f"✅ Transaction confirmed!")
            print(f"📦 Block: {receipt['blockNumber']}")
            print(f"⛽ Gas used: {receipt['gasUsed']:,}")
            
            # Verify new score
            new_score = await web3_service.get_blockchain_score(user_address)
            print(f"\n📊 New Blockchain Score: {new_score}")
            
            if new_score == target_score:
                print(f"✅ Score successfully synced!\n")
            else:
                print(f"⚠️ Score mismatch: expected {target_score}, got {new_score}\n")
        else:
            print(f"❌ Transaction failed!")
            print(f"📋 Receipt: {receipt}\n")
    else:
        print(f"❌ Failed to send transaction: {result.get('error')}\n")

if __name__ == "__main__":
    asyncio.run(fix_score())
