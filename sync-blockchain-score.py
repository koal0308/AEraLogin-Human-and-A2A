#!/usr/bin/env python3
"""
Sync blockchain score with database score
Reduces blockchain score from 112 to 56 to match DB
"""
import asyncio
import os
import sys
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import after loading .env
from web3_service import Web3Service

async def sync_score():
    user_address = "0x9de3772a1b2e958561d8371ee34364dcd90967ba"
    target_score = 56
    
    print(f"\n🔧 Syncing Blockchain Score with Database")
    print(f"═══════════════════════════════════════════")
    print(f"📍 Address: {user_address}")
    print(f"🎯 Target Score: {target_score}")
    print(f"═══════════════════════════════════════════\n")
    
    # Create Web3Service instance
    web3_service = Web3Service()
    
    # Check if initialized properly
    if not web3_service.account:
        print("❌ Web3Service not initialized - missing PRIVATE_KEY")
        return
    
    print(f"✅ Backend Wallet: {web3_service.account.address}\n")
    
    # Get current blockchain score
    try:
        current_score = await web3_service.get_blockchain_score(user_address)
        print(f"📊 Current Blockchain Score: {current_score}")
        print(f"📊 Target DB Score: {target_score}\n")
        
        if current_score == target_score:
            print(f"✅ Already synced! Nothing to do.\n")
            return
        
        # Update score
        print(f"⏳ Sending transaction to update score from {current_score} → {target_score}...\n")
        success, result = await web3_service.update_blockchain_score(user_address, target_score)
        
        if success:
            tx_hash = result.get('tx_hash')
            print(f"✅ Transaction sent!")
            print(f"📝 TX Hash: {tx_hash}")
            print(f"🔗 BaseScan: {result.get('basescan_url')}")
            print(f"\n⏳ Waiting for confirmation (may take 30-60 seconds)...\n")
            
            # Wait for receipt
            receipt = web3_service.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
            
            if receipt['status'] == 1:
                print(f"✅ Transaction CONFIRMED!")
                print(f"📦 Block: {receipt['blockNumber']}")
                print(f"⛽ Gas: {receipt['gasUsed']:,}")
                
                # Verify new score
                await asyncio.sleep(2)  # Wait for blockchain to update
                new_score = await web3_service.get_blockchain_score(user_address)
                print(f"\n📊 Verified Blockchain Score: {new_score}")
                
                if new_score == target_score:
                    print(f"✅ SUCCESS! Blockchain and DB are now synced!")
                    print(f"\n💡 Refresh your dashboard to see 'Synced' status!\n")
                else:
                    print(f"⚠️ Warning: Score is {new_score}, expected {target_score}\n")
            else:
                print(f"❌ Transaction FAILED!")
                print(f"Receipt: {receipt}\n")
        else:
            print(f"❌ Failed: {result.get('error')}\n")
            
    except Exception as e:
        print(f"❌ Error: {e}\n")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(sync_score())
