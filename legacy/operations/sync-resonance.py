#!/usr/bin/env python3
"""
Calculate and sync Resonance Score with Follower Bonus
Resonance = Own Score + Average Follower Score
"""
import asyncio
import os
import sqlite3
from dotenv import load_dotenv
from web3_service import Web3Service

load_dotenv()

DB_PATH = os.getenv("DATABASE_PATH", "./aera.db")

async def calculate_resonance_score(address: str) -> tuple[int, int, int, int]:
    """
    Calculate total resonance score for a creator
    
    Returns:
        (own_score, avg_follower_score, follower_count, total_resonance)
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Get own score
    cursor.execute("SELECT score FROM users WHERE address=?", (address.lower(),))
    user = cursor.fetchone()
    own_score = user['score'] if user else 0
    
    # Get follower stats
    cursor.execute("""
        SELECT COUNT(*) as count, AVG(follower_score) as avg_score, SUM(follower_score) as total
        FROM followers 
        WHERE owner_wallet=?
    """, (address.lower(),))
    
    stats = cursor.fetchone()
    conn.close()
    
    follower_count = stats['count'] or 0
    avg_follower_score = int(stats['avg_score'] or 0)
    
    # Resonance Formula: Own Score + Avg Follower Score
    total_resonance = own_score + avg_follower_score
    
    return own_score, avg_follower_score, follower_count, total_resonance


async def sync_resonance_to_blockchain(address: str):
    """Sync calculated resonance score to blockchain"""
    
    web3 = Web3Service()
    
    # Calculate resonance
    own, avg_follower, count, total = await calculate_resonance_score(address)
    
    print(f"\n🎯 Resonance Calculation for {address[:10]}...{address[-6:]}")
    print(f"=" * 70)
    print(f"📊 Own Score:           {own}")
    print(f"👥 Followers:           {count}")
    print(f"📈 Avg Follower Score:  {avg_follower}")
    print(f"✨ Total Resonance:     {total} (= {own} + {avg_follower})")
    print(f"=" * 70)
    
    # Get current blockchain score
    current_chain_score = await web3.get_blockchain_score(address)
    print(f"⛓️  Current Blockchain:  {current_chain_score}")
    
    if current_chain_score == total:
        print(f"✅ Already synced! Nothing to do.\n")
        return
    
    print(f"\n⏳ Syncing {current_chain_score} → {total} to blockchain...")
    
    # Update blockchain
    success, result = await web3.update_blockchain_score(address, total)
    
    if success:
        tx_hash = result.get('tx_hash')
        print(f"\n✅ Transaction sent!")
        print(f"📝 TX: {tx_hash}")
        print(f"🔗 {result.get('basescan_url')}")
        print(f"\n⏳ Waiting for confirmation...\n")
        
        # Wait for receipt
        receipt = web3.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
        
        if receipt['status'] == 1:
            print(f"✅ CONFIRMED!")
            print(f"📦 Block: {receipt['blockNumber']}")
            print(f"⛽ Gas: {receipt['gasUsed']:,}")
            
            # Verify
            await asyncio.sleep(2)
            new_score = await web3.get_blockchain_score(address)
            print(f"\n📊 Verified Blockchain Score: {new_score}")
            
            if new_score == total:
                print(f"✅ SUCCESS! Resonance synced!\n")
            else:
                print(f"⚠️ Mismatch: expected {total}, got {new_score}\n")
        else:
            print(f"❌ Transaction failed!\n")
    else:
        print(f"❌ Error: {result.get('error')}\n")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("\n❌ Usage: python sync-resonance.py <wallet_address>\n")
        print("Example: python sync-resonance.py 0x9de3772a1b2e958561d8371ee34364dcd90967ba\n")
        sys.exit(1)
    
    target_address = sys.argv[1].lower()
    asyncio.run(sync_resonance_to_blockchain(target_address))
