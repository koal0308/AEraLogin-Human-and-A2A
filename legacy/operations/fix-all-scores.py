#!/usr/bin/env python3
"""
Batch-Korrektur aller falschen Blockchain-Scores

Findet alle User mit Blockchain-Score > 0 und korrigiert sie auf
den korrekten berechneten Wert (Own Score + Avg Follower Score).

VERWENDUNG:
    python fix-all-scores.py                    # Trockenlauf (zeigt Änderungen)
    python fix-all-scores.py --execute          # Führt Blockchain-Sync aus
    python fix-all-scores.py --limit 5          # Nur erste 5 User
"""

import asyncio
import sqlite3
from resonance_calculator import calculate_resonance_score
from web3_service import Web3Service
import logging
import sys

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def fix_all_scores(dry_run=True, limit=None):
    """Korrigiere alle User mit falschen Blockchain-Scores"""
    
    print("=" * 70)
    print("🔧 BATCH-KORREKTUR - HYBRID-SYSTEM MIGRATION")
    print("=" * 70)
    print()
    
    if dry_run:
        print("⚠️  TROCKENLAUF - Keine Blockchain-Transaktionen")
        print("   Verwende --execute um tatsächlich zu syncen")
    else:
        print("✅ EXECUTE-MODE - Blockchain wird aktualisiert!")
    
    print()
    
    # Connect to database
    conn = sqlite3.connect('aera.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Get all users with blockchain scores
    cursor.execute("""
        SELECT address, score, blockchain_score, display_name
        FROM users 
        WHERE blockchain_score IS NOT NULL AND blockchain_score > 0
        ORDER BY blockchain_score DESC
    """)
    
    users = cursor.fetchall()
    
    if limit:
        users = users[:limit]
        print(f"📊 Limitiert auf erste {limit} User")
        print()
    
    print(f"📊 Gefunden: {len(users)} User mit Blockchain-Scores")
    print()
    
    # Web3 Service für Blockchain-Sync
    w3 = Web3Service() if not dry_run else None
    
    corrections_needed = []
    already_correct = []
    
    for user in users:
        address = user['address']
        blockchain_score = user['blockchain_score']
        
        # Calculate correct resonance
        own, avg_follower, count, total_resonance = calculate_resonance_score(address, conn)
        
        difference = blockchain_score - total_resonance
        
        if abs(difference) > 1:  # Allow 1 point tolerance for rounding
            corrections_needed.append({
                'address': address,
                'display_name': user['display_name'],
                'blockchain': blockchain_score,
                'calculated': total_resonance,
                'difference': difference,
                'own': own,
                'avg_follower': avg_follower,
                'follower_count': count
            })
        else:
            already_correct.append(address)
    
    print(f"✅ Korrekt: {len(already_correct)} User")
    print(f"❌ Korrektur nötig: {len(corrections_needed)} User")
    print()
    
    if not corrections_needed:
        print("🎉 Alle Scores sind korrekt! Nichts zu tun.")
        conn.close()
        return
    
    print("=" * 70)
    print("KORREKTUREN:")
    print("=" * 70)
    print()
    
    for i, correction in enumerate(corrections_needed, 1):
        print(f"{i}. {correction['address'][:10]}... ({correction['display_name'] or 'unnamed'})")
        print(f"   Blockchain: {correction['blockchain']} ❌")
        print(f"   Berechnet:  {correction['calculated']} ✅ (Own: {correction['own']} + Followers: {correction['avg_follower']}, Count: {correction['follower_count']})")
        print(f"   Differenz:  {correction['difference']:+d} ({'Burn' if correction['difference'] > 0 else 'Mint'} {abs(correction['difference'])} Token)")
        print()
    
    if dry_run:
        print("=" * 70)
        print("⚠️  TROCKENLAUF BEENDET")
        print("   Führe aus mit: python fix-all-scores.py --execute")
        print("=" * 70)
        conn.close()
        return
    
    # Execute corrections
    print("=" * 70)
    print("🚀 STARTE BLOCKCHAIN-SYNC...")
    print("=" * 70)
    print()
    
    success_count = 0
    error_count = 0
    
    for i, correction in enumerate(corrections_needed, 1):
        address = correction['address']
        target_score = correction['calculated']
        
        print(f"[{i}/{len(corrections_needed)}] Syncing {address[:10]}... → {target_score}")
        
        try:
            success, result = await w3.update_blockchain_score(address, target_score)
            
            if success:
                tx_hash = result.get('tx_hash', 'unknown')
                print(f"   ✅ Success! TX: {tx_hash[:16]}...")
                success_count += 1
                
                # Update database
                cursor.execute(
                    "UPDATE users SET blockchain_score = ? WHERE address = ?",
                    (target_score, address)
                )
                conn.commit()
            else:
                error_msg = result.get('error', 'unknown')
                print(f"   ❌ Error: {error_msg}")
                error_count += 1
                
        except Exception as e:
            print(f"   ❌ Exception: {str(e)}")
            error_count += 1
        
        # Small delay between transactions
        if i < len(corrections_needed):
            await asyncio.sleep(2)
    
    print()
    print("=" * 70)
    print("📊 ERGEBNIS:")
    print("=" * 70)
    print(f"✅ Erfolg: {success_count}/{len(corrections_needed)}")
    print(f"❌ Fehler:  {error_count}/{len(corrections_needed)}")
    print()
    
    conn.close()

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Batch-Korrektur aller falschen Blockchain-Scores")
    parser.add_argument('--execute', action='store_true', help='Führe Blockchain-Sync aus (sonst Trockenlauf)')
    parser.add_argument('--limit', type=int, help='Limitiere auf N User')
    
    args = parser.parse_args()
    
    asyncio.run(fix_all_scores(dry_run=not args.execute, limit=args.limit))
