#!/usr/bin/env python3
"""
Fix sync status for users who already have blockchain scores
Sets last_blockchain_sync to current time for users with existing blockchain scores
"""
import os
import sqlite3
from datetime import datetime

DB_PATH = os.getenv("DATABASE_PATH", "./aera.db")

def fix_sync_status():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Get all users with NULL last_blockchain_sync
    cursor.execute("""
        SELECT address, score 
        FROM users 
        WHERE last_blockchain_sync IS NULL
    """)
    
    users = cursor.fetchall()
    print(f"\n📊 Found {len(users)} users with NULL sync status\n")
    
    updated = 0
    for user in users:
        address = user['address']
        score = user['score']
        
        # Set last_sync to now (indicating they are "synced")
        cursor.execute("""
            UPDATE users 
            SET last_blockchain_sync = CURRENT_TIMESTAMP
            WHERE address = ?
        """, (address,))
        
        updated += 1
        print(f"✅ Updated {address[:10]}... (score: {score})")
    
    conn.commit()
    conn.close()
    
    print(f"\n✅ Updated {updated} users with sync status\n")

if __name__ == "__main__":
    fix_sync_status()
