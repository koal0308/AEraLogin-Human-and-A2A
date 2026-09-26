"""
🔄 Gate Migration Tool
======================

Migriert bestehende owner_telegram_groups Einträge 
zur neuen owner_gate_configs Tabelle.

Diese Migration:
- Kopiert statische Links als Fallback
- Setzt security_level auf "low" (nur statischer Link)
- Behält die alte Tabelle für Backward Compatibility

Usage:
    python migrate_gates.py

Author: VEra-Resonance
Created: 2026-01-03
"""

import sqlite3
import os
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

# Database path
DB_PATH = os.path.join(os.path.dirname(__file__), "aera.db")


def get_db_connection():
    """SQLite Connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def migrate_telegram_groups():
    """
    Migriert alle Einträge aus owner_telegram_groups 
    nach owner_gate_configs (als static fallback)
    """
    print("🔄 Starting Gate Migration...")
    print(f"   Database: {DB_PATH}")
    print()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if old table exists
    cursor.execute("""
        SELECT name FROM sqlite_master 
        WHERE type='table' AND name='owner_telegram_groups'
    """)
    if not cursor.fetchone():
        print("❌ Table 'owner_telegram_groups' not found - nothing to migrate")
        return
    
    # Get all existing entries
    cursor.execute("""
        SELECT owner_wallet, telegram_invite_link, group_name, created_at, is_active
        FROM owner_telegram_groups
        WHERE is_active = 1
    """)
    
    old_entries = cursor.fetchall()
    print(f"📋 Found {len(old_entries)} entries to migrate")
    print()
    
    migrated = 0
    skipped = 0
    
    for entry in old_entries:
        owner = entry['owner_wallet']
        link = entry['telegram_invite_link']
        name = entry['group_name']
        created = entry['created_at']
        
        # Check if already migrated
        cursor.execute("""
            SELECT id FROM owner_gate_configs 
            WHERE owner_wallet = ? AND platform = 'telegram'
        """, (owner,))
        
        if cursor.fetchone():
            print(f"   ⏭️ Skipping {owner[:10]}... (already exists)")
            skipped += 1
            continue
        
        # Insert into new table
        now = datetime.now(timezone.utc).isoformat()
        
        cursor.execute("""
            INSERT INTO owner_gate_configs 
            (owner_wallet, platform, static_invite_link, group_name, 
             created_at, updated_at, is_active, bot_verified, health_status)
            VALUES (?, 'telegram', ?, ?, ?, ?, 1, 0, 'migrated')
        """, (owner, link, name, created or now, now))
        
        print(f"   ✅ Migrated {owner[:10]}... → {name or 'Unnamed'}")
        migrated += 1
    
    conn.commit()
    conn.close()
    
    print()
    print("=" * 50)
    print(f"✅ Migration complete!")
    print(f"   Migrated: {migrated}")
    print(f"   Skipped:  {skipped}")
    print(f"   Total:    {len(old_entries)}")
    print()
    print("💡 Note: Migrated gates use STATIC links (low security).")
    print("   Owners can upgrade to ADVANCED mode by configuring")
    print("   their own bot in the User Dashboard.")


def show_gate_status():
    """Shows current status of all gates"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    print("\n📊 Current Gate Status:")
    print("=" * 60)
    
    cursor.execute("""
        SELECT owner_wallet, platform, bot_verified, 
               CASE WHEN bot_token_encrypted IS NOT NULL THEN 'YES' ELSE 'NO' END as has_bot,
               health_status, group_name
        FROM owner_gate_configs
        WHERE is_active = 1
        ORDER BY bot_verified DESC, platform
    """)
    
    gates = cursor.fetchall()
    
    if not gates:
        print("   No gates configured yet.")
    else:
        print(f"{'Owner':<15} {'Platform':<10} {'Has Bot':<8} {'Verified':<9} {'Status':<12} {'Group'}")
        print("-" * 80)
        for g in gates:
            owner = g['owner_wallet'][:12] + "..."
            verified = "✓" if g['bot_verified'] else "✗"
            status = (g['health_status'] or 'unknown')[:10]
            group = (g['group_name'] or '-')[:20]
            print(f"{owner:<15} {g['platform']:<10} {g['has_bot']:<8} {verified:<9} {status:<12} {group}")
    
    conn.close()


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--status":
        show_gate_status()
    else:
        migrate_telegram_groups()
        show_gate_status()
