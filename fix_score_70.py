#!/usr/bin/env python3
"""
Korrigiert den Score für Wallet 0x9de3772a1b2e958561d8371ee34364dcd90967ba
von 68 auf 70

Erklärung:
- INITIAL_SCORE: 50
- blockchain_interaction_count (On-chain): 18 → wird 22 nach Interaktions-Fix
- pending_bonus (Follow-Bonus, lokal): 2 (für neue Follower vom 29.12)

Score sollte sein: 50 + 18 + 2 = 70
Nach Blockchain-Fix: 50 + 22 + 0 = 72 (Bonus wird dann on-chain gezählt)
"""

import sqlite3
import os
from datetime import datetime

# Wallet-Adresse
WALLET = "0x9de3772a1b2e958561d8371ee34364dcd90967ba"
NEW_SCORE = 70

# Datenbankpfad
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "aera.db")

def fix_score():
    print("=" * 60)
    print("🔧 Score Korrektur")
    print("=" * 60)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Aktuellen Score abrufen
    cursor.execute("SELECT score, pending_bonus, blockchain_score FROM users WHERE address = ?", (WALLET,))
    result = cursor.fetchone()
    
    if not result:
        print(f"❌ Wallet {WALLET} nicht gefunden!")
        conn.close()
        return
    
    current_score, pending_bonus, blockchain_score = result
    print(f"\n📊 Aktueller Status:")
    print(f"   Wallet: {WALLET}")
    print(f"   Score: {current_score}")
    print(f"   Pending Bonus: {pending_bonus}")
    print(f"   Blockchain Score: {blockchain_score}")
    
    if current_score == NEW_SCORE:
        print(f"\n✅ Score ist bereits {NEW_SCORE}, keine Änderung nötig")
        conn.close()
        return
    
    # Score korrigieren
    timestamp = datetime.now().isoformat()
    
    cursor.execute(
        "UPDATE users SET score = ? WHERE address = ?",
        (NEW_SCORE, WALLET)
    )
    
    # Event protokollieren
    cursor.execute(
        """INSERT INTO events 
           (address, event_type, score_before, score_after, timestamp, created_at, referrer)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (WALLET, "score_correction_fix_missing_interactions", current_score, NEW_SCORE, 
         int(datetime.now().timestamp()), timestamp, "manual_fix")
    )
    
    conn.commit()
    
    # Verifizieren
    cursor.execute("SELECT score FROM users WHERE address = ?", (WALLET,))
    new_result = cursor.fetchone()
    
    print(f"\n✅ Score korrigiert:")
    print(f"   Vorher: {current_score}")
    print(f"   Nachher: {new_result[0]}")
    print(f"   Differenz: +{NEW_SCORE - current_score}")
    
    conn.close()
    print("\n" + "=" * 60)


if __name__ == "__main__":
    fix_score()
