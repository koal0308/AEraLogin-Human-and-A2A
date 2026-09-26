#!/usr/bin/env python3
"""
Skript zum Nachtragen der fehlenden Blockchain-Interaktionen vom 29.12.2025

4 fehlende Interaktionen für Wallet 0x9de3772a1b2e958561d8371ee34364dcd90967ba:
1. 0x7e07a79f8e4dc2f049604359e73eeceb3834b203 folgt dir (13:04:03)
2. 0x23394ff42e3cd3d91db6a96e39551ce62483e50d folgt dir (12:59:12)
3. Du folgst 0x7e07a79f8e4dc2f049604359e73eeceb3834b203 (13:07:39)
4. Du folgst 0x23394ff42e3cd3d91db6a96e39551ce62483e50d (13:01:13)
"""

import asyncio
import sys
import os

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Load environment variables BEFORE importing web3_service!
from dotenv import load_dotenv
load_dotenv()

from web3_service import Web3Service

# Wallet des Users
USER_WALLET = "0x9de3772a1b2e958561d8371ee34364dcd90967ba"

# Neue Wallets vom 29.12.2025
WALLET_1 = "0x7e07a79f8e4dc2f049604359e73eeceb3834b203"
WALLET_2 = "0x23394ff42e3cd3d91db6a96e39551ce62483e50d"

# PUBLIC_URL für Dashboard-Links
PUBLIC_URL = os.getenv("PUBLIC_URL", "https://aeralogin.de")

async def main():
    print("=" * 60)
    print("🔧 Fehlende Blockchain-Interaktionen nachtragen")
    print("=" * 60)
    
    # Web3 Service initialisieren
    web3_service = Web3Service()
    
    # Prüfe ob Service bereit ist
    if not web3_service.resonance_registry:
        print("❌ Fehler: Resonance Registry Contract nicht initialisiert!")
        print("   Bitte stelle sicher, dass .env korrekt konfiguriert ist")
        return
    
    print(f"✅ Web3 Service bereit")
    print(f"   Registry: {web3_service.resonance_registry.address}")
    print()
    
    # 4 fehlende Interaktionen
    interactions = [
        {
            "description": f"{WALLET_1[:10]}... folgt {USER_WALLET[:10]}...",
            "initiator": WALLET_1,
            "responder": USER_WALLET,
            "metadata": f"{PUBLIC_URL}/dashboard?owner={USER_WALLET}",
            "timestamp": "29.12.2025 13:04:03"
        },
        {
            "description": f"{WALLET_2[:10]}... folgt {USER_WALLET[:10]}...",
            "initiator": WALLET_2,
            "responder": USER_WALLET,
            "metadata": f"{PUBLIC_URL}/dashboard?owner={USER_WALLET}",
            "timestamp": "29.12.2025 12:59:12"
        },
        {
            "description": f"{USER_WALLET[:10]}... folgt {WALLET_1[:10]}...",
            "initiator": USER_WALLET,
            "responder": WALLET_1,
            "metadata": f"{PUBLIC_URL}/dashboard?owner={WALLET_1}",
            "timestamp": "29.12.2025 13:07:39"
        },
        {
            "description": f"{USER_WALLET[:10]}... folgt {WALLET_2[:10]}...",
            "initiator": USER_WALLET,
            "responder": WALLET_2,
            "metadata": f"{PUBLIC_URL}/dashboard?owner={WALLET_2}",
            "timestamp": "29.12.2025 13:01:13"
        }
    ]
    
    print(f"📝 {len(interactions)} Interaktionen werden nachgetragen:")
    print("-" * 60)
    
    successful = 0
    failed = 0
    
    for i, interaction in enumerate(interactions, 1):
        print(f"\n[{i}/{len(interactions)}] {interaction['description']}")
        print(f"    Ursprüngliches Datum: {interaction['timestamp']}")
        print(f"    Initiator: {interaction['initiator']}")
        print(f"    Responder: {interaction['responder']}")
        
        try:
            success, result = await web3_service.record_interaction(
                initiator=interaction['initiator'],
                responder=interaction['responder'],
                interaction_type=0,  # 0 = FOLLOW
                metadata=interaction['metadata']
            )
            
            if success and result.get('status') == 'success':
                print(f"    ✅ ERFOLG!")
                print(f"    TX: {result.get('tx_hash', 'N/A')}")
                print(f"    Block: {result.get('block_number', 'N/A')}")
                print(f"    Gas: {result.get('gas_used', 'N/A')}")
                successful += 1
            else:
                print(f"    ❌ FEHLGESCHLAGEN: {result}")
                failed += 1
                
            # Kurze Pause zwischen Transaktionen um Nonce-Konflikte zu vermeiden
            if i < len(interactions):
                print("    ⏳ Warte 3 Sekunden vor nächster Transaktion...")
                await asyncio.sleep(3)
                
        except Exception as e:
            print(f"    ❌ FEHLER: {str(e)}")
            failed += 1
    
    print("\n" + "=" * 60)
    print(f"📊 ZUSAMMENFASSUNG")
    print(f"   Erfolgreich: {successful}")
    print(f"   Fehlgeschlagen: {failed}")
    print("=" * 60)
    
    if successful > 0:
        print(f"\n💡 INFO: Der User {USER_WALLET[:10]}... sollte jetzt")
        print(f"   {18 + successful} Blockchain-Interaktionen haben (vorher: 18)")
        print(f"\n   Nächste Schritte:")
        print(f"   1. User soll sich neu im Dashboard einloggen")
        print(f"   2. Score sollte automatisch aktualisiert werden")
        print(f"   3. Blockchain Interaction History sollte aktuell sein")


if __name__ == "__main__":
    asyncio.run(main())
