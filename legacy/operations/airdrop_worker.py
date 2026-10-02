#!/usr/bin/env python3
"""
AEra Follow-Reward Worker
Überwacht neue Follower und vergibt 0.05 AERA pro Follow-Anfrage
"""

import sqlite3
import time
import logging
import os
from datetime import datetime
from dotenv import load_dotenv
import sys

# Optional: Web3 für echte Transfers
try:
    from web3 import Web3
    WEB3_AVAILABLE = True
except ImportError:
    WEB3_AVAILABLE = False

# Load environment variables
load_dotenv()

# Logging Setup
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "info").upper(),
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration
DB_PATH = os.path.join(os.path.dirname(__file__), "aera.db")
ADMIN_WALLET = os.getenv("ADMIN_WALLET", "")
ADMIN_PRIVATE_KEY = os.getenv("ADMIN_PRIVATE_KEY", "")
BASE_RPC_URL = os.getenv("BASE_RPC_URL", "https://mainnet.base.org")
AERA_CONTRACT = "0x5032206396A6001eEaD2e0178C763350C794F69e"
FOLLOW_REWARD_AMOUNT = 0.05  # 0.05 AERA pro Follow
FOLLOW_REWARD_AMOUNT_WEI = int(FOLLOW_REWARD_AMOUNT * 10**18)

# ERC-20 Transfer ABI
ERC20_ABI = [
    {
        "constant": False,
        "inputs": [
            {"name": "_to", "type": "address"},
            {"name": "_value", "type": "uint256"}
        ],
        "name": "transfer",
        "outputs": [{"name": "", "type": "bool"}],
        "type": "function"
    }
]

def get_db_connection():
    """Stellt Datenbankverbindung her"""
    conn = sqlite3.connect(DB_PATH, timeout=10.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA cache_size=-64000")
    return conn

def connect_web3():
    """Verbinde zu BASE Mainnet"""
    if not WEB3_AVAILABLE:
        logger.warning("⚠️ web3 nicht verfügbar - Demo-Modus aktiv")
        return None
    
    try:
        w3 = Web3(Web3.HTTPProvider(BASE_RPC_URL))
        
        if not w3.is_connected():
            logger.error(f"❌ Kann nicht zu BASE Mainnet verbinden: {BASE_RPC_URL}")
            return None
        
        logger.info(f"✓ Verbunden zu BASE Mainnet (Block: {w3.eth.block_number})")
        return w3
    except Exception as e:
        logger.error(f"❌ Web3-Verbindungsfehler: {str(e)}")
        return None

def send_follow_reward(w3, follower_address: str, amount_wei: int) -> dict:
    """
    Sendet Follow-Reward (0.05 AERA) an Follower
    """
    if not w3:
        return {
            "success": False,
            "tx_hash": None,
            "error": "Web3 not available - Demo mode"
        }
    
    try:
        if not Web3.is_address(follower_address):
            return {"success": False, "tx_hash": None, "error": "Invalid follower address"}
        
        follower_address = Web3.to_checksum_address(follower_address)
        admin_wallet = Web3.to_checksum_address(ADMIN_WALLET)
        contract_address = Web3.to_checksum_address(AERA_CONTRACT)
        
        logger.info(f"💰 Versende Follow-Reward: {amount_wei / 10**18} AERA → {follower_address[:10]}...")
        
        # Verbinde zum Contract
        contract = w3.eth.contract(address=contract_address, abi=ERC20_ABI)
        
        # Hole Nonce
        nonce = w3.eth.get_transaction_count(admin_wallet)
        
        # Baue Transaction
        tx = contract.functions.transfer(
            follower_address,
            amount_wei
        ).build_transaction({
            'from': admin_wallet,
            'nonce': nonce,
            'gas': 100000,
            'gasPrice': w3.eth.gas_price,
            'chainId': 8453  # BASE Mainnet
        })
        
        # Signiere
        signed_tx = w3.eth.account.sign_transaction(tx, ADMIN_PRIVATE_KEY)
        
        # Versende
        try:
            raw_tx = signed_tx.raw_transaction
        except AttributeError:
            try:
                raw_tx = signed_tx.raw
            except AttributeError:
                raw_tx = bytes(signed_tx)
        
        tx_hash = w3.eth.send_raw_transaction(raw_tx)
        tx_hash_str = tx_hash.hex()
        
        logger.info(f"✓ Follow-Reward TX versendet: {tx_hash_str[:20]}...")
        
        return {
            "success": True,
            "tx_hash": tx_hash_str,
            "error": None
        }
        
    except Exception as e:
        logger.error(f"❌ Follow-Reward Fehler: {str(e)}")
        return {
            "success": False,
            "tx_hash": None,
            "error": str(e)
        }

def process_new_followers(w3):
    """
    Verarbeitet neue Follower und vergibt Rewards (0.05 AERA)
    
    Logik:
    1. Finde Followers wo follow_confirmed = 0 (noch nicht belohnt)
    2. Vergleiche verified_at Timestamp mit aktuellem Timestamp
    3. Wenn neue Follow-Anfrage: Versende 0.05 AERA
    4. Markiere als follow_confirmed = 1
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Finde neue, unbewährte Followers (follow_confirmed = 0)
        cursor.execute("""
            SELECT id, owner_wallet, follower_address, follower_score, source_platform, verified_at
            FROM followers
            WHERE follow_confirmed = 0 AND verified = 1
            ORDER BY verified_at ASC
            LIMIT 10
        """)
        
        new_followers = cursor.fetchall()
        
        if not new_followers:
            logger.debug("ℹ️ Keine neuen Follow-Anfragen gefunden")
            conn.close()
            return
        
        logger.info(f"🎯 Verarbeite {len(new_followers)} neue Follower...")
        
        for follower in new_followers:
            follower_id = follower['id']
            owner = follower['owner_wallet']
            follower_addr = follower['follower_address']
            platform = follower['source_platform']
            verified_at = follower['verified_at']
            
            logger.info(f"")
            logger.info(f"{'=' * 70}")
            logger.info(f"📋 NEW FOLLOWER #{follower_id}")
            logger.info(f"   Owner:      {owner[:10]}...{owner[-4:]}")
            logger.info(f"   Follower:   {follower_addr[:10]}...{follower_addr[-4:]}")
            logger.info(f"   Platform:   {platform}")
            logger.info(f"   Score:      {follower['follower_score']}/100")
            logger.info(f"   Registered: {verified_at}")
            
            # Versende Follow-Reward (0.05 AERA)
            if w3 and ADMIN_WALLET and ADMIN_PRIVATE_KEY:
                logger.info(f"💸 Versende 0.05 AERA Reward...")
                reward_result = send_follow_reward(w3, follower_addr, FOLLOW_REWARD_AMOUNT_WEI)
                
                if reward_result["success"]:
                    logger.info(f"✅ Reward erfolgreich versendet!")
                    logger.info(f"   TX: {reward_result['tx_hash'][:30]}...")
                    reward_status = "completed"
                    reward_tx = reward_result['tx_hash']
                else:
                    logger.warning(f"⚠️ Reward fehlgeschlagen: {reward_result['error']}")
                    reward_status = "failed"
                    reward_tx = reward_result['error']
            else:
                logger.info(f"ℹ️ Demo-Modus: Reward wird nicht versendet")
                reward_status = "demo_pending"
                reward_tx = "DEMO_MODE"
            
            # Markiere Follower als belohnt (follow_confirmed = 1)
            current_timestamp = datetime.utcnow().isoformat()
            
            cursor.execute("""
                UPDATE followers
                SET follow_confirmed = 1, confirmed_at = ?
                WHERE id = ?
            """, (current_timestamp, follower_id))
            
            conn.commit()
            
            logger.info(f"✓ Reward Status: {reward_status}")
            logger.info(f"   Timestamp: {current_timestamp}")
            logger.info(f"{'=' * 70}")
            
        conn.close()
        logger.info(f"✅ Follow-Reward Verarbeitung abgeschlossen")
        
    except Exception as e:
        logger.error(f"❌ Fehler bei Follow-Verarbeitung: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())

def main():
    """Hauptschleife des Follow-Reward Workers"""
    logger.info("=" * 80)
    logger.info("🚀 AEra Follow-Reward Worker - GESTARTET")
    logger.info("=" * 80)
    logger.info("📊 Überwacht neue Follower und vergibt 0.05 AERA Rewards")
    logger.info("")
    
    if not ADMIN_WALLET or not ADMIN_PRIVATE_KEY:
        logger.warning("⚠️ Admin-Credentials nicht konfiguriert")
        logger.warning("   → Läufe im DEMO-MODUS (Rewards werden NICHT versendet)")
        w3 = None
    else:
        logger.info(f"✓ Admin Wallet: {ADMIN_WALLET[:10]}...{ADMIN_WALLET[-4:]}")
        w3 = connect_web3() if WEB3_AVAILABLE else None
        if w3:
            logger.info(f"✓ Web3 verbunden zu BASE Mainnet")
        else:
            logger.warning("⚠️ Web3 nicht verfügbar - Rewards können nicht versendet werden")
    
    logger.info("=" * 80)
    logger.info("⏳ Überwache Follow-Anfragen (Drücke Ctrl+C zum Beenden)...")
    logger.info("=" * 80)
    logger.info("")
    
    try:
        while True:
            try:
                process_new_followers(w3)
                time.sleep(30)  # Überprüfe alle 30 Sekunden
            except KeyboardInterrupt:
                raise
            except Exception as e:
                logger.error(f"❌ Fehler in Hauptschleife: {str(e)}")
                import traceback
                logger.error(traceback.format_exc())
                time.sleep(10)
    
    except KeyboardInterrupt:
        logger.info("\n")
        logger.info("=" * 80)
        logger.info("⏹️ Worker beendet (SIGINT)")
        logger.info("=" * 80)
        sys.exit(0)

if __name__ == "__main__":
    main()
