"""
VEra-Resonance — NFT Mint Confirmation Checker
© 2025 Karlheinz Beismann — VEra-Resonance Project
Licensed under the Apache License, Version 2.0

Background service to check pending NFT mints and confirm them
"""

import asyncio
import sqlite3
from typing import List, Dict, Any
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Load environment variables BEFORE importing web3_service
load_dotenv()

from logger import setup_logger
from web3_service import web3_service

logger = setup_logger(__name__)

# Global state
_confirmation_checker_task = None
_is_running = False

# Configuration
CHECK_INTERVAL_SECONDS = 30  # Check every 30 seconds
MAX_PENDING_AGE_HOURS = 24  # Consider pending mints older than 24h as failed


def get_db_connection():
    """Get database connection"""
    import os
    DB_PATH = os.path.join(os.path.dirname(__file__), "aera.db")
    return sqlite3.connect(DB_PATH)


async def check_pending_nft_mints():
    """
    Check all pending NFT mints and update their status
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get all users with pending mints
        cursor.execute("""
            SELECT address, identity_status, identity_nft_token_id, created_at
            FROM users
            WHERE identity_status IN ('pending', 'minting')
            ORDER BY created_at ASC
        """)
        
        pending_mints = cursor.fetchall()
        
        if not pending_mints:
            logger.debug("✓ No pending NFT mints to check")
            conn.close()
            return
        
        logger.info(f"🔍 Checking {len(pending_mints)} pending NFT mints...")
        
        for address, status, token_id, created_at in pending_mints:
            try:
                # Check if user has NFT
                has_nft = await web3_service.has_identity_nft(address)
                
                if has_nft:
                    # Get token ID from blockchain
                    blockchain_token_id = await web3_service.get_identity_token_id(address)
                    
                    # Update database to 'active' status
                    cursor.execute("""
                        UPDATE users
                        SET identity_status = 'active',
                            identity_nft_token_id = ?,
                            identity_minted_at = CURRENT_TIMESTAMP
                        WHERE address = ?
                    """, (blockchain_token_id, address.lower()))
                    
                    conn.commit()
                    logger.info(f"✅ NFT confirmed: {address} → Token #{blockchain_token_id} (Status: active)")
                else:
                    # Check if mint is too old
                    try:
                        created_time = datetime.fromisoformat(created_at)
                        # Make datetime.now() timezone-aware to match created_time
                        from datetime import timezone
                        now = datetime.now(timezone.utc)
                        # Remove timezone info from both for comparison
                        if created_time.tzinfo is not None:
                            created_time = created_time.replace(tzinfo=None)
                        if now.tzinfo is not None:
                            now = now.replace(tzinfo=None)
                        age_hours = (now - created_time).total_seconds() / 3600
                    except Exception as e:
                        logger.warning(f"⚠️ Could not calculate age for {address}: {e}")
                        age_hours = 0  # Assume recent if we can't calculate
                    
                    if age_hours > MAX_PENDING_AGE_HOURS:
                        # Mark as failed after 24h
                        cursor.execute("""
                            UPDATE users
                            SET identity_status = 'failed'
                            WHERE address = ?
                        """, (address.lower(),))
                        conn.commit()
                        logger.warning(f"⚠️ NFT mint marked as failed (24h timeout): {address}")
                    else:
                        logger.info(f"⏳ NFT still pending: {address[:10]}... (age: {age_hours:.1f}h)")
                
            except Exception as e:
                logger.error(f"❌ Error checking NFT for {address}: {e}")
        
        conn.close()
        
    except Exception as e:
        logger.error(f"❌ Error in check_pending_nft_mints: {e}")


async def nft_confirmation_checker_loop():
    """
    Background loop to check pending NFT mints
    """
    global _is_running
    _is_running = True
    
    logger.info("🎨 NFT confirmation checker started")
    
    while _is_running:
        try:
            await check_pending_nft_mints()
            await asyncio.sleep(CHECK_INTERVAL_SECONDS)
        except Exception as e:
            logger.error(f"❌ Error in NFT confirmation checker loop: {e}")
            await asyncio.sleep(CHECK_INTERVAL_SECONDS)
    
    logger.info("🛑 NFT confirmation checker stopped")


async def start_nft_confirmation_checker():
    """
    Start the background NFT confirmation checker
    """
    global _confirmation_checker_task, _is_running
    
    if _confirmation_checker_task is not None and not _confirmation_checker_task.done():
        logger.warning("⚠️ NFT confirmation checker already running")
        return
    
    _is_running = True
    _confirmation_checker_task = asyncio.create_task(nft_confirmation_checker_loop())
    logger.info("✅ NFT confirmation checker started")


async def stop_nft_confirmation_checker():
    """
    Stop the background NFT confirmation checker
    """
    global _confirmation_checker_task, _is_running
    
    _is_running = False
    
    if _confirmation_checker_task:
        _confirmation_checker_task.cancel()
        try:
            await _confirmation_checker_task
        except asyncio.CancelledError:
            pass
        
        logger.info("✅ NFT confirmation checker stopped")
