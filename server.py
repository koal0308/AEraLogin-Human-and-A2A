"""
VEra-Resonance Backend - FastAPI Server
Creator: Karlheinz Beismann
Project: VEra-Resonance — Decentralized Proof-of-Human Architecture
License: Apache 2.0 (see LICENSE file)
© 2025 VEra-Resonance Project

Verifies wallet addresses and manages Resonance Scores
"""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from typing import Optional
import sqlite3
import time
import json
import os
import asyncio
import httpx
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
import hashlib
import hmac
import secrets

# Load environment variables FIRST!
load_dotenv()

# ===== IMPORT CUSTOM LOGGER =====
from logger import logger, api_logger, db_logger, wallet_logger, airdrop_logger, log_activity

# ===== IMPORT BLOCKCHAIN SERVICE (after load_dotenv!) =====
from web3_service import web3_service
from blockchain_sync import sync_score_after_update, force_sync_on_login

# ===== IMPORT TELEGRAM BOT SERVICE =====
from telegram_bot_service import telegram_bot, create_one_time_telegram_invite, check_bot_setup

# Try to import extended function for Group Bot integration
try:
    from telegram_bot_service import create_one_time_telegram_invite_with_capabilities
    GROUP_BOT_AVAILABLE = True
except ImportError:
    GROUP_BOT_AVAILABLE = False

# ===== IMPORT DISCORD BOT SERVICE =====
try:
    from discord_bot_service import discord_bot, create_one_time_discord_invite, check_discord_bot_setup
    DISCORD_BOT_AVAILABLE = True
    logger.info("✓ Discord Bot Service imported")
except ImportError:
    DISCORD_BOT_AVAILABLE = False
    discord_bot = None
    logger.warning("⚠️ Discord Bot Service not available")

# ===== IMPORT DYNAMIC GATE SERVICE =====
try:
    from gate_service import init_gate_service, get_gate_service, GateService
    GATE_SERVICE_AVAILABLE = True
    logger.info("✓ Dynamic Gate Service imported")
except ImportError:
    GATE_SERVICE_AVAILABLE = False
    logger.warning("⚠️ Dynamic Gate Service not available - using legacy mode")

# Config
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", 8840))
PUBLIC_URL = os.getenv("PUBLIC_URL", f"http://localhost:{PORT}")
NGROK_URL = os.getenv("NGROK_URL", "")  # NEW: Explicit ngrok URL
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*").split(",")

# NEW: Tailscale Support
TAILSCALE_ENABLED = os.getenv("TAILSCALE_ENABLED", "false").lower() == "true"
TAILSCALE_IP = os.getenv("TAILSCALE_IP", "")

# NEW: Deployment Mode (local, tailscale, ngrok)
DEPLOYMENT_MODE = os.getenv("DEPLOYMENT_MODE", "local")  # local, tailscale, ngrok

INITIAL_SCORE = int(os.getenv("INITIAL_SCORE", 50))
MAX_SCORE = int(os.getenv("MAX_SCORE", 100))
SCORE_INCREMENT = int(os.getenv("SCORE_INCREMENT", 1))

# ============================================================================
# ===== AUTHENTICATION SECRETS - fail-fast, no fallbacks =====
# ============================================================================
# Every authentication secret MUST be configured explicitly. There is
# deliberately NO default and NO derivation between secrets: a predictable
# fallback would allow anyone who knows the source code to forge wallet
# sessions or OAuth tokens. Missing/weak configuration aborts startup.
_FORBIDDEN_SECRET_VALUES = frozenset({
    "aera-secret-key-change-in-production",
    "change-me-in-production",
    "changeme",
    "secret",
})
_MIN_SECRET_LENGTH = 32


def _require_auth_secret(name: str) -> str:
    """Load a mandatory authentication secret or abort startup.

    Never logs or echoes the secret value - only the variable name.
    """
    value = os.getenv(name, "")
    if not value:
        raise RuntimeError(
            f"Missing required {name}. Configure a random secret "
            f"(e.g. python -c \"import secrets; print(secrets.token_urlsafe(48))\")."
        )
    if value in _FORBIDDEN_SECRET_VALUES:
        raise RuntimeError(
            f"Insecure {name}: a well-known placeholder value is configured."
        )
    if len(value) < _MIN_SECRET_LENGTH:
        raise RuntimeError(
            f"Insecure {name}: must be at least {_MIN_SECRET_LENGTH} characters."
        )
    return value


TOKEN_SECRET = _require_auth_secret("TOKEN_SECRET")

# ============================================================================
# ===== TIERED SCORE SYSTEM - Gestaffeltes Punktesystem =====
# ============================================================================
# Score wächst mit abnehmender Rate je höher er ist:
# 50-60: +1.0 pro Interaktion (10 Interaktionen für 10 Punkte)
# 60-70: +0.5 pro Interaktion (20 Interaktionen für 10 Punkte)
# 70-80: +0.2 pro Interaktion (50 Interaktionen für 10 Punkte)
# 80-90: +0.1 pro Interaktion (100 Interaktionen für 10 Punkte)
# 90-100: +0.01 pro Interaktion (1000 Interaktionen für 10 Punkte)
# Total: ~1180 Interaktionen von 50 auf 100 (statt nur 50)

TIERED_SCORE_RATES = {
    50: 1.0,    # Score 50-59.99: +1.0 pro Interaktion
    60: 0.5,    # Score 60-69.99: +0.5 pro Interaktion
    70: 0.2,    # Score 70-79.99: +0.2 pro Interaktion
    80: 0.1,    # Score 80-89.99: +0.1 pro Interaktion
    90: 0.01,   # Score 90-99.99: +0.01 pro Interaktion
}

def calculate_tiered_points(current_score: float, interactions: int = 1) -> float:
    """
    Berechnet die Punkte basierend auf dem aktuellen Score (gestaffelt).
    
    Args:
        current_score: Aktueller Score des Users
        interactions: Anzahl der Interaktionen (default 1)
    
    Returns:
        Die zu vergebenden Punkte (als float)
    
    Example:
        Score 55 → +1.0 pro Interaktion
        Score 65 → +0.5 pro Interaktion  
        Score 75 → +0.2 pro Interaktion
        Score 85 → +0.1 pro Interaktion
        Score 95 → +0.01 pro Interaktion
    """
    # Bestimme die Rate basierend auf dem aktuellen Score
    if current_score >= 90:
        rate = TIERED_SCORE_RATES[90]
    elif current_score >= 80:
        rate = TIERED_SCORE_RATES[80]
    elif current_score >= 70:
        rate = TIERED_SCORE_RATES[70]
    elif current_score >= 60:
        rate = TIERED_SCORE_RATES[60]
    else:
        rate = TIERED_SCORE_RATES[50]
    
    return rate * interactions

def calculate_new_score(current_score: float, interactions: int = 1) -> float:
    """
    Berechnet den neuen Score nach Interaktionen (mit Tier-Übergang).
    
    Berücksichtigt Score-Tier-Grenzen korrekt - wenn der Score
    während der Berechnung eine Grenze überschreitet, wird 
    die Rate entsprechend angepasst.
    
    Args:
        current_score: Aktueller Score
        interactions: Anzahl Interaktionen
    
    Returns:
        Neuer Score (maximal MAX_SCORE)
    """
    new_score = current_score
    
    for _ in range(interactions):
        points = calculate_tiered_points(new_score, 1)
        new_score = min(new_score + points, MAX_SCORE)
        
        # Stop wenn MAX_SCORE erreicht
        if new_score >= MAX_SCORE:
            break
    
    return round(new_score, 2)  # Auf 2 Dezimalstellen runden


# ============================================================================
# Helper Functions for NFT Tiers
# ============================================================================

def get_tier_name(score: float) -> str:
    """
    Get tier name based on Resonance Score (50-200)
    
    Score Composition:
    - Base Score: 50-100 (own activities/logins)
    - Owner Score: 0-100 (from followers' average scores)
    - Total Resonance Score: 50-200
    
    Tier Thresholds:
    - < 51: No Tier (not eligible)
    - 51-100: Common (base level with followers)
    - 101-130: Uncommon (growing influence)
    - 131-160: Rare (strong community)
    - 161-180: Epic (major influence)
    - 181-200: Legendary (maximum resonance)
    """
    if score < 51:
        return "No Tier"  # Below minimum threshold
    elif score >= 181:
        return "Legendary"  # 181-200
    elif score >= 161:
        return "Epic"       # 161-180
    elif score >= 131:
        return "Rare"       # 131-160
    elif score >= 101:
        return "Uncommon"   # 101-130
    else:
        return "Common"     # 51-100


def get_tier_colors(tier: str) -> dict:
    """Get tier-specific colors for NFT images"""
    tier_color_map = {
        "Legendary": {  # 181-200: Gold/Orange (Maximum Resonance)
            "bg1": "#1a0a2e",
            "bg2": "#2d1b4e",
            "accent1": "#ffd700",
            "accent2": "#ff8c00"
        },
        "Epic": {  # 161-180: Purple/Blue (Major Influence)
            "bg1": "#1a0a2e", 
            "bg2": "#2d1b4e",
            "accent1": "#a855f7",
            "accent2": "#6366f1"
        },
        "Rare": {  # 131-160: Blue/Cyan (Strong Community)
            "bg1": "#0a1a2e",
            "bg2": "#1b2d4e", 
            "accent1": "#3b82f6",
            "accent2": "#06b6d4"
        },
        "Uncommon": {  # 101-130: Green (Growing Influence)
            "bg1": "#0a2e1a",
            "bg2": "#1b4e2d",
            "accent1": "#22c55e",
            "accent2": "#10b981"
        },
        "Common": {  # 51-100: Gray/Blue (Base Level)
            "bg1": "#0f1729",
            "bg2": "#1a2332",
            "accent1": "#64748b",
            "accent2": "#475569"
        },
        "No Tier": {  # < 51: Dark (Below Threshold)
            "bg1": "#050814",
            "bg2": "#0c1628",
            "accent1": "#334155",
            "accent2": "#1e293b"
        }
    }
    return tier_color_map.get(tier, tier_color_map["Common"])


TOKEN_EXPIRY_MINUTES = int(os.getenv("TOKEN_EXPIRY_MINUTES", 2))  # 2 Minuten Standard

# Airdrop Configuration
ADMIN_WALLET = os.getenv("ADMIN_WALLET", "")
ADMIN_PRIVATE_KEY = os.getenv("ADMIN_PRIVATE_KEY", "")
AERA_CONTRACT = os.getenv("AERA_CONTRACT", "0x5032206396A6001eEaD2e0178C763350C794F69e")
AIRDROP_AMOUNT = 0.5  # AEra Tokens
BASE_RPC = os.getenv("BASE_RPC_URL", "https://mainnet.base.org")

app = FastAPI(
    title="VEra-Resonance API",
    description="Decentralized Proof-of-Human System",
    version="0.1"
)


# CORS-Middleware für Browser-Zugriff (mit Environment-Variablen konfigurierbar)
allowed_origins = [origin.strip() for origin in CORS_ORIGINS]
if "*" in allowed_origins:
    allowed_origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True
)

logger.info(f"✓ CORS Konfiguration: {allowed_origins}")

# CSP Middleware für Web3 Kompatibilität
class CSPMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        # CSP für Web3: unsafe-eval wird für Web3-Provider benötigt (MetaMask, Coinbase Wallet, Base Wallet, etc.)
        # UPDATED: Added frame-ancestors and relaxed frame-src for wallet browser compatibility
        # UPDATED: Added plausible.io for GDPR-compliant analytics
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://*.coinbase.com https://*.base.org https://plausible.io; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "img-src 'self' data: https: blob:; "
            "connect-src 'self' https: wss: http://localhost:* https://base.blockscout.com https://base-rpc.publicnode.com wss://base-rpc.publicnode.com https://mainnet.base.org https://api.base.org https://*.coinbase.com https://*.wallet.coinbase.com wss://*.coinbase.com https://plausible.io; "
            "font-src 'self' data: https://fonts.gstatic.com; "
            "frame-src 'self' https://*.coinbase.com https://*.wallet.coinbase.com; "
            "frame-ancestors 'self' https://*.coinbase.com https://*.wallet.coinbase.com app://*; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "worker-src 'self' blob:;"
        )
        return response

app.add_middleware(CSPMiddleware)
logger.info("✓ CSP Middleware aktiviert (Web3 kompatibel)")

# Registriere Static Files (CSS, JS, etc.)
static_dir = os.path.join(os.path.dirname(__file__))
try:
    app.mount("/static", StaticFiles(directory=static_dir), name="static")
    logger.info(f"✓ Static Files mounted: {static_dir}")
except Exception as e:
    logger.warning(f"⚠️ Static Files konnten nicht gemountet werden: {e}")

# SDK Verzeichnis für Third-Party Integration
sdk_dir = os.path.join(os.path.dirname(__file__), "sdk")
if os.path.exists(sdk_dir):
    try:
        app.mount("/sdk", StaticFiles(directory=sdk_dir), name="sdk")
        logger.info(f"✓ SDK Files mounted: {sdk_dir}")
    except Exception as e:
        logger.warning(f"⚠️ SDK Files konnten nicht gemountet werden: {e}")

# Examples Verzeichnis für Dokumentation
examples_dir = os.path.join(os.path.dirname(__file__), "examples")
if os.path.exists(examples_dir):
    try:
        app.mount("/examples", StaticFiles(directory=examples_dir), name="examples")
        logger.info(f"✓ Examples Files mounted: {examples_dir}")
    except Exception as e:
        logger.warning(f"⚠️ Examples Files konnten nicht gemountet werden: {e}")

# Docs Verzeichnis für SDK-Dokumentation
docs_dir = os.path.join(os.path.dirname(__file__), "docs")
if os.path.exists(docs_dir):
    try:
        app.mount("/docs", StaticFiles(directory=docs_dir), name="docs")
        logger.info(f"✓ Docs Files mounted: {docs_dir}")
    except Exception as e:
        logger.warning(f"⚠️ Docs Files konnten nicht gemountet werden: {e}")

# Favicon Route
@app.get("/favicon.png")
async def favicon():
    """Serve Favicon"""
    favicon_path = os.path.join(os.path.dirname(__file__), "favicon.png")
    return FileResponse(favicon_path, media_type="image/png")

# Templates für dynamische Landing Pages
templates = Jinja2Templates(directory=static_dir)

# Datenbank-Konfiguration
DATABASE_NAME = os.getenv("DATABASE_PATH", "./aera.db")
DB_PATH = os.path.join(os.path.dirname(__file__), DATABASE_NAME.replace("./", ""))

# Platform-Konfiguration für dynamisches Styling
# ✅ TIER 1: Perfekt für NFT-Gating (Empfohlen: Telegram, Discord, Signal)
# ⚠️ TIER 2: Funktioniert, aber limitiert (WhatsApp, VK)
# ❌ Entfernt: Instagram, TikTok, LinkedIn, Facebook, YouTube, WeChat, Twitch
PLATFORM_CONFIG = {
    # ===== FOLLOWER LINK PLATFORMS (Referrer Tracking) =====
    "twitter": {
        "name": "X / Twitter",
        "color": "#1DA1F2",
        "gradient": "linear-gradient(135deg, #1DA1F2 0%, #0D8BD9 100%)",
        "emoji": "𝕏",
        "badge": "FROM X/TWITTER",
        "supports_groups": False,
        "recommended": False
    },
    "reddit": {
        "name": "Reddit",
        "color": "#FF4500",
        "gradient": "linear-gradient(135deg, #FF4500 0%, #CC3700 100%)",
        "emoji": "🤖",
        "badge": "FROM REDDIT",
        "supports_groups": False,
        "recommended": False
    },
    "direct": {
        "name": "Direct",
        "color": "#667eea",
        "gradient": "linear-gradient(135deg, #667eea 0%, #764ba2 100%)",
        "emoji": "⚡",
        "badge": "DIRECT ACCESS",
        "supports_groups": False,
        "recommended": False
    },
    
    # ===== NFT-GATED GROUP PLATFORMS =====
    # ✅ TIER 1: EMPFOHLEN für NFT-Gating
    "telegram": {
        "name": "Telegram",
        "color": "#0088cc",
        "gradient": "linear-gradient(135deg, #0088cc 0%, #006699 100%)",
        "emoji": "✈️",
        "badge": "FROM TELEGRAM",
        "supports_groups": True,
        "recommended": True,
        "description": "Perfect for NFT-gated communities"
    },
    "discord": {
        "name": "Discord",
        "color": "#5865F2",
        "gradient": "linear-gradient(135deg, #5865F2 0%, #4752C4 100%)",
        "emoji": "💬",
        "badge": "FROM DISCORD",
        "supports_groups": True,
        "recommended": True,
        "description": "Ideal for Web3 communities"
    },
    "signal": {
        "name": "Signal",
        "color": "#3A76F0",
        "gradient": "linear-gradient(135deg, #3A76F0 0%, #2E5DB8 100%)",
        "emoji": "🔒",
        "badge": "FROM SIGNAL",
        "supports_groups": True,
        "recommended": True,
        "description": "Privacy-focused messaging"
    },
    
    # ✅ TIER 1.5: Gut geeignet
    "slack": {
        "name": "Slack",
        "color": "#4A154B",
        "gradient": "linear-gradient(135deg, #4A154B 0%, #36C5F0 100%)",
        "emoji": "💬",
        "badge": "FROM SLACK",
        "supports_groups": True,
        "recommended": False,
        "description": "Professional communities"
    },
    "farcaster": {
        "name": "Farcaster",
        "color": "#8465CB",
        "gradient": "linear-gradient(135deg, #8465CB 0%, #6347A5 100%)",
        "emoji": "🎭",
        "badge": "FROM FARCASTER",
        "supports_groups": True,
        "recommended": False,
        "description": "Decentralized social (Web3-native)"
    },
    
    # ⚠️ TIER 2: Mit Einschränkungen
    "whatsapp": {
        "name": "WhatsApp",
        "color": "#25D366",
        "gradient": "linear-gradient(135deg, #25D366 0%, #128C7E 100%)",
        "emoji": "💚",
        "badge": "FROM WHATSAPP",
        "supports_groups": True,
        "recommended": False,
        "warning": "⚠️ Limited to 1024 members maximum",
        "description": "Max 1024 members"
    },
    "vk": {
        "name": "VK",
        "color": "#0077FF",
        "gradient": "linear-gradient(135deg, #0077FF 0%, #005CB8 100%)",
        "emoji": "🐻",
        "badge": "FROM VK",
        "supports_groups": True,
        "recommended": False,
        "description": "Popular social platform"
    },
    
    # Fallback
    "other": {
        "name": "Other Platform",
        "color": "#667eea",
        "gradient": "linear-gradient(135deg, #667eea 0%, #764ba2 100%)",
        "emoji": "🌐",
        "badge": "FROM OTHER PLATFORM",
        "supports_groups": False,
        "recommended": False
    }
}

def get_db_connection():
    """Erstelle Datenbankverbindung mit WAL-Modus für Concurrency"""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA cache_size = -64000")  # 64MB Cache
    conn.execute("PRAGMA busy_timeout=10000")  # 10s Timeout
    db_logger.debug(f"DB Connection established: {DB_PATH}")
    return conn

def extract_referrer_source(referrer: str) -> str:
    """
    Extrahiert die Quelle aus dem Referrer (z.B. 'twitter', 'telegram', 'direct')
    """
    if not referrer:
        return "direct"
    
    referrer_lower = referrer.lower()
    
    # Social Media Platforms
    if "twitter.com" in referrer_lower or "x.com" in referrer_lower or "t.co" in referrer_lower:
        return "twitter"
    elif "telegram" in referrer_lower or "t.me" in referrer_lower:
        return "telegram"
    elif "facebook.com" in referrer_lower or "fb.com" in referrer_lower:
        return "facebook"
    elif "instagram.com" in referrer_lower:
        return "instagram"
    elif "reddit.com" in referrer_lower:
        return "reddit"
    elif "discord" in referrer_lower:
        return "discord"
    elif "youtube.com" in referrer_lower or "youtu.be" in referrer_lower:
        return "youtube"
    elif "linkedin.com" in referrer_lower:
        return "linkedin"
    elif "tiktok.com" in referrer_lower:
        return "tiktok"
    
    # Search Engines
    elif "google" in referrer_lower:
        return "google"
    elif "bing" in referrer_lower:
        return "bing"
    elif "duckduckgo" in referrer_lower:
        return "duckduckgo"
    
    # Crypto/Web3
    elif "etherscan" in referrer_lower:
        return "etherscan"
    elif "opensea" in referrer_lower:
        return "opensea"
    
    # Other
    elif "localhost" in referrer_lower or "127.0.0.1" in referrer_lower:
        return "localhost"
    elif "ngrok" in referrer_lower:
        return "ngrok-test"
    else:
        return "other"

def init_db():
    """Initialisiert Datenbank mit notwendigen Tabellen"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Users-Tabelle (erweitert mit owner_wallet für Follower-Tracking)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        address TEXT PRIMARY KEY,
        first_seen INTEGER,
        last_login INTEGER,
        score INTEGER DEFAULT 50,
        login_count INTEGER DEFAULT 0,
        created_at TEXT,
        first_referrer TEXT,
        last_referrer TEXT,
        owner_wallet TEXT,
        is_verified_follower INTEGER DEFAULT 0,
        display_name TEXT,
        avatar_emoji TEXT DEFAULT '👤'
    )
    """)
    
    # Events-Tabelle für Audit-Trail (DSGVO-konform: KEINE IP/User-Agent!)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        address TEXT,
        event_type TEXT,
        score_before INTEGER,
        score_after INTEGER,
        timestamp INTEGER,
        created_at TEXT,
        referrer TEXT,
        owner_wallet TEXT
    )
    """)
    
    # Airdrops-Tabelle für Tracking
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS airdrops (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        address TEXT UNIQUE,
        amount REAL,
        tx_hash TEXT,
        status TEXT,
        created_at TEXT
    )
    """)
    
    # Followers-Tabelle: Link Owner <-> Follower
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS followers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner_wallet TEXT NOT NULL,
        follower_address TEXT NOT NULL,
        follower_score INTEGER,
        follower_display_name TEXT,
        verified_at TEXT,
        source_platform TEXT,
        verified BOOLEAN DEFAULT 1,
        follow_confirmed BOOLEAN DEFAULT 0,
        confirmed_at TEXT,
        UNIQUE(owner_wallet, follower_address),
        FOREIGN KEY(owner_wallet) REFERENCES users(address),
        FOREIGN KEY(follower_address) REFERENCES users(address)
    )
    """)
    
    # Telegram-Invites-Tabelle: Track Telegram/Discord Gate Access (with owner tracking)
    # MULTI-GATE SUPPORT: UNIQUE constraint includes group_id to allow same user in different groups
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS telegram_invites (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        address TEXT NOT NULL,
        invited_at TEXT,
        granted BOOLEAN DEFAULT 1,
        owner_wallet TEXT,
        platform TEXT DEFAULT 'telegram',
        group_id TEXT,
        FOREIGN KEY(address) REFERENCES users(address),
        UNIQUE(address, owner_wallet, platform, group_id)
    )
    """)
    
    # Migration: Add platform column if not exists
    try:
        cursor.execute("ALTER TABLE telegram_invites ADD COLUMN platform TEXT DEFAULT 'telegram'")
    except:
        pass  # Column already exists
    
    # Migration: Add group_id column for multi-gate support
    try:
        cursor.execute("ALTER TABLE telegram_invites ADD COLUMN group_id TEXT")
    except:
        pass  # Column already exists
    
    # Migration: Add Profile NFT columns (OPTIONAL - Public Display Layer)
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN profile_nft_token_id INTEGER")
    except:
        pass  # Column already exists
    
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN profile_nft_visibility TEXT DEFAULT 'private'")
    except:
        pass  # Column already exists
    
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN profile_nft_minted_at TEXT")
    except:
        pass  # Column already exists
    
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN profile_nft_mint_tx_hash TEXT")
    except:
        pass  # Column already exists
    
    # Migration: Add avatar_emoji column for profile customization
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN avatar_emoji TEXT DEFAULT '👤'")
    except:
        pass  # Column already exists
    
    # Owner-Telegram-Groups-Tabelle: Owner-specific Telegram group links
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS owner_telegram_groups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner_wallet TEXT UNIQUE NOT NULL,
        telegram_invite_link TEXT NOT NULL,
        group_name TEXT,
        created_at TEXT,
        is_active BOOLEAN DEFAULT 1,
        FOREIGN KEY(owner_wallet) REFERENCES users(address)
    )
    """)
    
    # 🔐 Community Redirect Tokens: One-time, time-limited tokens for secure redirects
    # This prevents users from copying and sharing the actual invite link
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS community_redirect_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token TEXT UNIQUE NOT NULL,
        address TEXT NOT NULL,
        invite_link TEXT NOT NULL,
        platform TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        used BOOLEAN DEFAULT 0,
        used_at TEXT
    )
    """)
    
    # ===== OAUTH TABLES FOR THIRD-PARTY INTEGRATION =====
    
    # OAuth Clients: Registered third-party applications
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS oauth_clients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT UNIQUE NOT NULL,
        client_secret_hash TEXT NOT NULL,
        client_name TEXT NOT NULL,
        redirect_uris TEXT NOT NULL,
        allowed_origins TEXT,
        min_score INTEGER DEFAULT 0,
        require_nft BOOLEAN DEFAULT 1,
        created_at TEXT NOT NULL,
        is_active BOOLEAN DEFAULT 1,
        owner_address TEXT,
        website_url TEXT,
        description TEXT
    )
    """)
    
    # OAuth Authorization Codes: Short-lived codes for token exchange
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS oauth_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT UNIQUE NOT NULL,
        client_id TEXT NOT NULL,
        address TEXT NOT NULL,
        redirect_uri TEXT NOT NULL,
        state TEXT,
        nonce TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        used BOOLEAN DEFAULT 0,
        FOREIGN KEY(client_id) REFERENCES oauth_clients(client_id)
    )
    """)
    
    # OAuth Sessions: JWT sessions for third-party sites
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS oauth_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT UNIQUE NOT NULL,
        client_id TEXT NOT NULL,
        address TEXT NOT NULL,
        score INTEGER,
        has_nft BOOLEAN,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        is_active BOOLEAN DEFAULT 1,
        FOREIGN KEY(client_id) REFERENCES oauth_clients(client_id)
    )
    """)
    
    # ===== S-02: OAuth access-token lifecycle store =====
    # OAuth access tokens are stateless JWTs carrying a `jti`. Without a
    # server-side record a leaked token stays usable until `exp` (24 h) and
    # cannot be revoked. This table is the authoritative lifecycle record.
    #
    # Deliberately a DEDICATED table:
    #   * `oauth_sessions` is keyed by `session_id`, which is never part of
    #     the JWT, so it cannot be joined to a token.
    #   * keeping lifecycle separate avoids touching legacy OAuth tables.
    #
    # This is NOT an anti-replay nonce store - a valid token stays reusable
    # until expiry or explicit revocation.
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS oauth_token_jti (
        jti TEXT PRIMARY KEY,
        sub TEXT NOT NULL,
        client_id TEXT NOT NULL,
        issued_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'active',
        revoked_at TEXT,
        revocation_reason TEXT
    )
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_oauth_token_jti_client
        ON oauth_token_jti(client_id)
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_oauth_token_jti_sub
        ON oauth_token_jti(sub)
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_oauth_token_jti_expires
        ON oauth_token_jti(expires_at)
    """)
    
    # ===== DYNAMIC GATE CONFIGURATION =====
    # Allows each owner to configure their own Bot for secure one-time links
    # MULTI-GATE SUPPORT: One owner can have multiple gates per platform!
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS owner_gate_configs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner_wallet TEXT NOT NULL,
        platform TEXT NOT NULL,
        
        -- Bot Credentials (ENCRYPTED with GATE_ENCRYPTION_KEY!)
        bot_token_encrypted TEXT,
        group_id TEXT NOT NULL,
        channel_id TEXT,
        
        -- Verification Status
        bot_username TEXT,
        bot_verified BOOLEAN DEFAULT 0,
        verified_at TEXT,
        last_health_check TEXT,
        health_status TEXT,
        
        -- Fallback (for owners without bot)
        static_invite_link TEXT,
        
        -- Metadata
        group_name TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT,
        is_active BOOLEAN DEFAULT 1,
        
        -- Access Control: Minimum Resonance Score required (50-200)
        min_score INTEGER DEFAULT 50,
        
        -- Security: Track who can manage this gate
        -- MULTI-GATE: Changed from UNIQUE(owner_wallet, platform) to allow multiple groups per platform
        UNIQUE(owner_wallet, platform, group_id),
        FOREIGN KEY(owner_wallet) REFERENCES users(address)
    )
    """)
    
    # Migration: Add min_score column if not exists (for existing databases)
    try:
        cursor.execute("ALTER TABLE owner_gate_configs ADD COLUMN min_score INTEGER DEFAULT 50")
    except:
        pass  # Column already exists
    
    # Migration: If old owner_telegram_groups exists, we keep it for backward compatibility
    # New gates should use owner_gate_configs instead
    
    conn.commit()
    conn.close()
    print(f"✓ Datenbank initialisiert: {DB_PATH}")

def generate_token(address: str, duration_minutes = None) -> str:
    """
    Generiert einen JWT-ähnlichen Token
    
    Args:
        address: Wallet-Adresse
        duration_minutes: Token-Gültigkeitsdauer in Minuten (None = Standard TOKEN_EXPIRY_MINUTES = 2 Min)
    """
    if duration_minutes is None:
        duration_minutes = TOKEN_EXPIRY_MINUTES
    elif duration_minutes == 0:
        # 0 = kein Ablaufdatum, Token gilt bis manuelles Abmelden
        duration_minutes = 525600  # 1 Jahr als Maximum
    
    expiry = (datetime.now(timezone.utc) + timedelta(minutes=int(duration_minutes))).timestamp()
    token_data = f"{address}:{expiry}"
    signature = hashlib.sha256((token_data + TOKEN_SECRET).encode()).hexdigest()
    token = f"{token_data}:{signature}"
    
    log_activity("DEBUG", "TOKEN", "Generated new token", address=address[:10], duration_minutes=duration_minutes, expiry_timestamp=expiry)
    return token

def verify_token(token: str) -> dict:
    """Verifiziert und dekodiert einen Token"""
    try:
        parts = token.split(":")
        if len(parts) != 3:
            wallet_logger.warning(f"Invalid token format received")
            return {"valid": False, "error": "Invalid token format"}
        
        address, expiry_str, signature = parts
        expected_sig = hashlib.sha256((f"{address}:{expiry_str}" + TOKEN_SECRET).encode()).hexdigest()
        
        if signature != expected_sig:
            wallet_logger.warning(f"Token signature mismatch for {address[:10]}")
            return {"valid": False, "error": "Invalid signature"}
        
        expiry = float(expiry_str)
        if datetime.fromtimestamp(expiry, tz=timezone.utc) < datetime.now(timezone.utc):
            wallet_logger.warning(f"Token expired for {address[:10]}")
            return {"valid": False, "error": "Token expired"}
        
        log_activity("DEBUG", "TOKEN", "Token verified", address=address[:10])
        return {"valid": True, "address": address, "expiry": expiry}
    except Exception as e:
        wallet_logger.error(f"Token verification error: {str(e)}")
        return {"valid": False, "error": str(e)}

async def trigger_airdrop(address: str) -> dict:
    """
    Trigger Airdrop via Telegram Bot API mit Retry-Logik
    Die echte Ausführung passiert im Telegram Bot Service
    """
    address = address.lower()
    max_retries = 3
    retry_delay = 0.5  # 500ms
    
    for attempt in range(max_retries):
        try:
            # Prüfe ob Wallet bereits Airdrop bekommen hat
            conn = get_db_connection()
            conn.execute("PRAGMA busy_timeout=5000")  # 5 Sekunden Timeout
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM airdrops WHERE address=?", (address,))
            existing_airdrop = cursor.fetchone()
            
            if existing_airdrop:
                conn.close()
                logger.info(f"⚠️ Airdrop already received for {address}")
                return {"triggered": False, "message": "Airdrop already received"}
            
            # Bestimme Status basierend auf Admin-Credentials
            if not ADMIN_WALLET or not ADMIN_PRIVATE_KEY:
                status = "pending_admin"
                logger.warning(f"⚠️ Airdrop pending (waiting for admin approval): {address}")
            else:
                status = "pending_execution"
                logger.info(f"✓ Airdrop queued for execution: {address}")
            
            # Registriere Airdrop in Datenbank
            cursor.execute(
                """INSERT INTO airdrops (address, amount, status, created_at)
                   VALUES (?, ?, ?, ?)""",
                (address, AIRDROP_AMOUNT, status, datetime.now(timezone.utc).isoformat())
            )
            conn.commit()
            conn.close()
            
            return {
                "triggered": True,
                "address": address,
                "amount": AIRDROP_AMOUNT,
                "status": status,
                "message": f"Airdrop of {AIRDROP_AMOUNT} AERA registered with status: {status}"
            }
            
        except Exception as e:
            if 'conn' in locals():
                conn.close()
            
            if attempt < max_retries - 1 and "database is locked" in str(e):
                logger.warning(f"⏳ Airdrop retry {attempt + 1}/{max_retries}: {str(e)}")
                await asyncio.sleep(retry_delay * (attempt + 1))  # Exponential backoff
                continue
            
            logger.error(f"❌ Airdrop error (attempt {attempt + 1}): {str(e)}")
            return {"triggered": False, "message": f"Airdrop failed: {str(e)}"}
    
    return {"triggered": False, "message": "Airdrop failed after retries"}

@app.on_event("startup")
async def startup_event():
    """App-Start: Initialisiere Datenbank und Blockchain Services"""
    init_db()
    # --- Agent Identity Layer (additive, off unless AGENT_LAYER_ENABLED=true) ---
    try:
        import agent as _agent_pkg
        if _agent_pkg.is_enabled():
            from agent import repository as _agent_repo
            from agent import routes as _agent_routes
            _agent_repo.init_schema()
            app.include_router(_agent_routes.router)
            logger.info("   🤖 Agent Identity Layer aktiviert (/api/agents/*)")
    except Exception as _e:
        logger.warning(f"   ⚠️ Agent Layer init skipped: {_e}")
    # --- Inbound standard-A2A gateway (additive, off unless
    #     AERA_A2A_GATEWAY_ENABLED=true). Requires the Agent Layer, because it
    #     routes to AEra agents. Does NOT modify the Agent Layer. ---
    try:
        import a2a_gateway as _a2a_gw
        if _a2a_gw.is_enabled():
            import agent as _agent_pkg2
            if not _agent_pkg2.is_enabled():
                raise RuntimeError("Agent Identity Layer is required but disabled")
            from a2a_gateway import credentials as _gw_cred
            from a2a_gateway import replay as _gw_replay
            from a2a_gateway import routes as _gw_routes
            from agent.repository import get_connection as _gw_conn
            _c = _gw_conn()
            try:
                _gw_replay.init_schema(_c)
                _gw_cred.init_schema(_c)
                _c.commit()
            finally:
                _c.close()
            app.include_router(_gw_routes.router)
            logger.info("   🌐 Inbound A2A Gateway aktiviert "
                        "(/.well-known/agent-card.json, /api/a2a)")
    except Exception as _e:
        logger.warning(f"   ⚠️ A2A Gateway init skipped: {_e}")
    logger.info("🚀 VEra-Resonance Server gestartet")
    logger.info(f"   🌐 Öffentliche URL: {PUBLIC_URL}")
    logger.info(f"   📍 Host: {HOST}:{PORT}")
    logger.info(f"   🔐 CORS Origins: {CORS_ORIGINS}")
    
    # Initialize Dynamic Gate Service
    if GATE_SERVICE_AVAILABLE:
        try:
            db_path = os.path.join(os.path.dirname(__file__), "aera.db")
            init_gate_service(db_path)
            logger.info("   🚪 Dynamic Gate Service initialisiert")
        except Exception as e:
            logger.warning(f"   ⚠️ Gate Service init failed: {e}")
    
    # Start Gate Health Check Task
    if GATE_SERVICE_AVAILABLE:
        asyncio.create_task(gate_health_check_loop())
        logger.info("   🔍 Gate Health Check Task gestartet")
    
    # Starte Blockchain Sync Queue Processor
    from blockchain_sync import start_sync_queue_processor, add_to_sync_queue, should_sync_score
    asyncio.create_task(start_sync_queue_processor())
    logger.info("   ⛓️  Blockchain Sync Queue gestartet")
    
    # Starte NFT Mint Confirmation Checker
    from nft_confirmation import start_nft_confirmation_checker
    asyncio.create_task(start_nft_confirmation_checker())
    logger.info("   🎨 NFT Mint Confirmation Checker gestartet")
    
    # Starte OAuth Session Cleanup Job
    asyncio.create_task(oauth_session_cleanup_loop())
    logger.info("   🧹 OAuth Session Cleanup Job gestartet")
    
    # Initial Scan: Füge alle User mit Score ≥10 zur Sync-Queue hinzu (async task)
    async def initial_sync_scan():
        try:
            from resonance_calculator import calculate_resonance_score
            from blockchain_sync import add_to_sync_queue
            
            # Wait a bit for sync processor to be ready
            await asyncio.sleep(2)
            
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT address, score, blockchain_score
                FROM users
                WHERE score >= 10
                ORDER BY score DESC
            """)
            users = cursor.fetchall()
            
            added_count = 0
            for address, db_score, blockchain_score in users:
                # Calculate total resonance (own + follower bonus)
                own, follower_bonus, count, total_resonance = calculate_resonance_score(address, conn)
                blockchain_score = blockchain_score or 0
                
                # Check if resonance differs from blockchain AND is a milestone (every 2 points)
                if total_resonance != blockchain_score and total_resonance % 2 == 0:
                    await add_to_sync_queue(address, total_resonance)
                    added_count += 1
                    logger.info(f"   📋 Queued: {address[:10]}... ({total_resonance} → blockchain: {blockchain_score})")
            
            conn.close()
            
            if added_count > 0:
                logger.info(f"   📊 {added_count} users added to initial sync queue")
            else:
                logger.info(f"   ℹ️  No users need blockchain sync at startup")
        except Exception as e:
            logger.error(f"   ❌ Failed to scan users for initial sync: {e}")
    
    # Start initial scan as async task
    asyncio.create_task(initial_sync_scan())

@app.get("/", response_class=HTMLResponse)
async def root():
    """AEraLogin Landing Page - Now serving landing.html"""
    with open(os.path.join(os.path.dirname(__file__), "landing.html"), "r") as f:
        return f.read()

@app.get("/resonance", response_class=HTMLResponse)
async def resonance_landing():
    """Resonance Landing Page - Gold & Sand Theme"""
    with open(os.path.join(os.path.dirname(__file__), "landing-resonance.html"), "r") as f:
        return f.read()

@app.get("/landing", response_class=HTMLResponse)
async def new_landing():
    """New Modern Landing Page - Authenticity & Resonance Theme"""
    with open(os.path.join(os.path.dirname(__file__), "landing.html"), "r") as f:
        return f.read()

# NOTE: /dashboard route is defined below with proper Cache-Control headers

@app.get("/follow", response_class=HTMLResponse)
async def follow_page(request: Request):
    """
    Dynamic Landing Page for Followers - Adapts styling based on referrer platform
    Only ONE template, dynamically styled!
    """
    referrer = request.headers.get("referer", request.headers.get("referrer", ""))
    
    # WICHTIG: URL-Parameter "source" hat PRIORITÄT vor Referrer-Header!
    url_source = request.query_params.get("source", "").strip().lower()
    referrer_source = url_source if url_source else extract_referrer_source(referrer)
    
    # Get platform config or default
    platform = PLATFORM_CONFIG.get(referrer_source, PLATFORM_CONFIG["direct"])
    
    logger.info(f"✓ Serving dynamic landing for: {referrer_source} ({platform['name']})")
    
    return templates.TemplateResponse("index.html", {
        "request": request,
        "platform_source": referrer_source,
        "platform_name": platform["name"],
        "platform_color": platform["color"],
        "platform_gradient": platform["gradient"],
        "platform_emoji": platform["emoji"],
        "platform_badge": platform["badge"]
    })

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    """Admin Follower Dashboard"""
    from fastapi.responses import HTMLResponse as HR
    with open(os.path.join(os.path.dirname(__file__), "dashboard.html"), "r") as f:
        content = f.read()
    return HR(content=content, headers={"Cache-Control": "no-cache, no-store, must-revalidate"})

@app.get("/dashboard.html", response_class=HTMLResponse)
async def dashboard_html():
    """Admin Follower Dashboard (with .html extension)"""
    from fastapi.responses import HTMLResponse as HR
    with open(os.path.join(os.path.dirname(__file__), "dashboard.html"), "r") as f:
        content = f.read()
    return HR(content=content, headers={"Cache-Control": "no-cache, no-store, must-revalidate"})

@app.get("/user-dashboard", response_class=HTMLResponse)
async def user_dashboard():
    """User Dashboard - Protected area for verified users"""
    from fastapi.responses import HTMLResponse as HR
    with open(os.path.join(os.path.dirname(__file__), "user-dashboard.html"), "r") as f:
        content = f.read()
    return HR(content=content, headers={"Cache-Control": "no-cache, no-store, must-revalidate"})

@app.get("/user-dashboard.html", response_class=HTMLResponse)
async def user_dashboard_html():
    """User Dashboard - Protected area for verified users (with .html extension)"""
    from fastapi.responses import HTMLResponse as HR
    with open(os.path.join(os.path.dirname(__file__), "user-dashboard.html"), "r") as f:
        content = f.read()
    return HR(content=content, headers={"Cache-Control": "no-cache, no-store, must-revalidate"})

@app.get("/blockchain-dashboard.js")
async def blockchain_dashboard_js():
    """Blockchain Dashboard JavaScript Module"""
    from fastapi.responses import FileResponse
    js_path = os.path.join(os.path.dirname(__file__), "blockchain-dashboard.js")
    return FileResponse(js_path, media_type="application/javascript")

@app.get("/aera-chat.js")
async def aera_chat_js():
    """AEra Chat Widget JavaScript"""
    from fastapi.responses import FileResponse
    js_path = os.path.join(os.path.dirname(__file__), "aera-chat.js")
    return FileResponse(js_path, media_type="application/javascript")

@app.get("/aera-chat.css")
async def aera_chat_css():
    """AEra Chat Widget CSS"""
    from fastapi.responses import FileResponse
    css_path = os.path.join(os.path.dirname(__file__), "aera-chat.css")
    return FileResponse(css_path, media_type="text/css")

@app.get("/blockchain-test.html", response_class=HTMLResponse)
async def blockchain_test():
    """Blockchain Integration Test Page"""
    with open(os.path.join(os.path.dirname(__file__), "blockchain-test.html"), "r") as f:
        return f.read()

@app.get("/blockchain-direct-test.html", response_class=HTMLResponse)
async def blockchain_direct_test():
    """Direct Blockchain API Test Page"""
    with open(os.path.join(os.path.dirname(__file__), "blockchain-direct-test.html"), "r") as f:
        return f.read()

@app.get("/join-telegram", response_class=HTMLResponse)
async def join_telegram():
    """Telegram Gate - Identity NFT verification for private Telegram access"""
    with open(os.path.join(os.path.dirname(__file__), "join-telegram.html"), "r") as f:
        return f.read()

@app.get("/join-discord", response_class=HTMLResponse)
async def join_discord(request: Request):
    """Discord Gate - Uses same page as Telegram, preserves all query parameters"""
    from fastapi.responses import RedirectResponse
    # Preserve all query parameters and add source=discord
    query_params = dict(request.query_params)
    query_params['source'] = 'discord'
    query_string = "&".join(f"{k}={v}" for k, v in query_params.items())
    return RedirectResponse(url=f"/join-telegram?{query_string}", status_code=302)

@app.get("/security-concept.html", response_class=HTMLResponse)
async def security_concept():
    """Security Concept Documentation - Sybil-Resistance & Bot-Prevention"""
    with open(os.path.join(os.path.dirname(__file__), "security-concept.html"), "r") as f:
        return f.read()

@app.get("/logo.html", response_class=HTMLResponse)
async def logo_page():
    """Logo Page - AEraLogIn Branding"""
    with open(os.path.join(os.path.dirname(__file__), "logo.html"), "r") as f:
        return f.read()

# ===== SDK DOCUMENTATION ROUTES =====
@app.get("/sdk-docs", response_class=HTMLResponse)
async def sdk_documentation():
    """SDK Documentation - Third-Party Integration Guide"""
    docs_path = os.path.join(os.path.dirname(__file__), "docs", "sdk-documentation.html")
    if os.path.exists(docs_path):
        with open(docs_path, "r") as f:
            return f.read()
    return HTMLResponse("<h1>SDK Documentation coming soon</h1>", status_code=200)

@app.get("/developer", response_class=HTMLResponse)
async def developer_portal():
    """Developer Portal - Redirect to SDK Docs"""
    return HTMLResponse(
        '<html><head><meta http-equiv="refresh" content="0;url=/sdk-docs"></head></html>',
        status_code=302
    )

@app.get("/api/health")
async def health_check():
    """Health-Check Endpoint with deployment info"""
    # NEW: Try to detect Tailscale IP
    tailscale_ip = None
    try:
        import socket
        hostname = socket.gethostname()
        # Tailscale IPs start with 100.
        for ip in socket.gethostbyname_ex(hostname)[2]:
            if ip.startswith('100.'):
                tailscale_ip = ip
                break
    except:
        pass
    
    return {
        "status": "healthy",
        "service": "VEra-Resonance v0.1",
        "timestamp": int(time.time()),
        "database": "connected" if os.path.exists(DB_PATH) else "disconnected",
        "database_path": DB_PATH,
        "deployment": {
            "mode": DEPLOYMENT_MODE,
            "local_url": f"http://localhost:{PORT}",
            "tailscale_ip": tailscale_ip,
            "tailscale_url": f"http://{tailscale_ip}/dashboard" if tailscale_ip else None,
            "public_url": PUBLIC_URL
        }
    }

@app.get("/api/debug")
async def debug_info(req: Request):
    """Debug Info für Troubleshooting"""
    client_host = req.client.host if req.client else "unknown"
    return {
        "server": "VEra-Resonance v0.1",
        "timestamp": int(time.time()),
        "client_ip": client_host,
        "database": {
            "path": DB_PATH,
            "exists": os.path.exists(DB_PATH),
            "size_mb": os.path.getsize(DB_PATH) / (1024 * 1024) if os.path.exists(DB_PATH) else 0
        },
        "cors": "enabled",
        "endpoints": {
            "health": "/api/health",
            "verify": "POST /api/verify",
            "user": "GET /api/user/{address}",
            "stats": "GET /api/stats",
            "events": "GET /api/events/{address}"
        }
    }

@app.post("/api/vera-chat")
async def vera_chat_proxy(req: Request):
    """
    VERA-Chat Proxy Endpoint
    Leitet Anfragen an den separaten VERA-KI Server (Port 8850) weiter
    
    Request:
        {
            "message": "Was ist AEra?",
            "context": "optional context info"
        }
    
    Response:
        {
            "response": "KI Antwort...",
            "timestamp": "2025-12-06T..."
        }
    """
    import httpx
    
    try:
        data = await req.json()
        message = data.get("message", "").strip()
        context = data.get("context")
        
        if not message:
            return {"error": "No message provided", "success": False}
        
        # Weiterleitung an VERA-KI Server (localhost:8850)
        VERA_API_URL = "http://localhost:8850/api/chat"
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                VERA_API_URL,
                json={"message": message, "context": context}
            )
            
            if response.status_code == 200:
                result = response.json()
                logger.info(f"VERA-Chat: '{message[:50]}...' → {len(result.get('response', ''))} chars")
                return result
            else:
                logger.error(f"VERA-KI Server Error: {response.status_code}")
                return {
                    "error": "VERA-KI Service temporarily unavailable",
                    "success": False
                }
                
    except httpx.ConnectError:
        logger.error("Cannot connect to VERA-KI Server (Port 8850)")
        return {
            "error": "Chat service offline. Please try again later.",
            "success": False
        }
    except Exception as e:
        logger.error(f"VERA-Chat Proxy Error: {e}")
        return {
            "error": "Internal server error",
            "success": False
        }

@app.post("/api/nonce")
async def get_nonce(req: Request):
    """
    Generiert eine Nonce für Message-Signing
    Diese Nonce muss vom Client mit MetaMask signiert werden
    """
    try:
        data = await req.json()
        address = data.get("address", "").lower()
        
        if not address or not address.startswith("0x") or len(address) != 42:
            log_activity("ERROR", "AUTH", "Invalid nonce request", address=address[:10] if address else "unknown")
            return {"error": "Invalid address", "success": False}
        
        # Generiere zufällige Nonce
        nonce = secrets.token_hex(16)
        log_activity("DEBUG", "AUTH", "Nonce generated", address=address[:10], nonce=nonce[:16])
        
        return {
            "success": True,
            "address": address,
            "nonce": nonce,
            "message": f"Signiere diese Nachricht um dich bei AEra anzumelden:\nNonce: {nonce}"
        }
    except Exception as e:
        log_activity("ERROR", "AUTH", f"Nonce error: {str(e)}")
        return {"error": str(e), "success": False}

# ===== USER PROFILE ENDPOINT =====

@app.post("/api/user/profile")
async def get_user_profile(req: Request):
    """
    Get user profile data for User Dashboard
    
    Request:
        { "address": "0x..." }
    
    Response:
        {
            "success": true,
            "address": "0x...",
            "display_name": "Builder 0x1234...",
            "nft_verified": true,
            "score": 123.45,
            "blockchain_score": 100,
            "communities": ["telegram"],
            "join_date": "2025-01-15"
        }
    """
    try:
        data = await req.json()
        address = data.get("address", "").lower()
        
        if not address or not address.startswith("0x") or len(address) != 42:
            log_activity("ERROR", "USER_PROFILE", "Invalid address", address=address[:10] if address else "none")
            return {"success": False, "error": "Invalid address"}
        
        log_activity("DEBUG", "USER_PROFILE", f"Profile requested for {address[:10]}...")
        
        # Get user data from database
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get basic user info - use correct column names!
        cursor.execute("""
            SELECT 
                address,
                display_name,
                avatar_emoji,
                score,
                blockchain_score,
                created_at,
                identity_status,
                identity_nft_token_id,
                first_seen
            FROM users 
            WHERE LOWER(address) = ?
        """, (address,))
        
        user_row = cursor.fetchone()
        
        if not user_row:
            conn.close()
            log_activity("DEBUG", "USER_PROFILE", f"User not found: {address[:10]}...")
            return {
                "success": False,
                "error": "User not found"
            }
        
        # Check NFT status - first from DB, then from chain if needed
        has_nft = user_row['identity_status'] == 'active' and user_row['identity_nft_token_id']
        if not has_nft:
            try:
                has_nft = await web3_service.has_identity_nft(address)
            except Exception as nft_err:
                log_activity("WARN", "USER_PROFILE", f"NFT check failed: {str(nft_err)}")
        
        # Get community access (Telegram gates granted)
        cursor.execute("""
            SELECT COUNT(DISTINCT owner_wallet) as community_count
            FROM telegram_invites 
            WHERE LOWER(address) = ? AND granted = 1
        """, (address,))
        
        community_row = cursor.fetchone()
        community_count = community_row['community_count'] if community_row else 0
        
        # Calculate Resonance Score (with follower bonus)
        from resonance_calculator import calculate_resonance_score
        own_score, follower_bonus, follower_count, total_resonance = calculate_resonance_score(address, conn)
        
        conn.close()
        
        # Build response
        response = {
            "success": True,
            "address": address,
            "display_name": user_row['display_name'] if user_row['display_name'] else None,
            "avatar_emoji": user_row['avatar_emoji'] if user_row['avatar_emoji'] else '👤',
            "nft_verified": has_nft,
            "token_id": user_row['identity_nft_token_id'],
            "score": float(total_resonance) if total_resonance else 0.0,
            "own_score": float(own_score) if own_score else 0.0,
            "follower_bonus": float(follower_bonus) if follower_bonus else 0.0,
            "follower_count": follower_count,
            "blockchain_score": float(user_row['blockchain_score']) if user_row['blockchain_score'] else 0.0,
            "communities": community_count,
            "join_date": user_row['created_at'] or user_row['first_seen']
        }
        
        log_activity("INFO", "USER_PROFILE", f"Profile loaded for {address[:10]}..., NFT: {has_nft}, Score: {response['score']}")
        return response
        
    except Exception as e:
        log_activity("ERROR", "USER_PROFILE", f"Error: {str(e)}")
        return {"success": False, "error": str(e)}


@app.post("/api/user/update-profile")
async def update_user_profile(req: Request):
    """
    ✏️ Update user profile (display name and avatar emoji)
    
    Request:
        {
            "address": "0x...",
            "display_name": "MyUsername" (optional, max 30 chars),
            "avatar_emoji": "🚀" (optional, single emoji)
        }
    
    Response:
        {
            "success": true,
            "display_name": "MyUsername",
            "avatar_emoji": "🚀"
        }
    """
    try:
        data = await req.json()
        address = data.get("address", "").lower()
        
        if not address or not address.startswith("0x") or len(address) != 42:
            return {"success": False, "error": "Invalid wallet address"}
        
        display_name = data.get("display_name", "").strip()
        avatar_emoji = data.get("avatar_emoji", "").strip()
        
        # Validate display_name (max 30 characters)
        if display_name and len(display_name) > 30:
            return {"success": False, "error": "Display name must be 30 characters or less"}
        
        # Validate avatar_emoji (should be a single emoji or empty)
        if avatar_emoji and len(avatar_emoji) > 10:  # Allow for emoji modifiers
            return {"success": False, "error": "Invalid avatar emoji"}
        
        # Default emoji if not provided
        if not avatar_emoji:
            avatar_emoji = '👤'
        
        log_activity("INFO", "USER_PROFILE", f"Profile update requested", 
                    address=address[:10], 
                    display_name=display_name[:20] if display_name else "default",
                    avatar=avatar_emoji)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if user exists
        cursor.execute("SELECT address FROM users WHERE LOWER(address) = ?", (address,))
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return {"success": False, "error": "User not found. Please login first."}
        
        # Update profile
        cursor.execute("""
            UPDATE users 
            SET display_name = ?, avatar_emoji = ?
            WHERE LOWER(address) = ?
        """, (display_name if display_name else None, avatar_emoji, address))
        
        conn.commit()
        conn.close()
        
        log_activity("INFO", "USER_PROFILE", f"✓ Profile updated successfully", 
                    address=address[:10])
        
        return {
            "success": True,
            "display_name": display_name if display_name else None,
            "avatar_emoji": avatar_emoji,
            "message": "Profile updated successfully"
        }
        
    except Exception as e:
        log_activity("ERROR", "USER_PROFILE", f"Update error: {str(e)}")
        return {"success": False, "error": str(e)}


# ===== TELEGRAM-GATE ENDPOINTS =====

@app.post("/api/check-rft")
async def check_rft(req: Request):
    """
    🔐 Telegram-Gate: Check if wallet has AEra Identity NFT
    
    Request:
        {
            "address": "0x..."
        }
    
    Response (has NFT):
        {
            "allowed": true,
            "has_nft": true,
            "token_id": 123,
            "reason": "Identity NFT verified"
        }
    
    Response (no NFT):
        {
            "allowed": false,
            "has_nft": false,
            "reason": "No Identity NFT found",
            "mint_required": true
        }
    """
    try:
        data = await req.json()
        address = data.get("address", "").lower()
        
        if not address or not address.startswith("0x") or len(address) != 42:
            log_activity("ERROR", "TELEGRAM_GATE", "Invalid address format", address=address[:10] if address else "none")
            return {
                "allowed": False,
                "has_nft": False,
                "error": "Invalid wallet address",
                "mint_required": False
            }
        
        # Check if user has Identity NFT via web3_service
        has_identity = await web3_service.has_identity_nft(address)
        
        if has_identity:
            # Get token ID for verification
            token_id = await web3_service.get_identity_token_id(address)
            
            log_activity("INFO", "TELEGRAM_GATE", "✓ NFT verified - Access granted", 
                        address=address[:10], 
                        token_id=token_id)
            
            return {
                "allowed": True,
                "has_nft": True,
                "token_id": token_id,
                "reason": "Identity NFT verified"
            }
        else:
            log_activity("INFO", "TELEGRAM_GATE", "✗ No NFT - Access denied", 
                        address=address[:10])
            
            return {
                "allowed": False,
                "has_nft": False,
                "reason": "No Identity NFT found",
                "mint_required": True
            }
            
    except Exception as e:
        log_activity("ERROR", "TELEGRAM_GATE", f"Check RFT error: {str(e)}")
        return {
            "allowed": False,
            "has_nft": False,
            "error": str(e),
            "mint_required": False
        }


@app.post("/api/telegram/invite")
async def telegram_invite(req: Request):
    """
    🔐 Platform-Gate: Generate invite link (only if NFT verified)
    Supports: telegram, discord, and other platforms
    
    NEW: Automatic Intent-Bridge for Android + MetaMask Mobile
    
    Request:
        {
            "address": "0x...",
            "platform": "telegram" | "discord" (optional, defaults to telegram),
            "user_agent": "..." (optional, for device detection)
        }
    
    Response (success - standard):
        {
            "success": true,
            "redirect_token": "...",
            "redirect_url": "/api/community/redirect?token=...",
            "message": "Welcome to AEra community!",
            "platform": "telegram" | "discord",
            "method": "standard_redirect",
            "device": "desktop" | "mobile_standard"
        }
    
    Response (success - intent_bridge for Android + In-App Browser):
        {
            "success": true,
            "method": "intent_bridge",
            "intent_url": "intent://resolve?...",
            "message": "Telegram wird geöffnet...",
            "platform": "telegram",
            "device": "android_in_app"
        }
    
    Response (success - iOS Universal Link):
        {
            "success": true,
            "method": "ios_universal_link",
            "redirect_token": "...",
            "redirect_url": "/api/community/redirect?token=...",
            "message": "Telegram wird geöffnet...",
            "platform": "telegram",
            "device": "ios_in_app"
        }
    
    Response (denied):
        {
            "success": false,
            "error": "No Identity NFT found",
            "mint_required": true
        }
    """
    try:
        data = await req.json()
        address = data.get("address", "").lower()
        platform = data.get("platform", "telegram").lower()  # Default to telegram
        group_id = data.get("group_id", None)  # NEW: For multi-gate support
        user_agent = data.get("user_agent", "")  # NEW: Frontend sends User-Agent for device detection
        
        if not address or not address.startswith("0x") or len(address) != 42:
            return {
                "success": False,
                "error": "Invalid wallet address",
                "mint_required": False
            }
        
        # CRITICAL: Verify NFT ownership before granting access
        has_identity = await web3_service.has_identity_nft(address)
        
        if not has_identity:
            log_activity("WARNING", f"{platform.upper()}_GATE", "❌ Invite denied - No NFT", 
                        address=address[:10])
            return {
                "success": False,
                "error": "No Identity NFT found",
                "mint_required": True
            }
        
        # ========================================
        # NEW: DEVICE DETECTION FOR INTENT-BRIDGE
        # ========================================
        is_android = "Android" in user_agent
        is_ios = "iPhone" in user_agent or "iPad" in user_agent or "iOS" in user_agent
        is_mobile = is_android or is_ios
        
        # In-App Browser Detection (MetaMask, Trust Wallet, Coinbase/Base Wallet, Rainbow, etc.)
        is_in_app_browser = any(x in user_agent.lower() for x in [
            "metamask",
            "trust",
            "coinbase",
            "coinbasewallet",
            "base",          # Base Wallet (Coinbase)
            "rainbow",
            "phantom",
            "uniswap",
            "1inch",
            "zerion",
            "wallet"         # Generic wallet detection
        ])
        
        log_activity("INFO", f"{platform.upper()}_GATE", "Device detected", 
                    address=address[:10],
                    is_android=is_android,
                    is_ios=is_ios,
                    is_mobile=is_mobile,
                    is_in_app=is_in_app_browser,
                    user_agent=user_agent[:50] if user_agent else "none")
        
        # Get invite link (owner-specific or default)
        owner_wallet = (data.get("owner_wallet") or "").lower() if isinstance(data, dict) else ""
        invite_link = None
        link_method = "static"  # Track how link was created
        
        # =====================================================================
        # ON-CHAIN RESONANCE SCORE CHECK: Read directly from Smart Contract!
        # Contract: 0x9A814DBF7E2352CE9eA6293b4b731B2a24800102 (Base Mainnet)
        # This is the REAL, tamper-proof score stored on the blockchain.
        # =====================================================================
        onchain_resonance_score = 0  # Default for users without on-chain score
        required_min_score = 50  # Default requirement
        
        # Read RESONANCE SCORE directly from blockchain (most accurate!)
        try:
            onchain_resonance_score = await web3_service.get_blockchain_score(address)
            log_activity("INFO", f"{platform.upper()}_GATE", 
                        f"📊 On-Chain Resonance Score: {onchain_resonance_score}", 
                        address=address[:10])
        except Exception as score_err:
            log_activity("WARNING", f"{platform.upper()}_GATE", f"Could not read on-chain score: {score_err}")
            # Fallback: Calculate from DB if blockchain read fails
            try:
                from resonance_calculator import calculate_resonance_score
                conn_score = get_db_connection()
                own_score, follower_bonus, follower_count, onchain_resonance_score = calculate_resonance_score(address, conn_score)
                conn_score.close()
                log_activity("INFO", f"{platform.upper()}_GATE", 
                            f"📊 Fallback DB Resonance: {onchain_resonance_score}", 
                            address=address[:10])
            except Exception as calc_err:
                log_activity("WARNING", f"{platform.upper()}_GATE", f"Could not calculate fallback: {calc_err}")
        
        # Check gate's min_score requirement (if owner-specific gate)
        if owner_wallet and GATE_SERVICE_AVAILABLE:
            try:
                gate_service = get_gate_service()
                if gate_service:
                    gate_config = await gate_service.get_gate_config(owner_wallet, platform, group_id)
                    if gate_config:
                        required_min_score = gate_config.get("min_score", 50) or 50
                        group_name = gate_config.get("group_name", "This community")
                        
                        # 🚫 BLOCK ACCESS if ON-CHAIN RESONANCE score is below required
                        if onchain_resonance_score < required_min_score:
                            score_diff = required_min_score - onchain_resonance_score
                            
                            log_activity("WARNING", f"{platform.upper()}_GATE", 
                                        f"❌ Access denied - On-Chain Score too low ({onchain_resonance_score} < {required_min_score})", 
                                        address=address[:10],
                                        owner=owner_wallet[:10],
                                        group=group_name)
                            
                            # Clear, user-friendly error message
                            return {
                                "success": False,
                                "error": f"Access denied: {group_name} requires a minimum Resonance Score of {required_min_score}. Your score: {onchain_resonance_score}.",
                                "error_details": {
                                    "group_name": group_name,
                                    "required_score": required_min_score,
                                    "your_score": onchain_resonance_score,
                                    "missing_points": score_diff
                                },
                                "score_required": required_min_score,
                                "your_onchain_score": onchain_resonance_score,
                                "hint": f"You need {score_diff} more points. Increase your score through regular interactions!",
                                "mint_required": False
                            }
                        
                        log_activity("INFO", f"{platform.upper()}_GATE", 
                                    f"✓ On-Chain score check passed ({onchain_resonance_score} >= {required_min_score})", 
                                    address=address[:10])
            except Exception as gate_err:
                log_activity("WARNING", f"{platform.upper()}_GATE", f"Gate config check error: {str(gate_err)}")
        
        # =====================================================================
        # NEW: Try Dynamic GateService first for owner-specific one-time links
        # =====================================================================
        if owner_wallet and GATE_SERVICE_AVAILABLE:
            try:
                gate_service = get_gate_service()
                if gate_service:
                    success, gate_link, method = await gate_service.create_one_time_invite(
                        owner_wallet=owner_wallet,
                        platform=platform,
                        user_address=address,
                        group_id=group_id,  # Multi-gate support
                        expire_seconds=300
                    )
                    
                    if success:
                        invite_link = gate_link
                        link_method = method
                        log_activity("INFO", f"{platform.upper()}_GATE", f"✓ GateService link created ({method})", 
                                    owner=owner_wallet[:10],
                                    address=address[:10])
            except Exception as gate_err:
                log_activity("WARNING", f"{platform.upper()}_GATE", f"GateService error: {str(gate_err)}")
        
        # =====================================================================
        # LEGACY: Fall back to old owner_telegram_groups table (static links)
        # =====================================================================
        if not invite_link and owner_wallet:
            try:
                conn_temp = get_db_connection()
                cursor_temp = conn_temp.cursor()
                cursor_temp.execute(
                    """SELECT telegram_invite_link FROM owner_telegram_groups 
                       WHERE owner_wallet = ? AND is_active = 1""",
                    (owner_wallet,)
                )
                result = cursor_temp.fetchone()
                conn_temp.close()
                
                if result:
                    invite_link = result['telegram_invite_link']
                    link_method = "legacy_static"
                    log_activity("INFO", f"{platform.upper()}_GATE", "✓ Using legacy owner link (static)", 
                                owner=owner_wallet[:10])
            except Exception as e:
                log_activity("WARNING", f"{platform.upper()}_GATE", f"Could not fetch owner link: {str(e)}")
        
        # Fallback to default link from .env based on platform
        if not invite_link:
            if platform == "discord":
                # 🎮 DISCORD: Try Bot API for TRUE one-time links first!
                if DISCORD_BOT_AVAILABLE and discord_bot and discord_bot.is_configured:
                    try:
                        log_activity("INFO", "DISCORD_GATE", "🎮 Attempting Bot API one-time link", address=address[:10])
                        
                        success, bot_link = await create_one_time_discord_invite(
                            wallet_address=address,
                            expire_seconds=300  # 5 minutes
                        )
                        
                        if success:
                            invite_link = bot_link
                            log_activity("INFO", "DISCORD_GATE", "✅ Bot API one-time link created", 
                                        address=address[:10], 
                                        link=invite_link[:30] + "...")
                        else:
                            log_activity("WARNING", "DISCORD_GATE", f"Bot API failed: {bot_link}, falling back to static link")
                    except Exception as bot_err:
                        log_activity("WARNING", "DISCORD_GATE", f"Bot API error: {str(bot_err)}, falling back to static link")
                
                # Fallback to static link from .env
                if not invite_link:
                    invite_link = os.getenv("DISCORD_INVITE_LINK", "")
                    if invite_link:
                        log_activity("INFO", "DISCORD_GATE", "Using default Discord link from .env (static)")
            else:
                # 🤖 TELEGRAM: Try Bot API for TRUE one-time links first!
                if telegram_bot.is_configured:
                    try:
                        log_activity("INFO", "TELEGRAM_GATE", "🤖 Attempting Bot API one-time link", address=address[:10])
                        
                        # 🔐 NEW: Get user's score for Group Bot capabilities
                        user_score = 50  # Default
                        try:
                            conn_score = get_db_connection()
                            cursor_score = conn_score.cursor()
                            cursor_score.execute("SELECT score FROM users WHERE address=?", (address,))
                            score_result = cursor_score.fetchone()
                            if score_result:
                                user_score = score_result['score']
                            conn_score.close()
                        except Exception as score_err:
                            log_activity("WARNING", "TELEGRAM_GATE", f"Could not fetch score: {score_err}")
                        
                        # Use extended function if Group Bot is available
                        if GROUP_BOT_AVAILABLE:
                            success, bot_link = await create_one_time_telegram_invite_with_capabilities(
                                wallet_address=address,
                                score=user_score,
                                min_score=50,  # TODO: Make configurable
                                expire_seconds=300  # 5 minutes
                            )
                            if success:
                                log_activity("INFO", "TELEGRAM_GATE", "✅ Link + Capabilities created", 
                                            address=address[:10], score=user_score)
                        else:
                            success, bot_link = await create_one_time_telegram_invite(
                                wallet_address=address,
                                expire_seconds=300  # 5 minutes
                            )
                        
                        if success:
                            invite_link = bot_link
                            log_activity("INFO", "TELEGRAM_GATE", "✅ Bot API one-time link created", 
                                        address=address[:10], 
                                        link=invite_link[:30] + "...")
                        else:
                            log_activity("WARNING", "TELEGRAM_GATE", f"Bot API failed: {bot_link}, falling back to static link")
                    except Exception as bot_err:
                        log_activity("WARNING", "TELEGRAM_GATE", f"Bot API error: {str(bot_err)}, falling back to static link")
                
                # Fallback to static link from .env
                if not invite_link:
                    invite_link = os.getenv("TELEGRAM_INVITE_LINK", "")
                    if invite_link:
                        log_activity("INFO", "TELEGRAM_GATE", "Using default Telegram link from .env (static)")
        
        if not invite_link:
            platform_name = "Discord" if platform == "discord" else "Telegram"
            log_activity("ERROR", f"{platform.upper()}_GATE", f"{platform_name} invite link not configured")
            return {
                "success": False,
                "error": f"{platform_name} invite link not configured",
                "mint_required": False
            }
        
        # Log successful access grant
        log_activity("INFO", f"{platform.upper()}_GATE", "✓ Invite link granted", 
                    address=address[:10])
        
        # Track invite in database + add 0.1 score bonus (ONE-TIME ONLY)
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Extract owner_wallet from request data (if provided)
            owner_wallet = (data.get("owner_wallet") or "").lower() if isinstance(data, dict) else ""
            
            # MULTI-GATE: Check if invited to THIS SPECIFIC gate (owner + platform + group_id)
            # This allows same user to join multiple gates of same platform/owner
            cursor.execute(
                """SELECT COUNT(*) as count FROM telegram_invites 
                   WHERE address = ? AND owner_wallet = ? AND platform = ? AND group_id = ?""",
                (address, owner_wallet or None, platform, group_id)
            )
            result = cursor.fetchone()
            previous_invites = result['count'] if result else 0
            
            # Insert invite record (with platform AND group_id for multi-gate support)
            cursor.execute(
                """INSERT OR IGNORE INTO telegram_invites 
                   (address, invited_at, granted, owner_wallet, platform, group_id)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (address, datetime.now(timezone.utc).isoformat(), 1, owner_wallet or None, platform, group_id)
            )
            
            # 🎯 ONE-TIME BONUS: Add 0.1 points for first join (per platform)
            if previous_invites == 0:
                try:
                    # Update backend score (resonance_score = off-chain score)
                    cursor.execute(
                        """UPDATE users SET resonance_score = resonance_score + 0.1 
                           WHERE address = ?""",
                        (address,)
                    )
                    platform_name = "Discord" if platform == "discord" else "Telegram"
                    log_activity("INFO", f"{platform.upper()}_BONUS", f"✓ +0.1 score for first {platform_name} join", 
                                address=address[:10])
                except Exception as score_err:
                    log_activity("WARNING", f"{platform.upper()}_BONUS", f"Could not update score: {str(score_err)}")
            
            conn.commit()
            conn.close()
            
            if owner_wallet:
                log_activity("INFO", f"{platform.upper()}_GATE", "✓ Invite tracked with owner", 
                            address=address[:10], owner=owner_wallet[:10])
        except Exception as db_err:
            # Non-critical error - invite still works
            log_activity("WARNING", f"{platform.upper()}_GATE", f"Could not log invite: {str(db_err)}")
        
        # ========================================
        # DISCORD: INTENT-BRIDGE FOR ANDROID + IN-APP BROWSER
        # ========================================
        if platform == "discord" and is_android and is_in_app_browser:
            # Extract invite code from Discord link
            # Format: https://discord.gg/ABC123 or https://discord.com/invite/ABC123
            invite_code = None
            if invite_link:
                if "discord.gg/" in invite_link:
                    invite_code = invite_link.split("discord.gg/")[-1].split("?")[0].strip()
                elif "discord.com/invite/" in invite_link:
                    invite_code = invite_link.split("invite/")[-1].split("?")[0].strip()
            
            if invite_code:
                # Build Android Intent URL for direct Discord opening
                # Discord package: com.discord
                intent_url = f"intent://discord.com/invite/{invite_code}#Intent;scheme=https;package=com.discord;end"
                
                log_activity("INFO", "DISCORD_GATE", "🎮 Intent-Bridge activated (Android + In-App)", 
                            address=address[:10],
                            device="android_in_app",
                            invite_code=invite_code[:10] + "...")
                
                return {
                    "success": True,
                    "method": "intent_bridge",
                    "intent_url": intent_url,
                    "fallback_url": "market://details?id=com.discord",
                    "message": "Discord is opening...",
                    "platform": platform,
                    "device": "android_in_app"
                }
        
        # ========================================
        # DISCORD: iOS UNIVERSAL LINK
        # ========================================
        if platform == "discord" and is_ios and is_in_app_browser:
            # Discord Universal Links work well on iOS
            # Format stays: https://discord.gg/ABC123 (iOS handles it automatically)
            
            log_activity("INFO", "DISCORD_GATE", "🍎 iOS Universal Link activated", 
                        address=address[:10],
                        device="ios_in_app")
            
            # Generate one-time token for iOS redirect
            redirect_token = secrets.token_urlsafe(32)
            token_created_at = datetime.now(timezone.utc)
            token_expires_at = token_created_at + timedelta(seconds=30)
            
            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute(
                    """INSERT INTO community_redirect_tokens 
                       (token, address, invite_link, platform, created_at, expires_at, used)
                       VALUES (?, ?, ?, ?, ?, ?, 0)""",
                    (redirect_token, address, invite_link, platform, 
                     token_created_at.isoformat(), token_expires_at.isoformat())
                )
                conn.commit()
                conn.close()
            except Exception as token_err:
                log_activity("ERROR", "DISCORD_GATE", f"iOS token generation failed: {str(token_err)}")
                return {"success": False, "error": "Could not generate secure redirect"}
            
            return {
                "success": True,
                "method": "ios_universal_link",
                "redirect_token": redirect_token,
                "redirect_url": f"/api/community/redirect?token={redirect_token}",
                "message": "Discord is opening...",
                "platform": platform,
                "device": "ios_in_app",
                "expires_in_seconds": 30
            }
        
        # ========================================
        # TELEGRAM: INTENT-BRIDGE FOR ANDROID + IN-APP BROWSER
        # ========================================
        if platform == "telegram" and is_android and is_in_app_browser:
            # Extract group identifier from invite link
            # Format: https://t.me/+XXXXXX or https://t.me/joinchat/XXXXXX
            group_identifier = None
            if invite_link:
                if "/+" in invite_link:
                    # Format: https://t.me/+ABC123
                    group_identifier = invite_link.split("+")[-1].split("?")[0].strip()
                elif "joinchat/" in invite_link:
                    # Format: https://t.me/joinchat/ABC123
                    group_identifier = invite_link.split("joinchat/")[-1].split("?")[0].strip()
            
            if group_identifier:
                # Build Android Intent URL for direct Telegram opening
                # This bypasses WebView limitations in MetaMask/Trust Wallet
                intent_url = f"intent://resolve?domain=t.me&startapp={group_identifier}#Intent;scheme=tg;package=org.telegram.messenger;end"
                
                log_activity("INFO", "TELEGRAM_GATE", "🤖 Intent-Bridge activated (Android + In-App)", 
                            address=address[:10],
                            device="android_in_app",
                            group_id=group_identifier[:10] + "...")
                
                return {
                    "success": True,
                    "method": "intent_bridge",
                    "intent_url": intent_url,
                    "fallback_url": f"market://details?id=org.telegram.messenger",
                    "message": "Telegram wird geöffnet...",
                    "platform": platform,
                    "device": "android_in_app"
                }
        
        # ========================================
        # TELEGRAM: iOS UNIVERSAL LINK
        # ========================================
        if platform == "telegram" and is_ios and is_in_app_browser:
            # iOS: Use telegram.me instead of t.me (better Universal Link support)
            ios_link = invite_link.replace("https://t.me/", "https://telegram.me/") if invite_link else invite_link
            
            log_activity("INFO", "TELEGRAM_GATE", "🍎 iOS Universal Link activated", 
                        address=address[:10],
                        device="ios_in_app")
            
            # Generate one-time token for iOS redirect
            redirect_token = secrets.token_urlsafe(32)
            token_created_at = datetime.now(timezone.utc)
            token_expires_at = token_created_at + timedelta(seconds=30)
            
            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute(
                    """INSERT INTO community_redirect_tokens 
                       (token, address, invite_link, platform, created_at, expires_at, used)
                       VALUES (?, ?, ?, ?, ?, ?, 0)""",
                    (redirect_token, address, ios_link, platform, 
                     token_created_at.isoformat(), token_expires_at.isoformat())
                )
                conn.commit()
                conn.close()
            except Exception as token_err:
                log_activity("ERROR", "TELEGRAM_GATE", f"iOS token generation failed: {str(token_err)}")
                return {"success": False, "error": "Could not generate secure redirect"}
            
            return {
                "success": True,
                "method": "ios_universal_link",
                "redirect_token": redirect_token,
                "redirect_url": f"/api/community/redirect?token={redirect_token}",
                "message": "Telegram wird geöffnet...",
                "platform": platform,
                "device": "ios_in_app",
                "expires_in_seconds": 30
            }
        
        # ========================================
        # STANDARD: Desktop / Normal Mobile Browser
        # ========================================
        # 🔐 SECURITY: Generate one-time redirect token instead of returning link directly
        # Token is valid for 30 seconds and can only be used once
        redirect_token = secrets.token_urlsafe(32)  # 256-bit secure token
        token_created_at = datetime.now(timezone.utc)
        token_expires_at = token_created_at + timedelta(seconds=30)
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                """INSERT INTO community_redirect_tokens 
                   (token, address, invite_link, platform, created_at, expires_at, used)
                   VALUES (?, ?, ?, ?, ?, ?, 0)""",
                (redirect_token, address, invite_link, platform, 
                 token_created_at.isoformat(), token_expires_at.isoformat())
            )
            
            # ✅ SUCCESS: Register and confirm the follower now that gate access was granted!
            # For gate platforms (telegram/discord), follower is NOT registered in /api/verify
            # so we need to INSERT here, not just UPDATE
            if owner_wallet:
                # Get user's current score for follower entry
                cursor.execute("SELECT score FROM users WHERE address = ?", (address,))
                user_row = cursor.fetchone()
                follower_score = user_row['score'] if user_row else 50
                
                # Use INSERT OR REPLACE to handle both new and existing entries
                # UNIQUE constraint is (owner_wallet, follower_address, source_platform)
                cursor.execute(
                    """INSERT INTO followers 
                       (owner_wallet, follower_address, follower_score, verified_at, source_platform, verified, follow_confirmed, confirmed_at)
                       VALUES (?, ?, ?, ?, ?, 1, 1, ?)
                       ON CONFLICT(owner_wallet, follower_address, source_platform) DO UPDATE SET
                           follower_score = excluded.follower_score,
                           follow_confirmed = 1,
                           confirmed_at = excluded.confirmed_at""",
                    (owner_wallet, address, follower_score, datetime.now(timezone.utc).isoformat(), platform, datetime.now(timezone.utc).isoformat())
                )
                log_activity("INFO", f"{platform.upper()}_GATE", "✓ Follower registered & confirmed after gate access", 
                            owner=owner_wallet[:10], follower=address[:10], score=follower_score)
            
            conn.commit()
            conn.close()
            log_activity("INFO", f"{platform.upper()}_GATE", "✓ Secure redirect token generated", 
                        address=address[:10], token=redirect_token[:8],
                        device="desktop" if not is_mobile else "mobile_standard")
        except Exception as token_err:
            log_activity("ERROR", f"{platform.upper()}_GATE", f"Token generation failed: {str(token_err)}")
            return {
                "success": False,
                "error": "Could not generate secure redirect",
                "mint_required": False
            }
        
        platform_name = "Discord" if platform == "discord" else "Telegram"
        return {
            "success": True,
            "method": "standard_redirect",
            "redirect_token": redirect_token,  # Token instead of direct link
            "redirect_url": f"/api/community/redirect?token={redirect_token}",
            "message": f"Welcome to AEra {platform_name} community!",
            "platform": platform,
            "device": "desktop" if not is_mobile else "mobile_standard",
            "expires_in_seconds": 30
        }
        
    except Exception as e:
        log_activity("ERROR", "PLATFORM_GATE", f"Invite generation error: {str(e)}")
        return {
            "success": False,
            "error": "Internal server error",
            "mint_required": False
        }


@app.get("/api/community/redirect")
async def community_redirect(token: str):
    """
    🔐 Secure One-Time Redirect to Community Invite Link
    
    This endpoint validates the token and performs a server-side redirect.
    The actual invite link is NEVER exposed to the frontend JavaScript.
    
    Security features:
    - Token is valid for 30 seconds only
    - Token can only be used ONCE
    - Token is cryptographically secure (256-bit)
    
    Query Parameters:
        token: The one-time redirect token from /api/telegram/invite
    
    Response:
        HTTP 302 Redirect to the actual community invite link
        OR error page if token is invalid/expired/used
    """
    from fastapi.responses import RedirectResponse, HTMLResponse
    
    if not token:
        return HTMLResponse(
            content="""
            <html>
            <head><title>Invalid Token</title></head>
            <body style="font-family: sans-serif; text-align: center; padding: 50px; background: #1a1a2e; color: white;">
                <h1>❌ Invalid Token</h1>
                <p>No redirect token provided.</p>
                <a href="/landing" style="color: #00d4ff;">← Back to Landing Page</a>
            </body>
            </html>
            """,
            status_code=400
        )
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Fetch token data
        cursor.execute(
            """SELECT id, address, invite_link, platform, expires_at, used 
               FROM community_redirect_tokens WHERE token = ?""",
            (token,)
        )
        token_data = cursor.fetchone()
        
        if not token_data:
            conn.close()
            log_activity("WARNING", "REDIRECT", "❌ Invalid token attempted", token=token[:8] if len(token) >= 8 else token)
            return HTMLResponse(
                content="""
                <html>
                <head><title>Invalid Token</title></head>
                <body style="font-family: sans-serif; text-align: center; padding: 50px; background: #1a1a2e; color: white;">
                    <h1>❌ Invalid Token</h1>
                    <p>This redirect token does not exist.</p>
                    <a href="/landing" style="color: #00d4ff;">← Back to Landing Page</a>
                </body>
                </html>
                """,
                status_code=404
            )
        
        # Check if token already used
        if token_data['used']:
            conn.close()
            log_activity("WARNING", "REDIRECT", "❌ Token already used", token=token[:8])
            return HTMLResponse(
                content="""
                <html>
                <head><title>Token Already Used</title></head>
                <body style="font-family: sans-serif; text-align: center; padding: 50px; background: #1a1a2e; color: white;">
                    <h1>⚠️ Token Already Used</h1>
                    <p>This redirect token has already been used.</p>
                    <p style="opacity: 0.7; font-size: 14px;">For security, each token can only be used once.</p>
                    <a href="/landing" style="color: #00d4ff;">← Back to Landing Page</a>
                </body>
                </html>
                """,
                status_code=403
            )
        
        # Check if token expired
        expires_at = datetime.fromisoformat(token_data['expires_at'].replace('Z', '+00:00'))
        now = datetime.now(timezone.utc)
        
        if now > expires_at:
            conn.close()
            log_activity("WARNING", "REDIRECT", "❌ Token expired", token=token[:8])
            return HTMLResponse(
                content="""
                <html>
                <head><title>Token Expired</title></head>
                <body style="font-family: sans-serif; text-align: center; padding: 50px; background: #1a1a2e; color: white;">
                    <h1>⏰ Token Expired</h1>
                    <p>This redirect token has expired (valid for 30 seconds only).</p>
                    <p style="opacity: 0.7; font-size: 14px;">Please go through the verification process again.</p>
                    <a href="/landing" style="color: #00d4ff;">← Back to Landing Page</a>
                </body>
                </html>
                """,
                status_code=410
            )
        
        # Mark token as used
        cursor.execute(
            """UPDATE community_redirect_tokens 
               SET used = 1, used_at = ? 
               WHERE id = ?""",
            (now.isoformat(), token_data['id'])
        )
        conn.commit()
        conn.close()
        
        invite_link = token_data['invite_link']
        platform = token_data['platform']
        address = token_data['address']
        
        log_activity("INFO", "REDIRECT", f"✓ Secure redirect to {platform}", 
                    address=address[:10], token=token[:8])
        
        # Perform the actual redirect (HTTP 302)
        return RedirectResponse(url=invite_link, status_code=302)
        
    except Exception as e:
        log_activity("ERROR", "REDIRECT", f"Redirect error: {str(e)}")
        return HTMLResponse(
            content=f"""
            <html>
            <head><title>Error</title></head>
            <body style="font-family: sans-serif; text-align: center; padding: 50px; background: #1a1a2e; color: white;">
                <h1>❌ Error</h1>
                <p>An error occurred while processing your request.</p>
                <a href="/landing" style="color: #00d4ff;">← Back to Landing Page</a>
            </body>
            </html>
            """,
            status_code=500
        )


@app.get("/api/telegram-bot/status")
async def telegram_bot_status():
    """
    🤖 Check Telegram Bot configuration and status
    
    Returns:
        {
            "configured": true/false,
            "ready": true/false,
            "bot_username": "@YourBot",
            "can_create_one_time_links": true/false,
            "error": "..." (if any)
        }
    """
    try:
        status = await check_bot_setup()
        
        return {
            "configured": status.get("token_configured", False) and status.get("group_configured", False),
            "ready": status.get("ready", False),
            "bot_username": f"@{status['bot_info'].get('username')}" if status.get("bot_info") else None,
            "can_create_one_time_links": status.get("ready", False),
            "permissions": status.get("permissions"),
            "message": status.get("message"),
            "error": status.get("error")
        }
        
    except Exception as e:
        log_activity("ERROR", "TELEGRAM_BOT", f"Status check failed: {str(e)}")
        return {
            "configured": False,
            "ready": False,
            "error": str(e)
        }


@app.post("/api/telegram-gate/set-group")
async def set_telegram_group(req: Request):
    """
    🔧 Set owner's personal Telegram group link
    
    Request:
        {
            "owner": "0x...",
            "telegram_link": "https://t.me/+XXXXX",
            "group_name": "My Private Group" (optional)
        }
    
    Response:
        {
            "success": true,
            "message": "Telegram group configured successfully"
        }
    """
    try:
        data = await req.json()
        owner = data.get("owner", "").lower()
        telegram_link = data.get("telegram_link", "").strip()
        group_name = data.get("group_name", "").strip()
        
        # Validation
        if not owner or not owner.startswith("0x") or len(owner) != 42:
            return {"success": False, "error": "Invalid owner address"}
        
        if not telegram_link or not telegram_link.startswith("https://t.me/"):
            return {"success": False, "error": "Invalid Telegram invite link"}
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Insert or update owner's Telegram link
        cursor.execute(
            """INSERT INTO owner_telegram_groups 
               (owner_wallet, telegram_invite_link, group_name, created_at, is_active)
               VALUES (?, ?, ?, ?, 1)
               ON CONFLICT(owner_wallet) DO UPDATE SET
                   telegram_invite_link = excluded.telegram_invite_link,
                   group_name = excluded.group_name""",
            (owner, telegram_link, group_name or None, datetime.now(timezone.utc).isoformat())
        )
        conn.commit()
        conn.close()
        
        log_activity("INFO", "TELEGRAM_GATE", "✓ Owner Telegram group configured", 
                    owner=owner[:10], 
                    group_name=group_name or "unnamed")
        
        return {
            "success": True,
            "message": "Telegram group configured successfully",
            "telegram_link": telegram_link,
            "group_name": group_name
        }
        
    except Exception as e:
        log_activity("ERROR", "TELEGRAM_GATE", f"Set group error: {str(e)}")
        return {"success": False, "error": str(e)}


@app.get("/api/telegram-gate/stats/{owner}")
async def get_telegram_gate_stats(owner: str):
    """
    📊 Get Telegram Gate statistics for an owner
    
    Returns:
        {
            "success": true,
            "owner": "0x...",
            "invite_count": 5,
            "telegram_link": "https://t.me/+XXX",
            "group_name": "My Group",
            "recent_invites": [
                {
                    "address": "0x...",
                    "invited_at": "2025-12-06T..."
                }
            ]
        }
    """
    try:
        owner = owner.lower()
        
        if not owner or not owner.startswith("0x") or len(owner) != 42:
            return {
                "success": False,
                "error": "Invalid owner address"
            }
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get owner's Telegram group configuration
        cursor.execute(
            """SELECT telegram_invite_link, group_name 
               FROM owner_telegram_groups 
               WHERE owner_wallet = ? AND is_active = 1""",
            (owner,)
        )
        group_config = cursor.fetchone()
        telegram_link = group_config['telegram_invite_link'] if group_config else None
        group_name = group_config['group_name'] if group_config else None
        
        # Count total invites via this owner's link
        cursor.execute(
            """SELECT COUNT(*) as count 
               FROM telegram_invites 
               WHERE owner_wallet = ?""",
            (owner,)
        )
        invite_count = cursor.fetchone()['count']
        
        # Get recent invites (last 10)
        cursor.execute(
            """SELECT address, invited_at 
               FROM telegram_invites 
               WHERE owner_wallet = ?
               ORDER BY invited_at DESC
               LIMIT 10""",
            (owner,)
        )
        recent_invites = [
            {
                "address": row['address'],
                "invited_at": row['invited_at']
            }
            for row in cursor.fetchall()
        ]
        
        conn.close()
        
        log_activity("INFO", "TELEGRAM_GATE", "Stats retrieved", 
                    owner=owner[:10], 
                    invite_count=invite_count)
        
        return {
            "success": True,
            "owner": owner,
            "invite_count": invite_count,
            "telegram_link": telegram_link,
            "group_name": group_name,
            "has_configured_group": telegram_link is not None,
            "recent_invites": recent_invites
        }
        
    except Exception as e:
        log_activity("ERROR", "TELEGRAM_GATE", f"Stats error: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "invite_count": 0
        }


# ============================================================================
# ===== DYNAMIC GATE SERVICE API =====
# ============================================================================
# Neue API-Endpoints für dynamische Bot-Konfiguration
# Ermöglicht Ownern, eigene Bots zu konfigurieren statt hardcoded .env
# ============================================================================

@app.post("/api/gate/detect-groups")
async def detect_telegram_groups(req: Request):
    """
    🔍 Auto-detect Telegram groups where bot is admin
    
    Uses Telegram's getUpdates API to find groups the bot has been added to.
    The user just needs to:
    1. Create a bot via @BotFather
    2. Add the bot to their group as admin
    3. Send any message in the group
    4. Call this endpoint → we return the group info!
    
    Request:
        {
            "bot_token": "123456:ABC..."
        }
    
    Response (success):
        {
            "success": true,
            "groups": [
                {
                    "group_id": "-1001234567890",
                    "group_name": "My Private Group",
                    "group_type": "supergroup" | "group" | "channel",
                    "member_count": 42 (if available)
                }
            ],
            "message": "Found 1 group(s)"
        }
    
    Response (no groups):
        {
            "success": true,
            "groups": [],
            "message": "No groups found. Make sure bot is admin and send a message in the group."
        }
    """
    try:
        data = await req.json()
        bot_token = data.get("bot_token", "").strip()
        
        if not bot_token:
            return {"success": False, "error": "bot_token is required"}
        
        # Basic token format validation
        if ":" not in bot_token:
            return {"success": False, "error": "Invalid bot token format (should be 123456:ABC...)"}
        
        import httpx
        
        # Step 1: Verify bot token is valid with getMe
        async with httpx.AsyncClient(timeout=10.0) as client:
            me_response = await client.get(f"https://api.telegram.org/bot{bot_token}/getMe")
            me_data = me_response.json()
            
            if not me_data.get("ok"):
                error_msg = me_data.get("description", "Unknown error")
                log_activity("ERROR", "GATE_DETECT", f"Invalid bot token: {error_msg}")
                return {"success": False, "error": f"Invalid bot token: {error_msg}"}
            
            bot_username = me_data.get("result", {}).get("username", "Unknown")
            log_activity("INFO", "GATE_DETECT", f"✓ Bot verified: @{bot_username}")
        
        # Step 2: Get updates to find groups
        async with httpx.AsyncClient(timeout=15.0) as client:
            updates_response = await client.get(
                f"https://api.telegram.org/bot{bot_token}/getUpdates",
                params={"limit": 100}  # Get last 100 updates
            )
            updates_data = updates_response.json()
            
            if not updates_data.get("ok"):
                return {
                    "success": False, 
                    "error": "Failed to get updates. Bot may be using webhook."
                }
        
        # Step 3: Extract unique groups from updates
        groups_found = {}  # Use dict to dedupe by group_id
        
        for update in updates_data.get("result", []):
            # Check message updates
            message = update.get("message") or update.get("my_chat_member", {}).get("chat")
            
            if message:
                chat = message.get("chat") if "chat" in message else message
                chat_id = str(chat.get("id", ""))
                chat_type = chat.get("type", "")
                
                # Only include groups/supergroups/channels (negative IDs)
                if chat_id.startswith("-") and chat_type in ["group", "supergroup", "channel"]:
                    if chat_id not in groups_found:
                        groups_found[chat_id] = {
                            "group_id": chat_id,
                            "group_name": chat.get("title", "Unknown Group"),
                            "group_type": chat_type
                        }
            
            # Also check my_chat_member updates (when bot is added to group)
            my_chat_member = update.get("my_chat_member")
            if my_chat_member:
                chat = my_chat_member.get("chat", {})
                chat_id = str(chat.get("id", ""))
                chat_type = chat.get("type", "")
                
                if chat_id.startswith("-") and chat_type in ["group", "supergroup", "channel"]:
                    if chat_id not in groups_found:
                        groups_found[chat_id] = {
                            "group_id": chat_id,
                            "group_name": chat.get("title", "Unknown Group"),
                            "group_type": chat_type
                        }
        
        # Step 4: Try to get member count for each group
        groups_list = list(groups_found.values())
        
        async with httpx.AsyncClient(timeout=10.0) as client:
            for group in groups_list:
                try:
                    count_response = await client.get(
                        f"https://api.telegram.org/bot{bot_token}/getChatMemberCount",
                        params={"chat_id": group["group_id"]}
                    )
                    count_data = count_response.json()
                    if count_data.get("ok"):
                        group["member_count"] = count_data.get("result", 0)
                except:
                    pass  # Member count is optional
        
        log_activity("INFO", "GATE_DETECT", f"Found {len(groups_list)} group(s) for @{bot_username}")
        
        if groups_list:
            return {
                "success": True,
                "bot_username": f"@{bot_username}",
                "groups": groups_list,
                "message": f"Found {len(groups_list)} group(s)"
            }
        else:
            return {
                "success": True,
                "bot_username": f"@{bot_username}",
                "groups": [],
                "message": "No groups found. Please:\n1. Add bot to your group as admin\n2. Send any message in the group\n3. Click 'Detect Groups' again"
            }
        
    except httpx.TimeoutException:
        return {"success": False, "error": "Telegram API timeout. Please try again."}
    except Exception as e:
        log_activity("ERROR", "GATE_DETECT", f"Detection error: {str(e)}")
        return {"success": False, "error": str(e)}


@app.post("/api/gate/detect-discord-servers")
async def detect_discord_servers(req: Request):
    """
    🎮 Auto-detect Discord servers (guilds) where bot is a member
    
    Discord bots automatically know which guilds they're in via the API.
    Unlike Telegram, no "getUpdates" needed - we query guilds directly.
    
    The user needs to:
    1. Create a bot at https://discord.com/developers/applications
    2. Enable SERVER MEMBERS INTENT in Bot settings
    3. Add bot to their server with these permissions:
       - Create Instant Invite
       - View Channels
    4. Call this endpoint → we return the guild info!
    
    Request:
        {
            "bot_token": "MTA2NzI...very_long_token"
        }
    
    Response (success):
        {
            "success": true,
            "bot_username": "MyBot#1234",
            "servers": [
                {
                    "guild_id": "123456789012345678",
                    "guild_name": "My Awesome Server",
                    "icon_url": "https://cdn.discordapp.com/icons/...",
                    "member_count": 150,
                    "owner": false,
                    "permissions": "2147483647"
                }
            ],
            "message": "Found 2 server(s)"
        }
    
    Response (no servers):
        {
            "success": true,
            "bot_username": "MyBot#1234",
            "servers": [],
            "message": "No servers found. Add bot to your server first."
        }
    """
    try:
        data = await req.json()
        bot_token = data.get("bot_token", "").strip()
        
        if not bot_token:
            return {"success": False, "error": "bot_token is required"}
        
        # Discord tokens are much longer than Telegram tokens
        if len(bot_token) < 50:
            return {"success": False, "error": "Invalid Discord bot token format (too short)"}
        
        import httpx
        
        DISCORD_API = "https://discord.com/api/v10"
        headers = {
            "Authorization": f"Bot {bot_token}",
            "Content-Type": "application/json"
        }
        
        # Step 1: Verify bot token with /users/@me
        async with httpx.AsyncClient(timeout=10.0) as client:
            me_response = await client.get(f"{DISCORD_API}/users/@me", headers=headers)
            
            if me_response.status_code == 401:
                return {"success": False, "error": "Invalid bot token (401 Unauthorized)"}
            
            if me_response.status_code != 200:
                return {"success": False, "error": f"Discord API error: HTTP {me_response.status_code}"}
            
            me_data = me_response.json()
            bot_username = me_data.get("username", "Unknown")
            bot_discriminator = me_data.get("discriminator", "0")
            bot_id = me_data.get("id", "")
            
            # New Discord usernames don't have discriminator
            if bot_discriminator == "0":
                bot_display = f"@{bot_username}"
            else:
                bot_display = f"{bot_username}#{bot_discriminator}"
            
            log_activity("INFO", "DISCORD_DETECT", f"✓ Bot verified: {bot_display}")
        
        # Step 2: Get all guilds the bot is in
        async with httpx.AsyncClient(timeout=15.0) as client:
            guilds_response = await client.get(
                f"{DISCORD_API}/users/@me/guilds",
                headers=headers
            )
            
            if guilds_response.status_code != 200:
                error_text = guilds_response.text
                return {
                    "success": False,
                    "error": f"Failed to get guilds: HTTP {guilds_response.status_code}",
                    "details": error_text[:200]
                }
            
            guilds_data = guilds_response.json()
        
        # Step 3: Process guilds and get additional info
        servers_list = []
        
        async with httpx.AsyncClient(timeout=10.0) as client:
            for guild in guilds_data:
                guild_id = guild.get("id", "")
                guild_name = guild.get("name", "Unknown Server")
                icon_hash = guild.get("icon")
                owner = guild.get("owner", False)
                permissions = guild.get("permissions", "0")
                
                server_info = {
                    "guild_id": guild_id,
                    "guild_name": guild_name,
                    "owner": owner,
                    "permissions": permissions
                }
                
                # Build icon URL if available
                if icon_hash:
                    ext = "gif" if icon_hash.startswith("a_") else "png"
                    server_info["icon_url"] = f"https://cdn.discordapp.com/icons/{guild_id}/{icon_hash}.{ext}"
                
                # Try to get member count (requires GUILD intent)
                try:
                    guild_detail = await client.get(
                        f"{DISCORD_API}/guilds/{guild_id}?with_counts=true",
                        headers=headers
                    )
                    if guild_detail.status_code == 200:
                        detail_data = guild_detail.json()
                        server_info["member_count"] = detail_data.get("approximate_member_count", 0)
                except:
                    pass  # Member count is optional
                
                # Try to get channels to find a suitable one for invites
                try:
                    channels_response = await client.get(
                        f"{DISCORD_API}/guilds/{guild_id}/channels",
                        headers=headers
                    )
                    if channels_response.status_code == 200:
                        channels = channels_response.json()
                        # Find first text channel
                        text_channels = [c for c in channels if c.get("type") == 0]
                        if text_channels:
                            server_info["default_channel_id"] = text_channels[0].get("id")
                            server_info["default_channel_name"] = text_channels[0].get("name")
                except:
                    pass
                
                servers_list.append(server_info)
        
        log_activity("INFO", "DISCORD_DETECT", f"Found {len(servers_list)} server(s) for {bot_display}")
        
        if servers_list:
            return {
                "success": True,
                "bot_username": bot_display,
                "bot_id": bot_id,
                "servers": servers_list,
                "message": f"Found {len(servers_list)} server(s)"
            }
        else:
            return {
                "success": True,
                "bot_username": bot_display,
                "bot_id": bot_id,
                "servers": [],
                "message": "No servers found. Please:\n1. Go to Discord Developer Portal\n2. OAuth2 → URL Generator\n3. Select 'bot' scope + 'Create Instant Invite' permission\n4. Use generated URL to add bot to your server\n5. Click 'Detect Servers' again"
            }
        
    except httpx.TimeoutException:
        return {"success": False, "error": "Discord API timeout. Please try again."}
    except Exception as e:
        log_activity("ERROR", "DISCORD_DETECT", f"Detection error: {str(e)}")
        return {"success": False, "error": str(e)}


@app.post("/api/gate/generate-discord-invite")
async def generate_discord_invite(req: Request):
    """
    🔗 Auto-generate a one-time invite link for a Discord server
    
    Creates an invite with max_uses=1 and configurable expiry.
    Bot must have CREATE_INSTANT_INVITE permission in the channel.
    
    Request:
        {
            "bot_token": "MTA2NzI...very_long_token",
            "guild_id": "123456789012345678",
            "channel_id": "987654321098765432" (optional - uses first text channel if not provided)
        }
    
    Response (success):
        {
            "success": true,
            "invite_link": "https://discord.gg/AbCdEf",
            "invite_code": "AbCdEf",
            "channel_name": "general",
            "max_uses": 1,
            "expires_in": 300,
            "message": "One-time invite link created"
        }
    """
    try:
        data = await req.json()
        bot_token = data.get("bot_token", "").strip()
        guild_id = data.get("guild_id", "").strip()
        channel_id = data.get("channel_id", "").strip()
        max_age = data.get("max_age", 300)  # Default 5 minutes
        
        if not bot_token:
            return {"success": False, "error": "bot_token is required"}
        
        if not guild_id:
            return {"success": False, "error": "guild_id is required"}
        
        import httpx
        
        DISCORD_API = "https://discord.com/api/v10"
        headers = {
            "Authorization": f"Bot {bot_token}",
            "Content-Type": "application/json"
        }
        
        # If no channel_id provided, find first text channel
        if not channel_id:
            async with httpx.AsyncClient(timeout=10.0) as client:
                channels_response = await client.get(
                    f"{DISCORD_API}/guilds/{guild_id}/channels",
                    headers=headers
                )
                
                if channels_response.status_code != 200:
                    return {
                        "success": False,
                        "error": "Cannot access server channels. Check bot permissions.",
                        "hint": "Bot needs 'View Channels' permission"
                    }
                
                channels = channels_response.json()
                text_channels = [c for c in channels if c.get("type") == 0]
                
                if not text_channels:
                    return {"success": False, "error": "No text channels found in server"}
                
                channel_id = text_channels[0].get("id")
                channel_name = text_channels[0].get("name", "unknown")
        else:
            channel_name = "specified"
        
        # Create the invite
        async with httpx.AsyncClient(timeout=10.0) as client:
            invite_response = await client.post(
                f"{DISCORD_API}/channels/{channel_id}/invites",
                headers=headers,
                json={
                    "max_age": max_age,
                    "max_uses": 1,
                    "unique": True
                }
            )
            
            if invite_response.status_code == 201 or invite_response.status_code == 200:
                invite_data = invite_response.json()
                invite_code = invite_data.get("code", "")
                
                log_activity("INFO", "DISCORD_INVITE", f"✓ One-time invite created for guild {guild_id[:10]}")
                
                return {
                    "success": True,
                    "invite_link": f"https://discord.gg/{invite_code}",
                    "invite_code": invite_code,
                    "channel_name": invite_data.get("channel", {}).get("name", channel_name),
                    "max_uses": invite_data.get("max_uses", 1),
                    "expires_in": max_age,
                    "message": "One-time invite link created"
                }
            else:
                error_text = invite_response.text
                
                # Check for permission errors
                if invite_response.status_code == 403:
                    return {
                        "success": False,
                        "error": "Bot lacks permission to create invites",
                        "hint": "Bot needs 'Create Instant Invite' permission in the channel"
                    }
                
                return {
                    "success": False,
                    "error": f"Failed to create invite: HTTP {invite_response.status_code}",
                    "details": error_text[:200]
                }
        
    except httpx.TimeoutException:
        return {"success": False, "error": "Discord API timeout. Please try again."}
    except Exception as e:
        log_activity("ERROR", "DISCORD_INVITE", f"Generate invite error: {str(e)}")
        return {"success": False, "error": str(e)}


@app.post("/api/gate/generate-invite-link")
async def generate_invite_link(req: Request):
    """
    🔗 Auto-generate an invite link for a Telegram group using bot API
    
    Uses exportChatInviteLink to create a permanent invite link.
    Bot must be admin with "Invite Users" permission.
    
    Request:
        {
            "bot_token": "123456:ABC...",
            "group_id": "-1001234567890"
        }
    
    Response (success):
        {
            "success": true,
            "invite_link": "https://t.me/+ABC123...",
            "message": "Invite link generated successfully"
        }
    """
    try:
        data = await req.json()
        bot_token = data.get("bot_token", "").strip()
        group_id = data.get("group_id", "").strip()
        
        if not bot_token:
            return {"success": False, "error": "bot_token is required"}
        
        if not group_id:
            return {"success": False, "error": "group_id is required"}
        
        import httpx
        
        async with httpx.AsyncClient(timeout=10.0) as client:
            # Try to export/create an invite link
            response = await client.post(
                f"https://api.telegram.org/bot{bot_token}/exportChatInviteLink",
                json={"chat_id": group_id}
            )
            result = response.json()
            
            if result.get("ok"):
                invite_link = result.get("result")
                log_activity("INFO", "GATE_INVITE", f"✓ Invite link generated for group {group_id[:15]}")
                return {
                    "success": True,
                    "invite_link": invite_link,
                    "message": "Invite link generated successfully"
                }
            else:
                error_msg = result.get("description", "Unknown error")
                
                # Common error: bot needs admin rights
                if "not enough rights" in error_msg.lower() or "admin" in error_msg.lower():
                    return {
                        "success": False,
                        "error": "Bot needs admin rights with 'Invite Users' permission",
                        "hint": "Make sure bot is admin and has 'Invite Users via Link' enabled"
                    }
                
                return {"success": False, "error": error_msg}
                
    except httpx.TimeoutException:
        return {"success": False, "error": "Telegram API timeout. Please try again."}
    except Exception as e:
        log_activity("ERROR", "GATE_INVITE", f"Generate invite error: {str(e)}")
        return {"success": False, "error": str(e)}


@app.post("/api/gate/configure")
async def configure_gate(req: Request):
    """
    🔐 Configure owner's personal Gate (Telegram/Discord)
    
    MULTI-GATE SUPPORT: One owner can configure multiple gates per platform!
    Each gate is identified by (owner, platform, group_id).
    
    Allows owners to set up their own bot for full security (one-time links).
    Bot token is encrypted before storage!
    
    Request:
        {
            "owner": "0x...",
            "platform": "telegram" | "discord",
            "bot_token": "123456:ABC...", (optional - for one-time links)
            "group_id": "-1001234567890",
            "channel_id": "123456789", (Discord only, optional)
            "group_name": "My Private Group", (optional)
            "static_invite_link": "https://t.me/+XXX" (fallback),
            "min_score": 50 (optional, 50-200, default 50)
        }
    
    Response:
        {
            "success": true,
            "message": "Gate configured successfully",
            "security_level": "high" | "low",
            "gate_id": "telegram:-1001234567890"
        }
    
    Security Levels:
        - HIGH: Bot token configured → true one-time links (member_limit=1)
        - LOW: Only static link → can be shared, no expiry
    """
    if not GATE_SERVICE_AVAILABLE:
        return {"success": False, "error": "Gate Service not available"}
    
    try:
        data = await req.json()
        owner = data.get("owner", "").lower()
        platform = data.get("platform", "").lower()
        bot_token = data.get("bot_token", "").strip()
        group_id = data.get("group_id", "").strip()
        channel_id = data.get("channel_id", "").strip()
        group_name = data.get("group_name", "").strip()
        static_invite_link = data.get("static_invite_link", "").strip()
        min_score = data.get("min_score", 50)
        
        # Validation
        if not owner or not owner.startswith("0x") or len(owner) != 42:
            return {"success": False, "error": "Invalid owner address"}
        
        if platform not in ["telegram", "discord"]:
            return {"success": False, "error": "Platform must be 'telegram' or 'discord'"}
        
        if not group_id:
            return {"success": False, "error": "group_id is required for multi-gate support"}
        
        # static_invite_link is optional IF bot_token is provided (bot can generate links)
        if not static_invite_link and not bot_token:
            return {"success": False, "error": "Either bot_token OR static_invite_link is required"}
        
        # Validate min_score (50-200)
        try:
            min_score = int(min_score)
            if min_score < 50 or min_score > 200:
                return {"success": False, "error": "min_score must be between 50 and 200"}
        except (ValueError, TypeError):
            min_score = 50
        
        # Get GateService
        gate_service = get_gate_service()
        if not gate_service:
            return {"success": False, "error": "Gate Service not initialized"}
        
        # Save configuration (with min_score)
        result = await gate_service.save_gate_config(
            owner_wallet=owner,
            platform=platform,
            bot_token=bot_token,
            group_id=group_id,
            channel_id=channel_id,
            group_name=group_name,
            static_invite_link=static_invite_link,
            min_score=min_score
        )
        
        if not result["success"]:
            return {"success": False, "error": result["error"]}
        
        # Determine security level
        security_level = "high" if bot_token else "low"
        gate_id = f"{platform}:{group_id}"
        
        log_activity("INFO", "GATE_SERVICE", f"✓ Gate configured ({platform})", 
                    owner=owner[:10], 
                    security=security_level,
                    min_score=min_score,
                    group_id=group_id[:15])
        
        # WICHTIG: User muss noch verifizieren wenn Bot-Token konfiguriert wurde!
        if bot_token:
            return {
                "success": True,
                "message": f"⚠️ Configuration saved! You MUST click '✅ Verify Bot Permissions' to complete setup.",
                "security_level": security_level,
                "has_bot": True,
                "has_static_fallback": bool(static_invite_link),
                "gate_id": gate_id,
                "min_score": min_score,
                "verified": False,
                "requires_verification": True
            }
        else:
            # Nur static link → kein Verify nötig
            return {
                "success": True,
                "message": f"{platform.title()} gate configured successfully (static link only)",
                "security_level": security_level,
                "has_bot": False,
                "has_static_fallback": True,
                "gate_id": gate_id,
                "min_score": min_score,
                "verified": True,
                "requires_verification": False
            }
        
    except Exception as e:
        log_activity("ERROR", "GATE_SERVICE", f"Configure error: {str(e)}")
        return {"success": False, "error": str(e)}


@app.post("/api/gate/verify-bot")
async def verify_gate_bot(req: Request):
    """
    ✅ Verify that owner's bot has correct permissions
    
    Tests the bot token and checks if bot is admin with invite permissions.
    Can be used in two modes:
    1. After saving: Just pass owner + platform → looks up config in DB
    2. Before saving: Pass bot_token + group_id directly → tests without saving
    
    Request (Mode 1 - from DB):
        {
            "owner": "0x...",
            "platform": "telegram" | "discord"
        }
    
    Request (Mode 2 - direct test):
        {
            "bot_token": "123456:ABC...",
            "group_id": "-1001234567890"
        }
    
    Response:
        {
            "success": true,
            "verified": true,
            "bot_username": "@MyBotUsername",
            "can_invite": true,
            "message": "✅ Bot has invite permissions"
        }
    """
    try:
        data = await req.json()
        bot_token = data.get("bot_token", "").strip()
        group_id = data.get("group_id", "").strip()
        owner = data.get("owner", "").lower()
        platform = data.get("platform", "").lower()
        
        # ===========================================
        # MODE 2: Direct verification (before saving)
        # ===========================================
        if bot_token and group_id:
            log_activity("INFO", "GATE_VERIFY", f"Direct bot verification (before save) - Platform: {platform or 'auto-detect'}")
            
            # Detect platform from token format if not provided
            if not platform:
                # Discord tokens are much longer (50+ chars) than Telegram tokens
                platform = "discord" if len(bot_token) > 50 else "telegram"
            
            # ===========================================
            # DISCORD VERIFICATION
            # ===========================================
            if platform == "discord":
                DISCORD_API = "https://discord.com/api/v10"
                headers = {
                    "Authorization": f"Bot {bot_token}",
                    "Content-Type": "application/json"
                }
                
                async with httpx.AsyncClient(timeout=10.0) as client:
                    # Step 1: Verify bot token with /users/@me
                    me_resp = await client.get(f"{DISCORD_API}/users/@me", headers=headers)
                    
                    if me_resp.status_code == 401:
                        return {
                            "success": False,
                            "verified": False,
                            "error": "Invalid Discord bot token"
                        }
                    
                    if me_resp.status_code != 200:
                        return {
                            "success": False,
                            "verified": False,
                            "error": f"Discord API error: {me_resp.status_code}"
                        }
                    
                    me_data = me_resp.json()
                    bot_username = f"{me_data.get('username', 'Unknown')}#{me_data.get('discriminator', '0000')}"
                    
                    # Step 2: Check if bot is in the guild
                    guild_resp = await client.get(f"{DISCORD_API}/guilds/{group_id}", headers=headers)
                    
                    if guild_resp.status_code == 403:
                        return {
                            "success": False,
                            "verified": False,
                            "bot_username": bot_username,
                            "error": "Bot is not a member of this server or lacks permissions"
                        }
                    
                    if guild_resp.status_code != 200:
                        return {
                            "success": False,
                            "verified": False,
                            "bot_username": bot_username,
                            "error": f"Could not access guild: {guild_resp.status_code}"
                        }
                    
                    guild_data = guild_resp.json()
                    guild_name = guild_data.get("name", "Unknown Server")
                    
                    # Step 3: Check bot permissions in the guild
                    # Get bot's member info to check permissions
                    bot_member_resp = await client.get(
                        f"{DISCORD_API}/guilds/{group_id}/members/{me_data['id']}", 
                        headers=headers
                    )
                    
                    can_invite = True  # If bot can access guild, it likely has permissions
                    
                    if bot_member_resp.status_code == 200:
                        # Check if bot has CREATE_INSTANT_INVITE permission (0x1)
                        # For simplicity, we assume if bot is in guild it can invite
                        can_invite = True
                    
                    return {
                        "success": True,
                        "verified": True,
                        "bot_username": bot_username,
                        "guild_name": guild_name,
                        "can_invite": can_invite,
                        "status": "member",
                        "message": f"✅ Discord Bot {bot_username} verified in '{guild_name}'"
                    }
            
            # ===========================================
            # TELEGRAM VERIFICATION (default)
            # ===========================================
            async with httpx.AsyncClient(timeout=10.0) as client:
                # Step 1: Verify token with getMe
                me_resp = await client.get(f"https://api.telegram.org/bot{bot_token}/getMe")
                me_data = me_resp.json()
                
                if not me_data.get("ok"):
                    return {
                        "success": False,
                        "verified": False,
                        "error": "Invalid bot token"
                    }
                
                bot_username = me_data["result"].get("username", "Unknown")
                
                # Step 2: Check if bot is admin in the group
                admin_resp = await client.get(
                    f"https://api.telegram.org/bot{bot_token}/getChatMember",
                    params={"chat_id": group_id, "user_id": me_data["result"]["id"]}
                )
                admin_data = admin_resp.json()
                
                if not admin_data.get("ok"):
                    return {
                        "success": False,
                        "verified": False,
                        "bot_username": f"@{bot_username}",
                        "error": f"Bot is not in the group or group not found: {admin_data.get('description', 'Unknown error')}"
                    }
                
                member_status = admin_data["result"].get("status", "")
                can_invite = admin_data["result"].get("can_invite_users", False)
                
                if member_status not in ["administrator", "creator"]:
                    return {
                        "success": False,
                        "verified": False,
                        "bot_username": f"@{bot_username}",
                        "error": f"Bot must be an admin. Current status: {member_status}"
                    }
                
                # Check invite permission
                if member_status == "creator":
                    can_invite = True  # Creator can always invite
                
                return {
                    "success": True,
                    "verified": True,
                    "bot_username": f"@{bot_username}",
                    "can_invite": can_invite,
                    "status": member_status,
                    "message": f"✅ Bot @{bot_username} is {member_status}" + 
                              (f" with invite permission" if can_invite else " (⚠️ no invite permission)")
                }
        
        # ===========================================
        # MODE 1: Verify from saved config (after saving)
        # ===========================================
        if not GATE_SERVICE_AVAILABLE:
            return {"success": False, "error": "Gate Service not available"}
        
        # Validation
        if not owner or not owner.startswith("0x") or len(owner) != 42:
            return {"success": False, "error": "Invalid owner address"}
        
        if platform not in ["telegram", "discord"]:
            return {"success": False, "error": "Platform must be 'telegram' or 'discord'"}
        
        # Get GateService
        gate_service = get_gate_service()
        if not gate_service:
            return {"success": False, "error": "Gate Service not initialized"}
        
        # Verify bot - pass group_id for multi-gate support!
        result = await gate_service.verify_bot(owner, platform, group_id if group_id else None)
        
        if result.get("success"):
            log_activity("INFO", "GATE_SERVICE", f"✅ Bot VERIFIED successfully", 
                        owner=owner[:10], 
                        platform=platform,
                        group_id=group_id[:15] if group_id else "auto",
                        bot_username=result.get("bot_username"))
        else:
            log_activity("WARNING", "GATE_SERVICE", f"❌ Bot verification FAILED", 
                        owner=owner[:10], 
                        platform=platform,
                        error=result.get("error"))
        
        return {
            "success": result.get("success", False),
            "verified": result.get("success", False),
            "bot_username": result.get("bot_username"),
            "can_invite": result.get("can_invite", False),
            "message": "✅ Bot verified! Gate is now ACTIVE (ADVANCED mode)." if result.get("success") 
                      else f"❌ Verification failed: {result.get('error')}",
            "error": result.get("error") if not result.get("success") else None
        }
        
    except Exception as e:
        log_activity("ERROR", "GATE_SERVICE", f"Verify error: {str(e)}")
        return {"success": False, "error": str(e)}


@app.get("/api/gate/status/{owner}")
async def get_gate_status(owner: str, platform: str = "telegram"):
    """
    📊 Get owner's gate configuration status
    
    Returns current configuration and security level.
    
    Path Parameters:
        owner: Wallet address of the gate owner
        
    Query Parameters:
        platform: 'telegram' or 'discord' (default: telegram)
    
    Response:
        {
            "success": true,
            "owner": "0x...",
            "platform": "telegram",
            "configured": true,
            "bot_verified": true,
            "bot_username": "@MyBot",
            "has_static_fallback": true,
            "security_level": "high",
            "group_name": "My Private Group"
        }
    
    Security Levels:
        - "high": Bot configured and verified → one-time links
        - "low": Only static link → shareable, no expiry
        - "none": Not configured
    """
    if not GATE_SERVICE_AVAILABLE:
        return {"success": False, "error": "Gate Service not available"}
    
    try:
        owner = owner.lower()
        platform = platform.lower()
        
        # Validation
        if not owner or not owner.startswith("0x") or len(owner) != 42:
            return {"success": False, "error": "Invalid owner address"}
        
        if platform not in ["telegram", "discord"]:
            return {"success": False, "error": "Platform must be 'telegram' or 'discord'"}
        
        # Get GateService
        gate_service = get_gate_service()
        if not gate_service:
            return {"success": False, "error": "Gate Service not initialized"}
        
        # Get status
        status = await gate_service.get_gate_status(owner, platform)
        
        return {
            "success": True,
            "owner": owner,
            "platform": platform,
            **status
        }
        
    except Exception as e:
        log_activity("ERROR", "GATE_SERVICE", f"Status error: {str(e)}")
        return {"success": False, "error": str(e)}


@app.post("/api/gate/create-invite")
async def create_gate_invite(req: Request):
    """
    🔗 Create a one-time invite link using dynamic Gate Service
    
    This is the NEW unified endpoint that uses the GateService layer.
    Automatically falls back to static links if no bot is configured.
    
    Request:
        {
            "owner": "0x...",
            "platform": "telegram" | "discord",
            "user_address": "0x...",
            "expire_seconds": 300 (optional, default 5 min)
        }
    
    Response:
        {
            "success": true,
            "invite_link": "https://t.me/+...",
            "method": "bot_one_time" | "static_fallback" | "default_bot",
            "is_one_time": true,
            "expires_in": 300
        }
    
    Methods:
        - bot_one_time: Owner's bot created a true one-time link (BEST)
        - static_fallback: Using owner's static link (less secure)
        - default_bot: Using AEra's default bot (fallback)
        - no_config: No gate configured for this owner
    """
    if not GATE_SERVICE_AVAILABLE:
        return {"success": False, "error": "Gate Service not available"}
    
    try:
        data = await req.json()
        owner = data.get("owner", "").lower()
        platform = data.get("platform", "telegram").lower()
        user_address = data.get("user_address", "").lower()
        expire_seconds = data.get("expire_seconds", 300)
        
        # Validation
        if not owner or not owner.startswith("0x") or len(owner) != 42:
            return {"success": False, "error": "Invalid owner address"}
        
        if not user_address or not user_address.startswith("0x") or len(user_address) != 42:
            return {"success": False, "error": "Invalid user address"}
        
        if platform not in ["telegram", "discord"]:
            return {"success": False, "error": "Platform must be 'telegram' or 'discord'"}
        
        # Get GateService
        gate_service = get_gate_service()
        if not gate_service:
            return {"success": False, "error": "Gate Service not initialized"}
        
        # Create invite
        success, invite_link, method = await gate_service.create_one_time_invite(
            owner_wallet=owner,
            platform=platform,
            user_address=user_address,
            expire_seconds=expire_seconds
        )
        
        if not success:
            return {
                "success": False,
                "error": "Could not create invite link",
                "method": method
            }
        
        # Determine if truly one-time
        is_one_time = method in ["bot_one_time", "default_bot"]
        
        log_activity("INFO", "GATE_SERVICE", f"✓ Invite created ({method})", 
                    owner=owner[:10], 
                    user=user_address[:10],
                    platform=platform)
        
        return {
            "success": True,
            "invite_link": invite_link,
            "method": method,
            "is_one_time": is_one_time,
            "expires_in": expire_seconds if is_one_time else None,
            "security_note": "This link expires after one use" if is_one_time else "This is a static link"
        }
        
    except Exception as e:
        log_activity("ERROR", "GATE_SERVICE", f"Create invite error: {str(e)}")
        return {"success": False, "error": str(e)}


@app.get("/api/gate/list/{owner}")
async def list_owner_gates(owner: str):
    """
    📋 List all gate configurations for an owner
    
    MULTI-GATE SUPPORT: Returns ALL configured gates for the owner.
    One owner can have multiple Telegram AND Discord groups!
    
    Path Parameters:
        owner: Wallet address of the gate owner
    
    Response:
        {
            "success": true,
            "owner": "0x...",
            "gates": [
                {
                    "platform": "telegram",
                    "group_name": "VIP Group",
                    "group_id": "-1001234567890",
                    "security_level": "high",
                    "bot_verified": true,
                    "has_static_link": true,
                    "min_score": 100,
                    "created_at": "2025-01-05 12:00:00",
                    "last_updated": "2025-01-05 14:30:00"
                },
                {
                    "platform": "telegram",
                    "group_name": "Premium Group",
                    "group_id": "-1009876543210",
                    "security_level": "low",
                    "bot_verified": false,
                    "has_static_link": true,
                    "min_score": 150,
                    "created_at": "2025-01-06 10:00:00",
                    "last_updated": "2025-01-06 10:00:00"
                }
            ],
            "total": 2
        }
    """
    try:
        owner = owner.lower()
        
        # Validation
        if not owner or not owner.startswith("0x") or len(owner) != 42:
            return {"success": False, "error": "Invalid owner address"}
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get all gate configs for this owner (MULTI-GATE: multiple per platform!)
        cursor.execute("""
            SELECT platform, group_name, group_id, channel_id,
                   bot_verified, static_invite_link,
                   created_at, updated_at, min_score,
                   CASE 
                       WHEN bot_token_encrypted IS NOT NULL AND bot_verified = 1 THEN 'high'
                       WHEN static_invite_link IS NOT NULL THEN 'low'
                       ELSE 'none'
                   END as security_level
            FROM owner_gate_configs 
            WHERE owner_wallet = ? AND is_active = 1
            ORDER BY platform, group_name
        """, (owner,))
        
        rows = cursor.fetchall()
        conn.close()
        
        gates = []
        for row in rows:
            gate = {
                "platform": row[0],
                "group_name": row[1] or f"Unnamed {row[0].title()} Group",
                "group_id": row[2],
                "channel_id": row[3],
                "bot_verified": bool(row[4]),
                "has_static_link": bool(row[5]),
                "invite_link": row[5] if row[5] else None,  # Return the actual link!
                "created_at": row[6],
                "last_updated": row[7],
                "min_score": row[8] or 50,
                "security_level": row[9]
            }
            gates.append(gate)
        
        log_activity("INFO", "GATE_SERVICE", f"Listed {len(gates)} gates for owner", owner=owner[:10])
        
        return {
            "success": True,
            "owner": owner,
            "gates": gates,
            "total": len(gates)
        }
        
    except Exception as e:
        log_activity("ERROR", "GATE_SERVICE", f"List gates error: {str(e)}")
        return {"success": False, "error": str(e)}


@app.delete("/api/gate/delete/{owner}/{platform}/{group_id:path}")
async def delete_owner_gate(owner: str, platform: str, group_id: str):
    """
    🗑️ Delete a gate configuration
    
    MULTI-GATE SUPPORT: Requires group_id to identify the specific gate.
    Removes a specific gate configuration for an owner.
    This action is irreversible - bot token will be deleted.
    
    Path Parameters:
        owner: Wallet address of the gate owner
        platform: 'telegram' or 'discord'
        group_id: The group/channel ID to delete (e.g., "-1001234567890")
    
    Response:
        {
            "success": true,
            "message": "Gate configuration deleted successfully",
            "owner": "0x...",
            "platform": "telegram",
            "group_id": "-1001234567890"
        }
    """
    try:
        owner = owner.lower()
        platform = platform.lower()
        group_id = group_id.strip()
        
        # Validation
        if not owner or not owner.startswith("0x") or len(owner) != 42:
            return {"success": False, "error": "Invalid owner address"}
        
        if platform not in ["telegram", "discord"]:
            return {"success": False, "error": "Platform must be 'telegram' or 'discord'"}
        
        if not group_id:
            return {"success": False, "error": "group_id is required"}
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if gate exists (with specific group_id)
        cursor.execute("""
            SELECT id, group_name FROM owner_gate_configs 
            WHERE owner_wallet = ? AND platform = ? AND group_id = ? AND is_active = 1
        """, (owner, platform, group_id))
        
        row = cursor.fetchone()
        if not row:
            conn.close()
            return {"success": False, "error": f"No active {platform} gate with group_id {group_id} found for this owner"}
        
        gate_id = row[0]
        group_name = row[1] or f"{platform.title()} Group"
        
        # Soft delete - mark as inactive and clear sensitive data (for Audit Trail)
        cursor.execute("""
            UPDATE owner_gate_configs 
            SET is_active = 0, 
                bot_token_encrypted = NULL,
                updated_at = datetime('now')
            WHERE id = ?
        """, (gate_id,))
        
        conn.commit()
        conn.close()
        
        log_activity("INFO", "GATE_SERVICE", f"✓ Gate deleted: {platform}", 
                    owner=owner[:10], 
                    group=group_name[:20],
                    group_id=group_id[:15])
        
        return {
            "success": True,
            "message": f"Gate configuration for {platform.title()} deleted successfully",
            "owner": owner,
            "platform": platform,
            "group_id": group_id,
            "deleted_group": group_name
        }
        
    except Exception as e:
        log_activity("ERROR", "GATE_SERVICE", f"Delete gate error: {str(e)}")
        return {"success": False, "error": str(e)}


# ============================================================================
# ===== GATE HEALTH CHECK SYSTEM =====
# ============================================================================

async def gate_health_check_loop():
    """
    Background task that periodically checks health of configured gates.
    Runs every 30 minutes to verify bot tokens are still valid.
    """
    while True:
        try:
            # Wait 30 minutes between checks (first check after 5 min delay)
            await asyncio.sleep(300)  # 5 min initial delay
            
            if not GATE_SERVICE_AVAILABLE:
                continue
            
            gate_service = get_gate_service()
            if not gate_service:
                continue
            
            logger.info("🔍 Running Gate Health Check...")
            
            # Get all active gate configs
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT owner_wallet, platform, bot_verified, last_health_check
                FROM owner_gate_configs 
                WHERE is_active = 1 AND bot_token_encrypted IS NOT NULL
            """)
            gates = cursor.fetchall()
            conn.close()
            
            checked = 0
            healthy = 0
            
            for gate in gates:
                owner = gate['owner_wallet']
                platform = gate['platform']
                
                try:
                    result = await gate_service.verify_bot(owner, platform)
                    
                    # Update health status
                    conn = get_db_connection()
                    cursor = conn.cursor()
                    
                    if result.get("success"):
                        cursor.execute("""
                            UPDATE owner_gate_configs 
                            SET last_health_check = ?, health_status = 'healthy'
                            WHERE owner_wallet = ? AND platform = ?
                        """, (datetime.now(timezone.utc).isoformat(), owner, platform))
                        healthy += 1
                    else:
                        cursor.execute("""
                            UPDATE owner_gate_configs 
                            SET last_health_check = ?, health_status = ?
                            WHERE owner_wallet = ? AND platform = ?
                        """, (datetime.now(timezone.utc).isoformat(), f"error: {result.get('error', 'unknown')[:100]}", owner, platform))
                    
                    conn.commit()
                    conn.close()
                    checked += 1
                    
                except Exception as e:
                    logger.warning(f"Health check failed for {owner[:10]}...: {e}")
                
                # Small delay between checks to avoid rate limits
                await asyncio.sleep(1)
            
            logger.info(f"✅ Gate Health Check complete: {healthy}/{checked} gates healthy")
            
            # Wait 30 minutes before next check
            await asyncio.sleep(1500)  # 25 more minutes (total 30 min cycle)
            
        except Exception as e:
            logger.error(f"Gate Health Check error: {e}")
            await asyncio.sleep(300)  # Wait 5 min on error


@app.get("/api/gate/health")
async def get_all_gates_health():
    """
    🔍 Get health status of all configured gates (admin endpoint)
    
    Returns summary of all gate configurations and their health status.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT owner_wallet, platform, bot_username, bot_verified, 
                   last_health_check, health_status, group_name, created_at
            FROM owner_gate_configs 
            WHERE is_active = 1
            ORDER BY last_health_check DESC
        """)
        
        gates = []
        for row in cursor.fetchall():
            gates.append({
                "owner": row['owner_wallet'][:10] + "...",
                "platform": row['platform'],
                "bot_username": row['bot_username'],
                "verified": bool(row['bot_verified']),
                "last_check": row['last_health_check'],
                "health": row['health_status'] or "not_checked",
                "group_name": row['group_name']
            })
        
        conn.close()
        
        healthy_count = sum(1 for g in gates if g['health'] == 'healthy')
        
        return {
            "success": True,
            "total_gates": len(gates),
            "healthy_gates": healthy_count,
            "gates": gates
        }
        
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.post("/api/check-follower-status")
async def check_follower_status(data: dict):
    """
    🔒 Check if a wallet is already registered as a follower for a specific owner+platform
    
    Request:
        {
            "address": "0x...",
            "owner": "0x...",
            "source": "direct"
        }
    
    Response:
        {
            "is_follower": true/false,
            "confirmed": true/false,
            "platform": "direct"
        }
    """
    try:
        address = data.get("address", "").lower()
        owner = data.get("owner", "").lower()
        source = data.get("source", "direct").lower()
        
        if not address or not owner:
            return {"error": "Address and owner required", "is_follower": False}
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            """SELECT id, follow_confirmed FROM followers 
               WHERE owner_wallet = ? AND follower_address = ? AND source_platform = ?""",
            (owner, address, source)
        )
        follower = cursor.fetchone()
        conn.close()
        
        if follower:
            return {
                "is_follower": True,
                "confirmed": follower['follow_confirmed'] == 1,
                "platform": source
            }
        
        return {
            "is_follower": False,
            "confirmed": False,
            "platform": source
        }
        
    except Exception as e:
        log_activity("ERROR", "API", f"Follower status check error: {str(e)}")
        return {"error": str(e), "is_follower": False}

@app.post("/api/verify")
async def verify(req: Request):
    """
    Verifiziert eine Wallet-Adresse mit MetaMask-Signatur (PROOF OF HUMAN)
    
    Request:
        {
            "address": "0x...",
            "nonce": "...",
            "signature": "0x..."
        }
    
    Response:
        {
            "is_human": true,
            "address": "0x...",
            "resonance_score": 50-100,
            "message": "..."
        }
    """
    try:
        data = await req.json()
        address = data.get("address", "").lower()
        nonce = data.get("nonce", "")
        signature = data.get("signature", "")
        message_from_frontend = data.get("message", "")  # NEW: SIWE message from frontend
        token_duration_minutes = data.get("token_duration_minutes", None)  # Token-Gültigkeitsdauer in Minuten
        owner_wallet = data.get("owner", "").lower()  # NEW: Owner for follower tracking
        display_name = data.get("display_name", "").strip()  # NEW: User-provided display name
        
        # ===== EXTRACT REFERRER (DSGVO: Nur Plattform-Name, KEINE IPs/User-Agents!) =====
        referrer = req.headers.get("referer", req.headers.get("referrer", ""))
        
        # PRIORITÄT: POST-Body "source" > URL-Parameter "source" > Referrer-Header
        source_from_body = data.get("source", "").strip().lower()
        url_source = req.query_params.get("source", "").strip().lower()
        referrer_source = source_from_body if source_from_body else (url_source if url_source else extract_referrer_source(referrer))
        
        log_activity("INFO", "AUTH", "Verify request received", 
                    address=address[:10], 
                    has_signature=bool(signature),
                    referrer_source=referrer_source,
                    owner_wallet=owner_wallet[:10] if owner_wallet else "none")
        
        # ===== VALIDATE OWNER WALLET IF PROVIDED =====
        if owner_wallet and (not owner_wallet.startswith("0x") or len(owner_wallet) != 42):
            log_activity("ERROR", "AUTH", "Invalid owner wallet format", address=address[:10])
            return {"error": "Invalid owner wallet format", "is_human": False}
        
        # ===== KRITISCH: SIGNATURE VALIDIERUNG =====
        if not signature:
            log_activity("ERROR", "AUTH", "No signature provided - REJECTING", address=address[:10])
            return {"error": "No signature provided - MetaMask sign required!", "is_human": False}
        
        if not nonce:
            log_activity("ERROR", "AUTH", "No nonce provided", address=address[:10])
            return {"error": "No nonce", "is_human": False}
        
        # Validiere Adresse
        if not address or not address.startswith("0x") or len(address) != 42:
            log_activity("ERROR", "AUTH", "Invalid address format", address=address[:10])
            return {"error": "Invalid address format", "is_human": False}
        
        # ===== VALIDIERE SIGNATURE MIT web3.py (EOA + Smart Contract Wallets) =====
        try:
            from eth_account.messages import encode_defunct, defunct_hash_message
            from eth_account import Account
            
            # 🔐 Support both old format AND SIWE (EIP-4361) format
            if message_from_frontend:
                # SIWE format: Use message from frontend
                message_text = message_from_frontend
                log_activity("INFO", "AUTH", "Using SIWE message from frontend", address=address[:10])
            else:
                # Old format: Build message with nonce
                message_text = f"Signiere diese Nachricht um dich bei AEra anzumelden:\nNonce: {nonce}"
            
            # Detect Smart Contract Wallet signature (EIP-6492)
            # These signatures are much longer than 65 bytes (130 hex chars + 0x)
            is_smart_wallet_sig = len(signature) > 200 if signature else False
            log_activity("INFO", "AUTH", f"Signature length: {len(signature)}, Smart Contract Wallet: {is_smart_wallet_sig}", address=address[:10])
            
            signature_valid = False
            
            # ========================================
            # SMART CONTRACT WALLET (EIP-1271) VERIFICATION
            # Base Wallet, Coinbase Smart Wallet, Safe, etc.
            # ========================================
            if is_smart_wallet_sig:
                log_activity("INFO", "AUTH", "Attempting EIP-1271 Smart Contract Wallet verification...", address=address[:10])
                try:
                    from web3 import Web3
                    
                    # Connect to BASE mainnet via Alchemy (faster)
                    alchemy_url = os.getenv("BASE_ALCHEMY_API_URL") or os.getenv("BASE_RPC_URL", "https://mainnet.base.org")
                    w3 = Web3(Web3.HTTPProvider(alchemy_url))
                    
                    # EIP-1271 ABI - just the isValidSignature function
                    EIP1271_ABI = [
                        {
                            "inputs": [
                                {"name": "_hash", "type": "bytes32"},
                                {"name": "_signature", "type": "bytes"}
                            ],
                            "name": "isValidSignature",
                            "outputs": [{"name": "", "type": "bytes4"}],
                            "stateMutability": "view",
                            "type": "function"
                        }
                    ]
                    
                    # Hash the message (EIP-191 personal sign format)
                    message_hash = defunct_hash_message(text=message_text)
                    log_activity("INFO", "AUTH", f"Message hash for EIP-1271: {message_hash.hex()[:20]}...", address=address[:10])
                    
                    # Create contract instance
                    wallet_contract = w3.eth.contract(
                        address=Web3.to_checksum_address(address),
                        abi=EIP1271_ABI
                    )
                    
                    # Convert signature to bytes
                    sig_bytes = bytes.fromhex(signature[2:]) if signature.startswith('0x') else bytes.fromhex(signature)
                    
                    # Call isValidSignature on the smart contract wallet
                    result = wallet_contract.functions.isValidSignature(
                        message_hash,
                        sig_bytes
                    ).call()
                    
                    # EIP-1271 magic value for valid signature
                    MAGIC_VALUE = bytes.fromhex('1626ba7e')
                    
                    if result == MAGIC_VALUE:
                        signature_valid = True
                        log_activity("INFO", "AUTH", "✅ EIP-1271 Smart Contract Wallet verification SUCCESS!", address=address[:10])
                    else:
                        log_activity("INFO", "AUTH", f"EIP-1271 returned: {result.hex()} (expected 1626ba7e)", address=address[:10])
                        
                except Exception as eip1271_error:
                    log_activity("INFO", "AUTH", f"EIP-1271 verification failed: {str(eip1271_error)}", address=address[:10])
            
            # ========================================
            # STANDARD EOA SIGNATURE VERIFICATION
            # MetaMask, Rainbow, Trust, etc.
            # ========================================
            if not signature_valid:
                try:
                    message = encode_defunct(text=message_text)
                    recovered_address = Account.recover_message(message, signature=signature)
                    
                    if recovered_address.lower() == address:
                        signature_valid = True
                        log_activity("INFO", "AUTH", "✅ EOA signature verification SUCCESS", address=address[:10])
                    else:
                        log_activity("ERROR", "AUTH", "Signature verification FAILED", address=address[:10], recovered=recovered_address[:10])
                except Exception as eoa_error:
                    log_activity("INFO", "AUTH", f"EOA verification failed: {str(eoa_error)}", address=address[:10])
            
            if not signature_valid:
                return {"error": "Signature verification failed", "is_human": False}
            
            # 🔐 SIWE: Also verify nonce is in the message (anti-replay)
            if message_from_frontend and nonce not in message_from_frontend:
                log_activity("ERROR", "AUTH", "SIWE nonce mismatch", address=address[:10])
                return {"error": "Nonce mismatch in SIWE message", "is_human": False}
            
            log_activity("INFO", "AUTH", "✓✓✓ Signature VERIFIED", address=address[:10])
            
        except ImportError:
            log_activity("WARNING", "AUTH", "eth_account not available - skipping signature check")
        except Exception as e:
            log_activity("ERROR", "AUTH", f"Signature verification error: {str(e)}", address=address[:10])
            return {"error": f"Signature error: {str(e)}", "is_human": False}
        
        # ===== BENUTZER-LOGIN (nach Signature-Verifizierung) =====
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 🔒 SECURITY: Check if follower already registered for this owner+platform
        if owner_wallet:
            # Prevent self-follow
            if owner_wallet.lower() == address.lower():
                conn.close()
                log_activity("WARNING", "FOLLOWER", "❌ Self-follow blocked", 
                            address=address[:10], 
                            source=referrer_source)
                return {
                    "error": "You cannot follow yourself!",
                    "is_human": False
                }
            
            # Check if already registered as follower for this owner+platform
            # NOTE: For gate platforms (telegram/discord), we DON'T block here
            # because follower registration happens AFTER successful gate access
            if referrer_source not in ["telegram", "discord"]:
                cursor.execute(
                    """SELECT id, follow_confirmed FROM followers 
                       WHERE owner_wallet = ? AND follower_address = ? AND source_platform = ?""",
                    (owner_wallet, address, referrer_source)
                )
                existing_follower = cursor.fetchone()
                
                if existing_follower and existing_follower['follow_confirmed'] == 1:
                    conn.close()
                    log_activity("WARNING", "FOLLOWER", "❌ Already registered as follower", 
                                owner=owner_wallet[:10],
                                follower=address[:10], 
                                source=referrer_source)
                    return {
                        "error": f"You are already registered as a follower on {referrer_source}!",
                        "is_human": False,
                        "already_follower": True
                    }
        
        # Benutzer suchen
        cursor.execute("SELECT * FROM users WHERE address=?", (address,))
        user = cursor.fetchone()
        
        current_timestamp = int(time.time())
        current_iso = datetime.now(timezone.utc).isoformat()
        
        if user:
            # Benutzer existiert bereits
            old_score = user['score']
            # sqlite3.Row unterstützt kein .get() - verwende try/except
            try:
                pending_bonus = user['pending_bonus'] if user['pending_bonus'] is not None else 0
            except (KeyError, IndexError):
                pending_bonus = 0
            
            # 🐛 FIX: Nur als "neuer Login" zählen wenn > 60 Sekunden seit letztem Login
            last_login = user['last_login']
            # 🐛 FIX: Handle NULL last_login (legacy users or incomplete registrations)
            if last_login is None:
                last_login = 0
                is_new_login_session = True  # First real login
            else:
                time_since_last_login = current_timestamp - last_login
                is_new_login_session = time_since_last_login > 60  # 60 seconds threshold
            
            # HYBRID-SYSTEM: Score erhöhen + pending_bonus aktivieren
            if is_new_login_session:
                # Echter neuer Login: Score + pending_bonus aktivieren
                # TIERED SCORING: Gestaffelte Punkte basierend auf aktuellem Score
                # Login = 1 Interaktion, pending_bonus = Anzahl Follower-Interaktionen
                total_interactions = 1 + int(pending_bonus)  # Login + pending follower bonuses
                new_score = calculate_new_score(user['score'], total_interactions)
                login_count = user['login_count'] + 1
            else:
                # Wiederholter Call innerhalb 60 Sekunden: Keine Änderung
                new_score = user['score']
                login_count = user['login_count']
            
            cursor.execute(
                """UPDATE users 
                   SET last_login=?, score=?, login_count=?, last_referrer=?, pending_bonus=?
                   WHERE address=?""",
                (current_timestamp, new_score, login_count, referrer_source, 
                 0 if is_new_login_session else pending_bonus, address)
            )
            
            if pending_bonus > 0:
                log_activity("INFO", "BONUS", "✓ Follow-Bonus activated",
                            address=address[:10],
                            bonus=f"+{pending_bonus}",
                            new_score=new_score)
            
            cursor.execute(
                """INSERT INTO events 
                   (address, event_type, score_before, score_after, timestamp, created_at, referrer)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (address, "login", old_score, new_score, current_timestamp, current_iso, referrer_source)
            )
            
            # BLOCKCHAIN: Check if score sync needed (every 10 points)
            await sync_score_after_update(address, new_score, conn)
            
            # 🐛 FIX: Handle NULL first_seen (legacy users)
            first_seen = user['first_seen'] if user['first_seen'] is not None else current_timestamp
            if is_new_login_session:
                message = f"Welcome back! Score increased to {new_score}/100"
                log_activity("INFO", "AUTH", "Existing user login", 
                            address=address[:10], 
                            old_score=old_score, 
                            new_score=new_score, 
                            login_count=login_count,
                            referrer=referrer_source)
            else:
                message = f"Session refresh (no score change)"
                log_activity("INFO", "AUTH", "Session refresh (duplicate call within 60s)", 
                            address=address[:10], 
                            score=new_score, 
                            time_since_last=f"{time_since_last_login}s",
                            referrer=referrer_source)
            
            # NEW: Auch bei existierenden User-Logins: Follower-Eintrag erstellen wenn owner_wallet vorhanden
            # ABER NICHT für Gate-Plattformen (telegram/discord) - diese werden erst nach Gate-Zugang registriert!
            if owner_wallet:
                # SECURITY: Prevent self-follow
                if owner_wallet.lower() == address.lower():
                    log_activity("WARNING", "FOLLOWER", "❌ Self-follow prevented", 
                                address=address[:10], 
                                source=referrer_source)
                # GATE PLATFORMS: Skip follower registration here - will be done after successful gate access
                elif referrer_source in ["telegram", "discord"]:
                    log_activity("INFO", "FOLLOWER", "⏳ Gate platform detected - follower registration deferred to gate access", 
                                owner=owner_wallet[:10], 
                                follower=address[:10], 
                                source=referrer_source)
                else:
                    try:
                        # Prüfe ob dieser Follower auf dieser Plattform bereits existiert
                        cursor.execute(
                            """SELECT id FROM followers 
                               WHERE owner_wallet = ? AND follower_address = ? AND source_platform = ?""",
                            (owner_wallet, address, referrer_source)
                        )
                        existing = cursor.fetchone()
                        
                        if existing:
                            # Update: Nur Score und Timestamp aktualisieren
                            cursor.execute(
                                """UPDATE followers 
                                   SET follower_score = ?, verified_at = ?
                                   WHERE owner_wallet = ? AND follower_address = ? AND source_platform = ?""",
                                (new_score, current_iso, owner_wallet, address, referrer_source)
                            )
                            log_activity("INFO", "FOLLOWER", "✓ Follower score updated", 
                                        owner=owner_wallet[:10], 
                                        follower=address[:10], 
                                        source=referrer_source)
                        else:
                            # Insert: Neuer Follower-Eintrag für diese Plattform
                            # NOTE: follow_confirmed = 0 initially! Will be set to 1 after successful gate access
                            cursor.execute(
                                """INSERT INTO followers 
                                   (owner_wallet, follower_address, follower_score, follower_display_name, verified_at, source_platform, verified, follow_confirmed)
                                   VALUES (?, ?, ?, ?, ?, ?, ?, 0)""",
                                (owner_wallet, address, new_score, display_name or None, current_iso, referrer_source, 1)
                            )
                            log_activity("INFO", "FOLLOWER", "✓ New follower registered (pending gate access)", 
                                        owner=owner_wallet[:10], 
                                        follower=address[:10], 
                                        source=referrer_source)
                            
                            # HYBRID-SYSTEM: Owner bekommt Follow-Bonus (pending)
                            try:
                                cursor.execute(
                                    "UPDATE users SET pending_bonus = pending_bonus + 1 WHERE address = ?",
                                    (owner_wallet,)
                                )
                                log_activity("INFO", "BONUS", "✓ Follow-Bonus added (pending)",
                                            owner=owner_wallet[:10],
                                            bonus="+1",
                                            activation="next_login")
                            except Exception as bonus_err:
                                log_activity("WARNING", "BONUS", f"Could not add pending bonus: {str(bonus_err)}")
                            
                            # ===== BLOCKCHAIN: RECORD FOLLOW INTERACTION =====
                            try:
                                dashboard_link = f"{PUBLIC_URL}/dashboard?owner={owner_wallet}"
                                success, result = await web3_service.record_interaction(
                                    initiator=address,          # Follower initiates the follow
                                    responder=owner_wallet,     # Owner receives the follow
                                    interaction_type=0,         # 0 = FOLLOW
                                    metadata=dashboard_link     # Dashboard link as metadata
                                )
                                
                                if success:
                                    log_activity("INFO", "BLOCKCHAIN", "✓ Follow interaction recorded on-chain",
                                                initiator=address[:10],
                                                responder=owner_wallet[:10],
                                                type="FOLLOW",
                                                tx_hash=str(result)[:20] if result else "unknown")
                                else:
                                    log_activity("WARNING", "BLOCKCHAIN", f"Follow interaction recording failed: {result}",
                                                initiator=address[:10],
                                                responder=owner_wallet[:10])
                            except Exception as blockchain_err:
                                log_activity("WARNING", "BLOCKCHAIN", f"Follow interaction error (non-critical): {str(blockchain_err)}",
                                            initiator=address[:10],
                                            responder=owner_wallet[:10])
                    except Exception as e:
                        log_activity("WARNING", "FOLLOWER", f"Could not create/update follower entry: {str(e)}")
            
        else:
            # Neuer Benutzer
            initial_score = 50
            cursor.execute(
                """INSERT INTO users 
                   (address, first_seen, last_login, score, login_count, created_at, first_referrer, last_referrer, owner_wallet, is_verified_follower, display_name)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (address, current_timestamp, current_timestamp, initial_score, 1, current_iso, referrer_source, referrer_source, owner_wallet or None, 1 if owner_wallet else 0, display_name or None)
            )
            
            cursor.execute(
                """INSERT INTO events 
                   (address, event_type, score_before, score_after, timestamp, created_at, referrer, owner_wallet)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (address, "signup", 0, initial_score, current_timestamp, current_iso, referrer_source, owner_wallet or None)
            )
            
            # NEW: Wenn Owner vorhanden, registriere als Follower
            # ABER NICHT für Gate-Plattformen (telegram/discord) - diese werden erst nach Gate-Zugang registriert!
            if owner_wallet:
                # SECURITY: Prevent self-follow
                if owner_wallet.lower() == address.lower():
                    log_activity("WARNING", "FOLLOWER", "❌ Self-follow prevented (new user)", 
                                address=address[:10], 
                                source=referrer_source)
                # GATE PLATFORMS: Skip follower registration here - will be done after successful gate access
                elif referrer_source in ["telegram", "discord"]:
                    log_activity("INFO", "FOLLOWER", "⏳ Gate platform detected (new user) - follower registration deferred to gate access", 
                                owner=owner_wallet[:10], 
                                follower=address[:10], 
                                source=referrer_source)
                else:
                    try:
                        # NOTE: follow_confirmed = 0 initially! Will be set to 1 after successful gate access
                        cursor.execute(
                            """INSERT INTO followers 
                               (owner_wallet, follower_address, follower_score, follower_display_name, verified_at, source_platform, verified, follow_confirmed)
                               VALUES (?, ?, ?, ?, ?, ?, ?, 0)""",
                            (owner_wallet, address, initial_score, display_name or None, current_iso, referrer_source, 1)
                        )
                        log_activity("INFO", "FOLLOWER", "✓ Follower registered (pending gate access)", 
                                    owner=owner_wallet[:10], 
                                    follower=address[:10], 
                                    source=referrer_source)
                        
                        # HYBRID-SYSTEM: Owner bekommt Follow-Bonus (pending)
                        try:
                            cursor.execute(
                                "UPDATE users SET pending_bonus = pending_bonus + 1 WHERE address = ?",
                                (owner_wallet,)
                            )
                            log_activity("INFO", "BONUS", "✓ Follow-Bonus added (pending)",
                                        owner=owner_wallet[:10],
                                        bonus="+1",
                                        activation="next_login")
                        except Exception as bonus_err:
                            log_activity("WARNING", "BONUS", f"Could not add pending bonus: {str(bonus_err)}")
                        
                        # ===== BLOCKCHAIN: RECORD FOLLOW INTERACTION =====
                        try:
                            dashboard_link = f"{PUBLIC_URL}/dashboard?owner={owner_wallet}"
                            success, result = await web3_service.record_interaction(
                                initiator=address,          # Follower initiates the follow
                                responder=owner_wallet,     # Owner receives the follow
                                interaction_type=0,         # 0 = FOLLOW
                                metadata=dashboard_link     # Dashboard link as metadata
                            )
                            
                            if success:
                                log_activity("INFO", "BLOCKCHAIN", "✓ Follow interaction recorded on-chain (new user)",
                                            initiator=address[:10],
                                            responder=owner_wallet[:10],
                                            type="FOLLOW",
                                            tx_hash=str(result)[:20] if result else "unknown")
                            else:
                                log_activity("WARNING", "BLOCKCHAIN", f"Follow interaction recording failed: {result}",
                                            initiator=address[:10],
                                            responder=owner_wallet[:10])
                        except Exception as blockchain_err:
                            log_activity("WARNING", "BLOCKCHAIN", f"Follow interaction error (non-critical): {str(blockchain_err)}",
                                        initiator=address[:10],
                                        responder=owner_wallet[:10])
                    except Exception as e:
                        log_activity("WARNING", "FOLLOWER", f"Could not register follower: {str(e)}")
            
            first_seen = current_timestamp
            new_score = initial_score
            message = f"Welcome! Your initial Resonance Score is {initial_score}/100"
            if owner_wallet:
                message += f" | Registered as follower"
            log_activity("INFO", "AUTH", "New user registered", 
                        address=address[:10], 
                        initial_score=initial_score,
                        referrer=referrer_source,
                        owner=owner_wallet[:10] if owner_wallet else "none")
            
            # BLOCKCHAIN: Check if score sync needed (initial score 50)
            await sync_score_after_update(address, new_score, conn)
            
            # DELAY: Wait 3 seconds to prevent nonce conflict between score sync and NFT mint
            await asyncio.sleep(3)
        
        # ===== BLOCKCHAIN: IDENTITY NFT INTEGRATION =====
        try:
            # Check current identity status from DB
            cursor.execute("SELECT identity_status, identity_nft_token_id FROM users WHERE address=?", (address,))
            identity_result = cursor.fetchone()
            db_identity_status = identity_result[0] if identity_result else 'pending'
            db_token_id = identity_result[1] if identity_result else None
            
            # Prüfe ob User bereits Identity NFT hat
            has_identity = await web3_service.has_identity_nft(address)
            
            # RETRY LOGIC: If status is 'failed' or 'pending' (old users), try minting again
            if not has_identity and db_identity_status in ['failed', 'pending']:
                log_activity("INFO", "BLOCKCHAIN", "🎨 Starting Identity NFT mint", address=address[:10])
                success, result = await web3_service.mint_identity_nft(address)
                
                if success:
                    # Extract tx_hash from result dict
                    tx_hash = result.get("tx_hash") if isinstance(result, dict) else result
                    # Set status to 'minting' with tx_hash - background task will confirm later
                    cursor.execute(
                        """UPDATE users 
                           SET identity_status='minting', identity_mint_tx_hash=?, identity_minted_at=?
                           WHERE address=?""",
                        (tx_hash, current_iso, address)
                    )
                    
                    log_activity("INFO", "BLOCKCHAIN", "📤 Identity NFT mint transaction sent", 
                                address=address[:10], 
                                tx_hash=tx_hash[:16] + "..." if tx_hash else "N/A")
                    message += f" | Identity NFT minting (TX: {tx_hash[:10] if tx_hash else 'N/A'}...)"
                else:
                    error_msg = result
                    log_activity("WARNING", "BLOCKCHAIN", f"NFT minting failed: {error_msg}", address=address[:10])
                    # Nicht-kritischer Fehler - fahre fort
                    cursor.execute(
                        """UPDATE users 
                           SET identity_status='failed'
                           WHERE address=?""",
                        (address,)
                    )
            else:
                # User hat bereits NFT - hole Token ID
                token_id = await web3_service.get_identity_token_id(address)
                if token_id is not None:
                    # Update DB falls noch nicht gespeichert
                    cursor.execute(
                        """UPDATE users 
                           SET identity_nft_token_id=?, identity_status='active'
                           WHERE address=? AND identity_nft_token_id IS NULL""",
                        (token_id, address)
                    )
                    log_activity("INFO", "BLOCKCHAIN", "✓ Identity NFT verified", 
                                address=address[:10], 
                                token_id=token_id)
        
        except Exception as e:
            log_activity("WARNING", "BLOCKCHAIN", f"Identity NFT error (non-critical): {str(e)}", address=address[:10])
            # Nicht-kritischer Fehler - System funktioniert weiter ohne Blockchain
        
        conn.commit()
        conn.close()
        
        # Trigger Airdrop NACH Commit
        if not user:
            airdrop_result = await trigger_airdrop(address)
            message += f" | {airdrop_result['message']}"
        
        # Generiere Token
        token = generate_token(address, token_duration_minutes)
        
        log_activity("INFO", "AUTH", "✓ Verify successful (SIGNATURE VERIFIED)", address=address[:10], score=new_score)
        
        return {
            "is_human": True,
            "address": address,
            "resonance_score": new_score,
            "first_seen": first_seen,
            "last_login": current_timestamp,
            "login_count": user['login_count'] + 1 if user else 1,
            "message": message,
            "token": token
        }
        
    except Exception as e:
        log_activity("ERROR", "AUTH", f"Verification error: {str(e)}")
        return {
            "error": str(e),
            "is_human": False
        }

@app.get("/api/user/{address}")
async def get_user(address: str):
    """
    Ruft Benutzerdaten ab (ohne Sicherheitscheck - nur Demo!)
    """
    try:
        address = address.lower()
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM users WHERE address=?", (address,))
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            return {"error": "User not found"}
        
        return {
            "address": user['address'],
            "resonance_score": user['score'],
            "first_seen": user['first_seen'],
            "last_login": user['last_login'],
            "login_count": user['login_count'],
            "created_at": user['created_at']
        }
        
    except Exception as e:
        return {"error": str(e)}

@app.get("/api/stats")
async def get_stats():
    """
    Gibt Statistiken aus (öffentlich)
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) as total FROM users")
        total_users = cursor.fetchone()['total']
        
        cursor.execute("SELECT AVG(score) as avg_score FROM users")
        avg_score = cursor.fetchone()['avg_score']
        
        cursor.execute("SELECT COUNT(*) as total FROM events WHERE event_type='login'")
        total_logins = cursor.fetchone()['total']
        
        conn.close()
        
        return {
            "total_users": total_users,
            "average_score": round(avg_score, 2) if avg_score else 0,
            "total_logins": total_logins,
            "timestamp": int(time.time())
        }
        
    except Exception as e:
        return {"error": str(e)}

@app.get("/api/events/{address}")
async def get_user_events(address: str):
    """
    Ruft Login-Ereignisse eines Benutzers ab
    """
    try:
        address = address.lower()
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            """SELECT * FROM events 
               WHERE address=? 
               ORDER BY timestamp DESC 
               LIMIT 50""",
            (address,)
        )
        events = cursor.fetchall()
        conn.close()
        
        return {
            "address": address,
            "events": [dict(event) for event in events]
        }
        
    except Exception as e:
        return {"error": str(e)}

@app.get("/api/referrer-stats")
async def get_referrer_stats():
    """
    Gibt Statistiken über Referrer-Quellen zurück
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Neue User pro Referrer
        cursor.execute("""
            SELECT first_referrer, COUNT(*) as count
            FROM users
            WHERE first_referrer IS NOT NULL
            GROUP BY first_referrer
            ORDER BY count DESC
        """)
        new_users_by_referrer = cursor.fetchall()
        
        # Alle Events pro Referrer
        cursor.execute("""
            SELECT referrer, COUNT(*) as count
            FROM events
            WHERE referrer IS NOT NULL
            GROUP BY referrer
            ORDER BY count DESC
        """)
        events_by_referrer = cursor.fetchall()
        
        # Top Referrer letzte 24h
        yesterday = int(time.time()) - (24 * 3600)
        cursor.execute("""
            SELECT referrer, COUNT(*) as count
            FROM events
            WHERE referrer IS NOT NULL AND timestamp > ?
            GROUP BY referrer
            ORDER BY count DESC
            LIMIT 10
        """, (yesterday,))
        top_24h = cursor.fetchall()
        
        conn.close()
        
        return {
            "new_users_by_source": [dict(r) for r in new_users_by_referrer],
            "total_events_by_source": [dict(r) for r in events_by_referrer],
            "top_sources_24h": [dict(r) for r in top_24h],
            "timestamp": int(time.time())
        }
        
    except Exception as e:
        return {"error": str(e)}


# ===== GDPR / DSGVO ENDPOINTS =====

@app.get("/api/gdpr/data/{address}")
async def gdpr_get_data(address: str):
    """
    🔒 GDPR Art. 15 - Recht auf Datenauskunft
    
    Gibt alle gespeicherten Daten zu einer Wallet-Adresse zurück.
    
    Returns:
        {
            "address": "0x...",
            "personal_data": {
                "first_seen": "2025-12-06T...",
                "last_login": "2025-12-06T...",
                "score": 55,
                "login_count": 5,
                "display_name": "User123"
            },
            "events": [...],
            "followers": [...],
            "telegram_invites": [...],
            "data_export_url": "/api/gdpr/export/0x..."
        }
    """
    try:
        address = address.lower()
        
        if not address or not address.startswith("0x") or len(address) != 42:
            return {"error": "Invalid address format", "success": False}
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # User Data
        cursor.execute("SELECT * FROM users WHERE address=?", (address,))
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return {
                "success": False,
                "error": "No data found for this address",
                "address": address
            }
        
        # Events
        cursor.execute("""
            SELECT event_type, score_before, score_after, timestamp, created_at, referrer 
            FROM events 
            WHERE address=? 
            ORDER BY timestamp DESC
        """, (address,))
        events = [dict(row) for row in cursor.fetchall()]
        
        # Followers (wenn User als Owner fungiert)
        cursor.execute("""
            SELECT follower_address, follower_score, verified_at, source_platform, follow_confirmed
            FROM followers
            WHERE owner_wallet=?
        """, (address,))
        followers = [dict(row) for row in cursor.fetchall()]
        
        # Following (wenn User selbst Follower ist)
        cursor.execute("""
            SELECT owner_wallet, verified_at, source_platform, follow_confirmed
            FROM followers
            WHERE follower_address=?
        """, (address,))
        following = [dict(row) for row in cursor.fetchall()]
        
        # Telegram Invites
        cursor.execute("""
            SELECT invited_at, granted, owner_wallet
            FROM telegram_invites
            WHERE address=?
        """, (address,))
        telegram_invites = [dict(row) for row in cursor.fetchall()]
        
        # Telegram Groups (wenn Owner)
        cursor.execute("""
            SELECT telegram_invite_link, group_name, created_at, is_active
            FROM owner_telegram_groups
            WHERE owner_wallet=?
        """, (address,))
        telegram_groups = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        
        log_activity("INFO", "GDPR", "✓ Data request fulfilled", address=address[:10])
        
        return {
            "success": True,
            "address": address,
            "personal_data": {
                "first_seen": user['first_seen'],
                "last_login": user['last_login'],
                "score": user['score'],
                "login_count": user['login_count'],
                "created_at": user['created_at'],
                "first_referrer": user['first_referrer'],
                "last_referrer": user['last_referrer'],
                "display_name": user['display_name'] if 'display_name' in user.keys() else None,
                "is_verified_follower": user['is_verified_follower']
            },
            "events_count": len(events),
            "events": events[:50],  # Last 50 events
            "followers_count": len(followers),
            "followers": followers,
            "following_count": len(following),
            "following": following,
            "telegram_invites": telegram_invites,
            "telegram_groups": telegram_groups,
            "data_export_url": f"/api/gdpr/export/{address}",
            "deletion_url": f"/api/gdpr/delete/{address}",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except Exception as e:
        log_activity("ERROR", "GDPR", f"Data request error: {str(e)}")
        return {"success": False, "error": str(e)}


@app.delete("/api/gdpr/delete/{address}")
async def gdpr_delete_data(address: str, req: Request):
    """
    🔒 GDPR Art. 17 - Recht auf Löschung ("Recht auf Vergessenwerden")
    
    Löscht ALLE personenbezogenen Daten zu einer Wallet-Adresse.
    
    WICHTIG: User muss mit MetaMask signieren um Löschung zu bestätigen!
    
    Request Body:
        {
            "signature": "0x...",
            "nonce": "..."
        }
    
    Response:
        {
            "success": true,
            "deleted": {
                "users": 1,
                "events": 25,
                "followers": 5,
                "telegram_invites": 1
            }
        }
    """
    try:
        address = address.lower()
        
        if not address or not address.startswith("0x") or len(address) != 42:
            return {"error": "Invalid address format", "success": False}
        
        # SECURITY: Require signature verification
        try:
            data = await req.json()
            signature = data.get("signature", "")
            nonce = data.get("nonce", "")
            
            if not signature or not nonce:
                return {
                    "success": False,
                    "error": "Signature required for data deletion",
                    "message": "Please sign the deletion request with MetaMask"
                }
            
            # Verify signature
            from eth_account.messages import encode_defunct
            from eth_account import Account
            
            message_text = f"I confirm deletion of all my data from AEra:\nNonce: {nonce}"
            message = encode_defunct(text=message_text)
            recovered_address = Account.recover_message(message, signature=signature)
            
            if recovered_address.lower() != address:
                log_activity("ERROR", "GDPR", "❌ Deletion denied - Invalid signature", 
                            address=address[:10])
                return {
                    "success": False,
                    "error": "Signature verification failed"
                }
            
        except Exception as sig_err:
            log_activity("ERROR", "GDPR", f"Signature verification error: {str(sig_err)}")
            return {
                "success": False,
                "error": "Signature verification failed",
                "details": str(sig_err)
            }
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Count items before deletion
        cursor.execute("SELECT COUNT(*) as count FROM events WHERE address=?", (address,))
        events_count = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM followers WHERE follower_address=?", (address,))
        followers_count = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM telegram_invites WHERE address=?", (address,))
        telegram_count = cursor.fetchone()['count']
        
        # Delete all data (CASCADE)
        cursor.execute("DELETE FROM events WHERE address=?", (address,))
        cursor.execute("DELETE FROM followers WHERE follower_address=? OR owner_wallet=?", (address, address))
        cursor.execute("DELETE FROM telegram_invites WHERE address=? OR owner_wallet=?", (address, address))
        cursor.execute("DELETE FROM owner_telegram_groups WHERE owner_wallet=?", (address,))
        cursor.execute("DELETE FROM airdrops WHERE address=?", (address,))
        cursor.execute("DELETE FROM users WHERE address=?", (address,))
        
        conn.commit()
        conn.close()
        
        log_activity("WARNING", "GDPR", "🗑️ User data DELETED (GDPR request)", 
                    address=address[:10], 
                    events=events_count, 
                    followers=followers_count)
        
        return {
            "success": True,
            "message": "All personal data has been permanently deleted",
            "deleted": {
                "users": 1,
                "events": events_count,
                "followers": followers_count,
                "telegram_invites": telegram_count
            },
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except Exception as e:
        log_activity("ERROR", "GDPR", f"Deletion error: {str(e)}")
        return {"success": False, "error": str(e)}


@app.get("/api/gdpr/export/{address}")
async def gdpr_export_data(address: str):
    """
    🔒 GDPR Art. 20 - Recht auf Datenübertragbarkeit
    
    Exportiert alle Daten als JSON-Download.
    
    Returns: JSON file download
    """
    try:
        address = address.lower()
        
        if not address or not address.startswith("0x") or len(address) != 42:
            return {"error": "Invalid address format"}
        
        # Get all data via gdpr_get_data endpoint
        data_response = await gdpr_get_data(address)
        
        if not data_response.get("success"):
            return data_response
        
        # Return as downloadable JSON
        from fastapi.responses import JSONResponse
        
        filename = f"aera_data_export_{address[:10]}_{int(time.time())}.json"
        
        return JSONResponse(
            content=data_response,
            headers={
                "Content-Disposition": f"attachment; filename={filename}"
            }
        )
        
    except Exception as e:
        log_activity("ERROR", "GDPR", f"Export error: {str(e)}")
        return {"error": str(e)}


@app.get("/privacy-policy", response_class=HTMLResponse)
async def privacy_policy():
    """📜 Privacy Policy - GDPR Compliant"""
    with open(os.path.join(os.path.dirname(__file__), "privacy-policy.html"), "r") as f:
        return HTMLResponse(content=f.read())


# ============================================================================
# ===== NFT METADATA API - For Wallet Display (OpenSea, Rainbow, etc.) =====
# ============================================================================

@app.get("/api/nft/metadata/{token_id}")
async def get_nft_metadata(token_id: int):
    """
    🎨 NFT Metadata Endpoint (ERC-721 Standard)
    
    Returns JSON metadata for AEra Identity NFT.
    This endpoint should be set as the tokenURI base in the smart contract.
    
    Example: https://aeralogin.com/api/nft/metadata/10
    
    Response:
        {
            "name": "AEra Identity #10",
            "description": "Verified human identity...",
            "image": "https://aeralogin.com/api/nft/image/10",
            "external_url": "https://aeralogin.com/dashboard",
            "attributes": [
                {"trait_type": "Resonance Score", "value": 72, "max_value": 100},
                {"trait_type": "Followers", "value": 16},
                ...
            ]
        }
    """
    try:
        # Get wallet address from token ID
        address = await get_address_from_token_id(token_id)
        
        if not address:
            return {
                "name": f"AEra Identity #{token_id}",
                "description": "AEra Identity NFT - Verified Human on BASE",
                "image": f"{PUBLIC_URL}/api/nft/image/{token_id}",
                "attributes": [
                    {"trait_type": "Status", "value": "Unknown"}
                ]
            }
        
        # Get user data from database
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT score, login_count, created_at, identity_status
            FROM users WHERE address = ?
        """, (address.lower(),))
        user = cursor.fetchone()
        
        # Get follower count
        cursor.execute("""
            SELECT COUNT(*) as count FROM followers WHERE owner_wallet = ?
        """, (address.lower(),))
        follower_result = cursor.fetchone()
        follower_count = follower_result['count'] if follower_result else 0
        
        # Get interaction count (follows made)
        cursor.execute("""
            SELECT COUNT(*) as count FROM followers WHERE follower_address = ?
        """, (address.lower(),))
        interaction_result = cursor.fetchone()
        interaction_count = interaction_result['count'] if interaction_result else 0
        
        conn.close()
        
        if not user:
            return {
                "name": f"AEra Identity #{token_id}",
                "description": "AEra Identity NFT - Verified Human on BASE",
                "image": f"{PUBLIC_URL}/api/nft/image/{token_id}",
                "attributes": [
                    {"trait_type": "Status", "value": "Inactive"}
                ]
            }
        
        # Calculate score tier
        score = float(user['score']) if user['score'] else 50
        if score >= 90:
            tier = "Legendary"
            tier_emoji = "🏆"
        elif score >= 80:
            tier = "Epic"
            tier_emoji = "💎"
        elif score >= 70:
            tier = "Rare"
            tier_emoji = "🌟"
        elif score >= 60:
            tier = "Uncommon"
            tier_emoji = "✨"
        else:
            tier = "Common"
            tier_emoji = "🌀"
        
        # Format join date
        created_at = user['created_at']
        if created_at:
            try:
                join_date = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                member_since = join_date.strftime("%B %Y")
            except:
                member_since = "2025"
        else:
            member_since = "2025"
        
        return {
            "name": f"AEra Identity #{token_id}",
            "description": f"Verified human identity on BASE blockchain. {tier_emoji} {tier} Tier with {int(score)} Resonance Score.",
            "image": f"{PUBLIC_URL}/api/nft/image/{token_id}",
            "external_url": f"{PUBLIC_URL}/dashboard?owner={address}",
            "background_color": "050814",
            "attributes": [
                {
                    "trait_type": "Resonance Score",
                    "value": int(score),
                    "max_value": 100,
                    "display_type": "number"
                },
                {
                    "trait_type": "Tier",
                    "value": tier
                },
                {
                    "trait_type": "Followers",
                    "value": follower_count,
                    "display_type": "number"
                },
                {
                    "trait_type": "Interactions",
                    "value": interaction_count + follower_count,
                    "display_type": "number"
                },
                {
                    "trait_type": "Logins",
                    "value": user['login_count'] if user['login_count'] else 1,
                    "display_type": "number"
                },
                {
                    "trait_type": "Member Since",
                    "value": member_since
                },
                {
                    "trait_type": "Status",
                    "value": "Active" if user['identity_status'] == 'active' else "Pending"
                },
                {
                    "trait_type": "Chain",
                    "value": "BASE"
                }
            ]
        }
        
    except Exception as e:
        log_activity("ERROR", "NFT_METADATA", f"Error getting metadata for token {token_id}: {str(e)}")
        return {
            "name": f"AEra Identity #{token_id}",
            "description": "AEra Identity NFT",
            "image": f"{PUBLIC_URL}/api/nft/image/{token_id}",
            "attributes": []
        }


@app.get("/api/nft/image/{token_id}")
async def get_nft_image(token_id: int):
    """
    🎨 Dynamic NFT Image (SVG)
    
    Generates a beautiful SVG image showing the current Resonance Score.
    Updates automatically when score changes!
    
    Returns: image/svg+xml
    """
    from fastapi.responses import Response
    
    try:
        # Get wallet address from token ID
        address = await get_address_from_token_id(token_id)
        
        score = 50
        follower_count = 0
        interaction_count = 0
        tier = "Common"
        tier_color = "#667eea"
        
        if address:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute("SELECT score FROM users WHERE address = ?", (address.lower(),))
            user = cursor.fetchone()
            if user and user['score']:
                score = int(float(user['score']))
            
            cursor.execute("SELECT COUNT(*) as count FROM followers WHERE owner_wallet = ?", (address.lower(),))
            result = cursor.fetchone()
            follower_count = result['count'] if result else 0
            
            cursor.execute("SELECT COUNT(*) as count FROM followers WHERE follower_address = ?", (address.lower(),))
            result = cursor.fetchone()
            interaction_count = result['count'] if result else 0
            
            conn.close()
        
        # Determine tier and colors
        if score >= 90:
            tier = "LEGENDARY"
            tier_color = "#FFD700"
            glow_color = "#FFD700"
            bg_gradient = "url(#legendaryGrad)"
        elif score >= 80:
            tier = "EPIC"
            tier_color = "#9B59B6"
            glow_color = "#9B59B6"
            bg_gradient = "url(#epicGrad)"
        elif score >= 70:
            tier = "RARE"
            tier_color = "#3498DB"
            glow_color = "#3498DB"
            bg_gradient = "url(#rareGrad)"
        elif score >= 60:
            tier = "UNCOMMON"
            tier_color = "#2ECC71"
            glow_color = "#2ECC71"
            bg_gradient = "url(#uncommonGrad)"
        else:
            tier = "COMMON"
            tier_color = "#667eea"
            glow_color = "#667eea"
            bg_gradient = "url(#commonGrad)"
        
        # Calculate progress bar width (0-100%)
        progress_width = min(score, 100) * 2.4  # 240px max width
        
        svg = f'''<?xml version="1.0" encoding="UTF-8"?>
<svg width="350" height="350" viewBox="0 0 350 350" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <!-- Background Gradients -->
    <linearGradient id="commonGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#050814"/>
      <stop offset="100%" style="stop-color:#0a0e27"/>
    </linearGradient>
    <linearGradient id="uncommonGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#0a1a0f"/>
      <stop offset="100%" style="stop-color:#052e16"/>
    </linearGradient>
    <linearGradient id="rareGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#0a1628"/>
      <stop offset="100%" style="stop-color:#0c2445"/>
    </linearGradient>
    <linearGradient id="epicGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#1a0a28"/>
      <stop offset="100%" style="stop-color:#2d1045"/>
    </linearGradient>
    <linearGradient id="legendaryGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#1a1505"/>
      <stop offset="100%" style="stop-color:#2d2408"/>
    </linearGradient>
    
    <!-- Progress Bar Gradient -->
    <linearGradient id="progressGrad" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" style="stop-color:#0052ff"/>
      <stop offset="50%" style="stop-color:#00d4ff"/>
      <stop offset="100%" style="stop-color:{tier_color}"/>
    </linearGradient>
    
    <!-- Glow Effect -->
    <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
      <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
      <feMerge>
        <feMergeNode in="coloredBlur"/>
        <feMergeNode in="SourceGraphic"/>
      </feMerge>
    </filter>
  </defs>
  
  <!-- Background -->
  <rect width="350" height="350" rx="20" fill="{bg_gradient}"/>
  
  <!-- Border Glow -->
  <rect width="346" height="346" x="2" y="2" rx="18" fill="none" stroke="{tier_color}" stroke-width="2" opacity="0.5"/>
  
  <!-- Logo Circle -->
  <circle cx="175" cy="80" r="40" fill="none" stroke="{tier_color}" stroke-width="2" filter="url(#glow)"/>
  <text x="175" y="95" text-anchor="middle" font-size="40" fill="{tier_color}">🌀</text>
  
  <!-- Title -->
  <text x="175" y="145" text-anchor="middle" font-family="Arial, sans-serif" font-size="16" font-weight="bold" fill="white">AEra Identity</text>
  <text x="175" y="165" text-anchor="middle" font-family="Arial, sans-serif" font-size="12" fill="{tier_color}">#{token_id}</text>
  
  <!-- Tier Badge -->
  <rect x="125" y="175" width="100" height="24" rx="12" fill="{tier_color}" opacity="0.2"/>
  <text x="175" y="192" text-anchor="middle" font-family="Arial, sans-serif" font-size="11" font-weight="bold" fill="{tier_color}">{tier}</text>
  
  <!-- Score Section -->
  <text x="175" y="230" text-anchor="middle" font-family="Arial, sans-serif" font-size="12" fill="#888">RESONANCE SCORE</text>
  <text x="175" y="265" text-anchor="middle" font-family="Arial, sans-serif" font-size="42" font-weight="bold" fill="white" filter="url(#glow)">{score}</text>
  <text x="210" y="265" text-anchor="start" font-family="Arial, sans-serif" font-size="16" fill="#666">/100</text>
  
  <!-- Progress Bar -->
  <rect x="55" y="280" width="240" height="8" rx="4" fill="#1a1a2e"/>
  <rect x="55" y="280" width="{progress_width}" height="8" rx="4" fill="url(#progressGrad)"/>
  
  <!-- Stats -->
  <text x="90" y="320" text-anchor="middle" font-family="Arial, sans-serif" font-size="11" fill="#888">👥 {follower_count}</text>
  <text x="90" y="335" text-anchor="middle" font-family="Arial, sans-serif" font-size="9" fill="#555">Followers</text>
  
  <text x="175" y="320" text-anchor="middle" font-family="Arial, sans-serif" font-size="11" fill="#888">⛓️ {interaction_count + follower_count}</text>
  <text x="175" y="335" text-anchor="middle" font-family="Arial, sans-serif" font-size="9" fill="#555">Interactions</text>
  
  <text x="260" y="320" text-anchor="middle" font-family="Arial, sans-serif" font-size="11" fill="#888">✅</text>
  <text x="260" y="335" text-anchor="middle" font-family="Arial, sans-serif" font-size="9" fill="#555">Verified</text>
</svg>'''
        
        return Response(content=svg, media_type="image/svg+xml")
        
    except Exception as e:
        log_activity("ERROR", "NFT_IMAGE", f"Error generating image for token {token_id}: {str(e)}")
        # Return a simple fallback SVG
        fallback_svg = f'''<?xml version="1.0" encoding="UTF-8"?>
<svg width="350" height="350" viewBox="0 0 350 350" xmlns="http://www.w3.org/2000/svg">
  <rect width="350" height="350" rx="20" fill="#050814"/>
  <text x="175" y="175" text-anchor="middle" font-family="Arial" font-size="40" fill="#667eea">🌀</text>
  <text x="175" y="220" text-anchor="middle" font-family="Arial" font-size="16" fill="white">AEra #{token_id}</text>
</svg>'''
        return Response(content=fallback_svg, media_type="image/svg+xml")


async def get_address_from_token_id(token_id: int) -> Optional[str]:
    """
    Get wallet address from NFT token ID
    
    Uses database lookup first (fastest), then falls back to blockchain query
    """
    try:
        # Method 1: Database lookup (fastest)
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT address FROM users WHERE identity_nft_token_id = ?",
            (token_id,)
        )
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return result['address']
        
        # Method 2: Blockchain query (ownerOf)
        try:
            from web3 import Web3
            
            IDENTITY_NFT_ADDRESS = os.getenv("IDENTITY_NFT_ADDRESS", "0xF9ff5DC523927B9632049bd19e17B610E9197d53")
            
            # Use Alchemy for faster blockchain queries
            alchemy_url = os.getenv("BASE_ALCHEMY_API_URL") or os.getenv("BASE_RPC_URL", "https://mainnet.base.org")
            w3 = Web3(Web3.HTTPProvider(alchemy_url))
            
            # Minimal ABI with ownerOf
            abi = [
                {
                    "inputs": [{"name": "tokenId", "type": "uint256"}],
                    "name": "ownerOf",
                    "outputs": [{"name": "", "type": "address"}],
                    "stateMutability": "view",
                    "type": "function"
                }
            ]
            
            contract = w3.eth.contract(
                address=Web3.to_checksum_address(IDENTITY_NFT_ADDRESS),
                abi=abi
            )
            
            owner = contract.functions.ownerOf(token_id).call()
            return owner.lower()
            
        except Exception as blockchain_err:
            log_activity("WARNING", "NFT", f"Could not get owner from blockchain: {str(blockchain_err)}")
            return None
        
    except Exception as e:
        log_activity("ERROR", "NFT", f"Error getting address for token {token_id}: {str(e)}")
        return None


# ============================================================================
# ===== PROFILE NFT API - Optional Public Display Layer =====
# ============================================================================

@app.get("/api/profile-nft/status/{address}")
async def get_profile_nft_status(address: str):
    """
    🎨 Get Profile NFT status for a user
    
    This is the OPTIONAL public display NFT, separate from Identity NFT.
    
    Returns:
        {
            "has_profile_nft": true/false,
            "token_id": 1,
            "is_public": false,
            "metadata_nonce": 0,
            "soulbound_mode": false,
            "contract_address": "0x...",
            "minted_at": "2024-12-31T...",
            "backend_is_delegate": true/false  // Can backend change visibility for free?
        }
    """
    try:
        address = address.lower()
        
        # Check blockchain first
        profile_data = await web3_service.get_profile_data(address)
        
        if profile_data:
            # Get additional DB info
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT profile_nft_minted_at, profile_nft_mint_tx_hash FROM users WHERE address=?",
                (address,)
            )
            db_result = cursor.fetchone()
            conn.close()
            
            # Check if backend is delegate (for free visibility changes)
            backend_is_delegate = await web3_service.is_backend_delegate(profile_data["token_id"])
            
            return {
                "has_profile_nft": True,
                "token_id": profile_data["token_id"],
                "is_public": profile_data["is_public"],
                "metadata_nonce": profile_data["metadata_nonce"],
                "token_uri": profile_data["token_uri"],
                "soulbound_mode": profile_data["soulbound_mode"],
                "contract_address": profile_data["contract_address"],
                "minted_at": db_result["profile_nft_minted_at"] if db_result else None,
                "mint_tx_hash": db_result["profile_nft_mint_tx_hash"] if db_result else None,
                "opensea_url": f"https://opensea.io/assets/base/{profile_data['contract_address']}/{profile_data['token_id']}",
                "backend_is_delegate": backend_is_delegate,
                "backend_address": os.getenv("BACKEND_ADDRESS", "0x22A2cAcB19e77D25DA063A787870A3eE6BAC8Dfe")
            }
        else:
            return {
                "has_profile_nft": False,
                "token_id": None,
                "is_public": None,
                "contract_address": os.getenv("PROFILE_NFT_ADDRESS"),
                "message": "No Profile NFT minted. This is optional.",
                "backend_is_delegate": False,
                "backend_address": os.getenv("BACKEND_ADDRESS", "0x22A2cAcB19e77D25DA063A787870A3eE6BAC8Dfe")
            }
            
    except Exception as e:
        log_activity("ERROR", "PROFILE_NFT", f"Error getting profile status for {address}: {str(e)}")
        return {"error": str(e), "has_profile_nft": False}


@app.post("/api/profile-nft/mint")
async def mint_profile_nft(request: Request):
    """
    🎨 Mint a new Profile NFT (USER-INITIATED WITH WALLET SIGNATURE!)
    
    This is an OPTIONAL action - users can use AEra without this NFT.
    Requires wallet signature for authorization.
    
    Request Body:
        {
            "address": "0x...",
            "signature": "0x...",
            "message": "...",
            "timestamp": 1234567890
        }
    
    Returns:
        {"success": true, "token_id": 1, "tx_hash": "0x..."}
    """
    try:
        data = await request.json()
        address = data.get("address", "").lower()
        signature = data.get("signature", "")
        message = data.get("message", "")
        timestamp = data.get("timestamp", 0)
        
        if not address:
            return JSONResponse(
                status_code=400,
                content={"success": False, "error": "Address required"}
            )
        
        # ===== SIGNATURE VERIFICATION =====
        if not signature or not message:
            return JSONResponse(
                status_code=400,
                content={
                    "success": False, 
                    "error": "Wallet signature required",
                    "message": "Please confirm the mint request in your wallet"
                }
            )
        
        # Verify timestamp is recent (within 5 minutes)
        current_time = int(time.time() * 1000)
        if abs(current_time - timestamp) > 300000:  # 5 minutes
            return JSONResponse(
                status_code=400,
                content={"success": False, "error": "Request expired. Please try again."}
            )
        
        # Verify the signature matches the address
        try:
            from eth_account.messages import encode_defunct
            from eth_account import Account
            
            encoded_message = encode_defunct(text=message)
            recovered_address = Account.recover_message(encoded_message, signature=signature).lower()
            
            if recovered_address != address:
                log_activity("WARNING", "PROFILE_NFT", f"❌ Signature mismatch: expected {address[:10]}, got {recovered_address[:10]}")
                return JSONResponse(
                    status_code=400,
                    content={"success": False, "error": "Signature verification failed. Wrong wallet?"}
                )
            
            log_activity("INFO", "PROFILE_NFT", f"✅ Signature verified for {address[:10]}...")
            
        except Exception as sig_err:
            log_activity("ERROR", "PROFILE_NFT", f"Signature verification error: {str(sig_err)}")
            return JSONResponse(
                status_code=400,
                content={"success": False, "error": f"Signature verification failed: {str(sig_err)}"}
            )
        
        # ===== PRE-MINT CHECKS =====
        # Verify user has Identity NFT first (prerequisite)
        has_identity = await web3_service.has_identity_nft(address)
        if not has_identity:
            return JSONResponse(
                status_code=400,
                content={
                    "success": False, 
                    "error": "Identity NFT required before minting Profile NFT"
                }
            )
        
        # Check if already has Profile NFT
        has_profile = await web3_service.has_profile_nft(address)
        if has_profile:
            profile_data = await web3_service.get_profile_data(address)
            return JSONResponse(
                status_code=400,
                content={
                    "success": False,
                    "error": f"User already has Profile NFT #{profile_data['token_id']}"
                }
            )
        
        # ===== MINT THE NFT =====
        success, result = await web3_service.mint_profile_nft(address)
        
        if success:
            # Save to database
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE users 
                SET profile_nft_token_id=?, profile_nft_visibility='private', 
                    profile_nft_minted_at=?, profile_nft_mint_tx_hash=?
                WHERE address=?
            """, (result["token_id"], datetime.utcnow().isoformat(), result["tx_hash"], address))
            conn.commit()
            conn.close()
            
            log_activity("INFO", "PROFILE_NFT", f"Minted Profile NFT #{result['token_id']} for {address[:10]}...")
            
            return {
                "success": True,
                "token_id": result["token_id"],
                "tx_hash": result["tx_hash"],
                "contract_address": result["contract_address"],
                "opensea_url": f"https://opensea.io/assets/base/{result['contract_address']}/{result['token_id']}"
            }
        else:
            return JSONResponse(
                status_code=500,
                content={"success": False, "error": result.get("error", "Unknown error")}
            )
            
    except Exception as e:
        log_activity("ERROR", "PROFILE_NFT", f"Error minting profile: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": str(e)}
        )


@app.post("/api/profile-nft/visibility")
async def set_profile_visibility(request: Request):
    """
    👁️ Set Profile NFT visibility (PUBLIC/PRIVATE)
    
    Privacy by default - user can opt-in to public display.
    
    Request Body:
        {"address": "0x...", "is_public": true/false}
    """
    try:
        data = await request.json()
        address = data.get("address", "").lower()
        is_public = data.get("is_public", False)
        
        if not address:
            return JSONResponse(
                status_code=400,
                content={"success": False, "error": "Address required"}
            )
        
        # Get token ID first
        profile_data = await web3_service.get_profile_data(address)
        if not profile_data:
            return JSONResponse(
                status_code=400,
                content={"success": False, "error": "No Profile NFT found for this address"}
            )
        
        token_id = profile_data["token_id"]
        
        # Set visibility on-chain
        success, result = await web3_service.set_profile_visibility(token_id, is_public)
        
        if success:
            # Update database
            visibility_str = "public" if is_public else "private"
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE users 
                SET profile_nft_visibility=?
                WHERE address=?
            """, (visibility_str, address))
            conn.commit()
            conn.close()
            
            log_activity("INFO", "PROFILE_NFT", f"Set visibility to {visibility_str} for token #{token_id}")
            
            return {
                "success": True,
                "token_id": token_id,
                "is_public": is_public,
                "visibility": visibility_str,
                "tx_hash": result.get("tx_hash")
            }
        else:
            return JSONResponse(
                status_code=500,
                content={"success": False, "error": result.get("error", "Unknown error")}
            )
            
    except Exception as e:
        log_activity("ERROR", "PROFILE_NFT", f"Error setting visibility: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": str(e)}
        )


@app.post("/api/profile-nft/sync-visibility")
async def sync_profile_visibility(request: Request):
    """
    🔄 Sync Profile NFT visibility from on-chain to database
    
    Called after a user-paid visibility transaction to update DB.
    Reads the actual on-chain visibility and updates the database.
    
    Request Body:
        {"address": "0x..."}
    """
    try:
        data = await request.json()
        address = data.get("address", "").lower()
        
        if not address:
            return JSONResponse(
                status_code=400,
                content={"success": False, "error": "Address required"}
            )
        
        # Get on-chain profile data including visibility
        profile_data = await web3_service.get_profile_data(address)
        if not profile_data:
            return JSONResponse(
                status_code=400,
                content={"success": False, "error": "No Profile NFT found for this address"}
            )
        
        # Get visibility from on-chain data
        is_public = profile_data.get("is_public", False)
        visibility_str = "public" if is_public else "private"
        
        # Update database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE users 
            SET profile_nft_visibility=?
            WHERE address=?
        """, (visibility_str, address))
        conn.commit()
        conn.close()
        
        log_activity("INFO", "PROFILE_NFT", f"Synced visibility to {visibility_str} for {address[:10]}...")
        
        return {
            "success": True,
            "address": address,
            "visibility": visibility_str,
            "is_public": is_public,
            "synced_from": "on-chain"
        }
        
    except Exception as e:
        log_activity("ERROR", "PROFILE_NFT", f"Error syncing visibility: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": str(e)}
        )


@app.post("/api/profile-nft/refresh")
async def refresh_profile_metadata(request: Request):
    """
    🔄 Refresh Profile NFT metadata
    
    Increments the metadata nonce to force OpenSea/marketplaces to refresh.
    Uses EIP-4906 MetadataUpdate event.
    
    Request Body:
        {"address": "0x..."}
    """
    try:
        data = await request.json()
        address = data.get("address", "").lower()
        
        if not address:
            return JSONResponse(
                status_code=400,
                content={"success": False, "error": "Address required"}
            )
        
        # Get token ID first
        profile_data = await web3_service.get_profile_data(address)
        if not profile_data:
            return JSONResponse(
                status_code=400,
                content={"success": False, "error": "No Profile NFT found for this address"}
            )
        
        token_id = profile_data["token_id"]
        
        # Increment metadata nonce on-chain
        success, result = await web3_service.increment_metadata_nonce(token_id)
        
        if success:
            log_activity("INFO", "PROFILE_NFT", f"Refreshed metadata for token #{token_id}")
            
            return {
                "success": True,
                "token_id": token_id,
                "new_nonce": result.get("new_nonce"),
                "tx_hash": result.get("tx_hash"),
                "message": "Metadata refresh requested. OpenSea will update within 1-24 hours."
            }
        else:
            return JSONResponse(
                status_code=500,
                content={"success": False, "error": result.get("error", "Unknown error")}
            )
            
    except Exception as e:
        log_activity("ERROR", "PROFILE_NFT", f"Error refreshing metadata: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": str(e)}
        )


@app.post("/api/profile-nft/burn")
async def burn_profile_nft(request: Request):
    """
    🔥 Burn a Profile NFT (removes it completely)
    
    This is a destructive action! User can re-mint later.
    
    Request Body:
        {"address": "0x..."}
    """
    try:
        data = await request.json()
        address = data.get("address", "").lower()
        
        if not address:
            return JSONResponse(
                status_code=400,
                content={"success": False, "error": "Address required"}
            )
        
        # Get token ID first
        profile_data = await web3_service.get_profile_data(address)
        if not profile_data:
            return JSONResponse(
                status_code=400,
                content={"success": False, "error": "No Profile NFT to burn"}
            )
        
        token_id = profile_data["token_id"]
        
        # Burn the NFT
        success, result = await web3_service.burn_profile_nft(token_id)
        
        if success:
            # Update database
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE users 
                SET profile_nft_token_id=NULL, profile_nft_visibility=NULL, 
                    profile_nft_minted_at=NULL, profile_nft_mint_tx_hash=NULL
                WHERE address=?
            """, (address,))
            conn.commit()
            conn.close()
            
            log_activity("INFO", "PROFILE_NFT", f"Burned Profile NFT #{token_id} for {address[:10]}...")
            
            return {
                "success": True,
                "burned_token_id": token_id,
                "tx_hash": result["tx_hash"]
            }
        else:
            return JSONResponse(
                status_code=500,
                content={"success": False, "error": result.get("error", "Unknown error")}
            )
            
    except Exception as e:
        log_activity("ERROR", "PROFILE_NFT", f"Error burning profile: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": str(e)}
        )


@app.get("/api/profile-nft/total-supply")
async def get_profile_nft_total_supply():
    """📊 Get total number of minted Profile NFTs"""
    try:
        total = await web3_service.get_profile_total_supply()
        return {
            "total_supply": total,
            "contract_address": os.getenv("PROFILE_NFT_ADDRESS")
        }
    except Exception as e:
        return {"error": str(e), "total_supply": 0}


# ============================================================================
# ===== PROFILE NFT METADATA ENDPOINTS - For OpenSea/Marketplaces =====
# ============================================================================

# Support both /api/profile/public/1 and /api/profile/public/1.json
@app.get("/api/profile/public/{token_id}.json")
@app.get("/api/profile/public/{token_id}")
async def get_profile_public_metadata(token_id: int):
    """
    🌐 Public Profile NFT Metadata
    
    Returns full metadata when visibility is PUBLIC.
    """
    try:
        # Get owner address from token ID
        address = await get_profile_address_from_token_id(token_id)
        if not address:
            return JSONResponse(
                status_code=404,
                content={"error": "Token not found"}
            )
        
        # Check visibility
        is_public = await web3_service.get_profile_visibility(token_id)
        if not is_public:
            # Redirect to private endpoint
            return await get_profile_private_metadata(token_id)
        
        # Get user data from DB
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT score, blockchain_score, login_count, created_at, display_name
            FROM users WHERE address=?
        """, (address,))
        user = cursor.fetchone()
        
        # Get follower count
        cursor.execute("SELECT COUNT(*) FROM followers WHERE owner_wallet=?", (address,))
        follower_count = cursor.fetchone()[0] or 0
        conn.close()
        
        if not user:
            return JSONResponse(status_code=404, content={"error": "User not found"})
        
        # Use blockchain_score if available, otherwise fallback to DB score
        blockchain_score = user['blockchain_score'] or user['score'] or 50
        db_score = user['score'] or 50
        tier = get_tier_name(blockchain_score)
        display_name = user['display_name'] or f"AEra User"
        
        # Calculate owner score (blockchain - db = pending score from owned followers)
        owner_score = blockchain_score - db_score if blockchain_score > db_score else 0
        
        attributes = [
            {"trait_type": "Token ID", "value": token_id, "display_type": "number"},
            {"trait_type": "Visibility", "value": "Public"},
            {"trait_type": "Tier", "value": tier},
            {"trait_type": "Resonance Score", "value": blockchain_score, "display_type": "number"},
            {"trait_type": "Followers", "value": follower_count, "display_type": "number"},
            {"trait_type": "Logins", "value": user['login_count'] or 0, "display_type": "number"},
            {"trait_type": "Member Since", "value": int(datetime.fromisoformat(user['created_at']).timestamp()) if user['created_at'] else 0, "display_type": "date"}
        ]
        
        # Add Owner Score if user has earned from followers
        if owner_score > 0:
            attributes.insert(4, {"trait_type": "Owner Score", "value": owner_score, "display_type": "number"})
        
        return {
            "name": f"AEra Profile #{token_id}",
            "description": f"Public AEra Profile for {display_name}. Verified on-chain identity with Resonance Score {blockchain_score}.",
            "image": f"https://aeralogin.com/api/profile/image/{token_id}",
            "external_url": f"https://aeralogin.com/profile/{address}",
            "attributes": attributes
        }
        
    except Exception as e:
        log_activity("ERROR", "PROFILE_NFT", f"Error getting public metadata for {token_id}: {str(e)}")
        return JSONResponse(status_code=500, content={"error": str(e)})


# Handle double-slash issue from contract URI construction
@app.get("/api/profile/private//{token_id}.json")
async def get_profile_private_metadata_double_slash(token_id: int):
    """Redirect from double-slash URL"""
    return await get_profile_private_metadata(token_id)

@app.get("/api/profile/public//{token_id}.json")
async def get_profile_public_metadata_double_slash(token_id: int):
    """Redirect from double-slash URL"""
    return await get_profile_public_metadata(token_id)


# Support both /api/profile/private/1 and /api/profile/private/1.json
@app.get("/api/profile/private/{token_id}.json")
@app.get("/api/profile/private/{token_id}")
async def get_profile_private_metadata(token_id: int):
    """
    🔒 Private Profile NFT Metadata
    
    Returns minimal placeholder when visibility is PRIVATE.
    """
    try:
        return {
            "name": f"AEra Profile #{token_id}",
            "description": "Private AEra Profile NFT. Owner has chosen to keep details private.",
            "image": "https://aeralogin.com/api/profile/image/private",
            "external_url": "https://aeralogin.com",
            "attributes": [
                {"trait_type": "Visibility", "value": "Private"}
            ]
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.get("/api/profile/contract.json")
async def get_profile_contract_metadata():
    """
    📄 Profile NFT Collection Metadata (OpenSea Collection Info)
    """
    return {
        "name": "AEra Profile",
        "description": "Official AEra Profile NFT Collection with Privacy Features. Each NFT represents a verified on-chain identity with user-controlled visibility settings.",
        "image": "https://aeralogin.com/favicon.png",
        "external_link": "https://aeralogin.com",
        "seller_fee_basis_points": 0,
        "fee_recipient": ""
    }


@app.get("/api/profile/image/{token_id}")
async def get_profile_image(token_id: str):
    """
    🎨 Dynamic Profile NFT Image (SVG)
    
    Generates a custom SVG based on user's profile data.
    """
    try:
        # Special case: private placeholder
        if token_id == "private":
            svg = '''<?xml version="1.0" encoding="UTF-8"?>
<svg width="350" height="350" viewBox="0 0 350 350" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="bgGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#1a1a2e"/>
      <stop offset="100%" style="stop-color:#16213e"/>
    </linearGradient>
  </defs>
  <rect width="350" height="350" rx="20" fill="url(#bgGrad)"/>
  <text x="175" y="160" text-anchor="middle" font-family="Arial, sans-serif" font-size="60" fill="#667eea">🔒</text>
  <text x="175" y="210" text-anchor="middle" font-family="Arial, sans-serif" font-size="20" fill="white">Private Profile</text>
  <text x="175" y="240" text-anchor="middle" font-family="Arial, sans-serif" font-size="12" fill="#888">AEra Identity</text>
</svg>'''
            return Response(content=svg, media_type="image/svg+xml")
        
        # Convert to int
        token_id_int = int(token_id)
        
        # Get owner address
        address = await get_profile_address_from_token_id(token_id_int)
        if not address:
            # Return private placeholder directly (no recursion)
            return Response(content=get_private_placeholder_svg(), media_type="image/svg+xml")
        
        # Check visibility
        is_public = await web3_service.get_profile_visibility(token_id_int)
        if not is_public:
            # Return private placeholder directly (no recursion)
            return Response(content=get_private_placeholder_svg(), media_type="image/svg+xml")
        
        # Get user data
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT score, blockchain_score, display_name FROM users WHERE address=?
        """, (address,))
        user = cursor.fetchone()
        
        cursor.execute("SELECT COUNT(*) FROM followers WHERE owner_wallet=?", (address,))
        follower_count = cursor.fetchone()[0] or 0
        conn.close()
        
        # Use blockchain score if available, otherwise fallback to DB score
        blockchain_score = user['blockchain_score'] or user['score'] or 50 if user else 50
        db_score = user['score'] or 50 if user else 50
        display_name = user['display_name'] or f"AEra User" if user else "AEra User"
        tier = get_tier_name(blockchain_score)
        tier_colors = get_tier_colors(tier)
        
        # Calculate owner score
        owner_score = blockchain_score - db_score if blockchain_score > db_score else 0
        
        short_addr = f"{address[:6]}...{address[-4:]}"
        
        svg = f'''<?xml version="1.0" encoding="UTF-8"?>
<svg width="350" height="350" viewBox="0 0 350 350" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="bgGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:{tier_colors['bg1']}"/>
      <stop offset="100%" style="stop-color:{tier_colors['bg2']}"/>
    </linearGradient>
    <linearGradient id="scoreGrad" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" style="stop-color:{tier_colors['accent1']}"/>
      <stop offset="100%" style="stop-color:{tier_colors['accent2']}"/>
    </linearGradient>
  </defs>
  
  <!-- Background -->
  <rect width="350" height="350" rx="20" fill="url(#bgGrad)"/>
  
  <!-- Border -->
  <rect x="10" y="10" width="330" height="330" rx="15" fill="none" stroke="url(#scoreGrad)" stroke-width="2" opacity="0.5"/>
  
  <!-- Token ID Badge (Top Right) -->
  <rect x="280" y="20" width="50" height="24" rx="12" fill="url(#scoreGrad)" opacity="0.8"/>
  <text x="305" y="37" text-anchor="middle" font-family="Arial, sans-serif" font-size="12" fill="white" font-weight="bold">#{token_id_int}</text>
  
  <!-- Profile Icon -->
  <circle cx="175" cy="90" r="40" fill="url(#scoreGrad)" opacity="0.3"/>
  <text x="175" y="105" text-anchor="middle" font-family="Arial, sans-serif" font-size="40" fill="white">🌀</text>
  
  <!-- Display Name -->
  <text x="175" y="160" text-anchor="middle" font-family="Arial, sans-serif" font-size="18" fill="white" font-weight="bold">{display_name[:20]}</text>
  
  <!-- Address -->
  <text x="175" y="185" text-anchor="middle" font-family="monospace" font-size="12" fill="#888">{short_addr}</text>
  
  <!-- Tier Badge -->
  <rect x="120" y="200" width="110" height="28" rx="14" fill="url(#scoreGrad)"/>
  <text x="175" y="220" text-anchor="middle" font-family="Arial, sans-serif" font-size="14" fill="white" font-weight="bold">{tier}</text>
  
  <!-- Score -->
  <text x="175" y="270" text-anchor="middle" font-family="Arial, sans-serif" font-size="48" fill="url(#scoreGrad)" font-weight="bold">{int(blockchain_score)}</text>
  <text x="175" y="295" text-anchor="middle" font-family="Arial, sans-serif" font-size="12" fill="#888">Resonance Score</text>
  
  <!-- Followers -->
  <text x="175" y="330" text-anchor="middle" font-family="Arial, sans-serif" font-size="11" fill="#666">👥 {follower_count} Followers</text>
</svg>'''
        
        return Response(content=svg, media_type="image/svg+xml")
        
    except Exception as e:
        log_activity("ERROR", "PROFILE_NFT", f"Error generating profile image: {str(e)}")
        # Return private placeholder on error (no recursion)
        return Response(content=get_private_placeholder_svg(), media_type="image/svg+xml")


def get_private_placeholder_svg() -> str:
    """Returns the SVG content for a private profile placeholder"""
    return '''<?xml version="1.0" encoding="UTF-8"?>
<svg width="350" height="350" viewBox="0 0 350 350" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="bgGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#1a1a2e"/>
      <stop offset="100%" style="stop-color:#16213e"/>
    </linearGradient>
  </defs>
  <rect width="350" height="350" rx="20" fill="url(#bgGrad)"/>
  <text x="175" y="160" text-anchor="middle" font-family="Arial, sans-serif" font-size="60" fill="#667eea">🔒</text>
  <text x="175" y="210" text-anchor="middle" font-family="Arial, sans-serif" font-size="20" fill="white">Private Profile</text>
  <text x="175" y="240" text-anchor="middle" font-family="Arial, sans-serif" font-size="12" fill="#888">AEra Identity</text>
</svg>'''


async def get_profile_address_from_token_id(token_id: int) -> Optional[str]:
    """Get wallet address from Profile NFT token ID"""
    try:
        # Method 1: Database lookup
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT address FROM users WHERE profile_nft_token_id = ?",
            (token_id,)
        )
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return result['address']
        
        # Method 2: Blockchain query (ownerOf)
        try:
            from web3 import Web3
            
            PROFILE_NFT_ADDRESS = os.getenv("PROFILE_NFT_ADDRESS")
            if not PROFILE_NFT_ADDRESS:
                return None
            
            # Use Alchemy for faster blockchain queries
            alchemy_url = os.getenv("BASE_ALCHEMY_API_URL") or os.getenv("BASE_RPC_URL", "https://mainnet.base.org")
            w3 = Web3(Web3.HTTPProvider(alchemy_url))
            
            abi = [
                {
                    "inputs": [{"name": "tokenId", "type": "uint256"}],
                    "name": "ownerOf",
                    "outputs": [{"name": "", "type": "address"}],
                    "stateMutability": "view",
                    "type": "function"
                }
            ]
            
            contract = w3.eth.contract(
                address=Web3.to_checksum_address(PROFILE_NFT_ADDRESS),
                abi=abi
            )
            
            owner = contract.functions.ownerOf(token_id).call()
            return owner.lower()
            
        except Exception:
            return None
        
    except Exception as e:
        log_activity("ERROR", "PROFILE_NFT", f"Error getting address for profile token {token_id}: {str(e)}")
        return None


# ===== BLOCKCHAIN API ENDPOINTS =====

@app.get("/api/blockchain/identity/{address}")
async def get_blockchain_identity(address: str):
    """
    Get Identity NFT information for a user
    
    Returns:
        {
            "has_identity": true,
            "token_id": 123,
            "status": "active",
            "minted_at": "2024-11-30T14:30:00",
            "contract_address": "0x...",
            "basescan_url": "https://basescan.org/nft/0x..."
        }
    """
    try:
        address = address.lower()
        
        # Get DB info
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """SELECT identity_nft_token_id, identity_status, identity_minted_at, identity_mint_tx_hash
               FROM users WHERE address=?""",
            (address,)
        )
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            return {
                "has_identity": False,
                "identity_status": "not_found",
                "token_id": None,
                "mint_tx_hash": None,
                "minted_at": None,
                "contract_address": None,
                "basescan_url": None
            }
        
        # Get blockchain info
        # Primary: Trust DB if status is 'active' (already verified)
        db_token_id = user['identity_nft_token_id']
        db_status = user['identity_status']
        
        if db_status == 'active' and db_token_id is not None:
            # User has verified NFT in DB
            has_identity = True
            token_id = db_token_id
        else:
            # Check blockchain for pending/failed cases
            has_identity = await web3_service.has_identity_nft(address)
            token_id = await web3_service.get_identity_token_id(address) if has_identity else db_token_id
        
        contract_address = os.getenv("IDENTITY_NFT_ADDRESS", "")
        tx_hash = user['identity_mint_tx_hash']
        basescan_url = f"https://basescan.org/nft/{contract_address}/{token_id}" if token_id else None
        tx_url = f"https://basescan.org/tx/{tx_hash}" if tx_hash else None
        
        return {
            "has_identity": has_identity,
            "identity_status": user['identity_status'],  # pending, minting, active, failed
            "token_id": token_id,
            "mint_tx_hash": tx_hash,
            "minted_at": user['identity_minted_at'],
            "contract_address": contract_address,
            "basescan_url": basescan_url,
            "tx_url": tx_url
        }
        
    except Exception as e:
        log_activity("ERROR", "API", f"Blockchain identity error: {str(e)}")
        return {"error": str(e), "has_identity": False}


@app.get("/api/blockchain/score/{address}")
async def get_blockchain_score(address: str):
    """
    Get Resonance Score comparison (DB vs Blockchain)
    
    Returns:
        {
            "address": "0x...",
            "db_score": 55,
            "blockchain_score": 50,
            "sync_pending": 5,
            "last_sync": "2024-11-30T14:30:00",
            "next_sync_at": 60,
            "contract_address": "0x...",
            "basescan_url": "https://basescan.org/address/0x..."
        }
    """
    try:
        address = address.lower()
        
        # Get DB info
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """SELECT score, blockchain_score, blockchain_score_synced_at, last_blockchain_sync
               FROM users WHERE address=?""",
            (address,)
        )
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return {"error": "User not found"}
        
        # Calculate Resonance Score (Own + Avg Follower)
        from resonance_calculator import calculate_resonance_score
        own_score, avg_follower_score, follower_count, total_resonance = calculate_resonance_score(address, conn)
        conn.close()
        
        # Get blockchain score
        blockchain_score = await web3_service.get_blockchain_score(address)
        
        sync_pending = total_resonance - (blockchain_score or 0)
        
        # Calculate next sync milestone (every 2 points)
        next_sync_at = ((total_resonance // 2) + 1) * 2 if total_resonance < 100 else ((total_resonance // 2) + 1) * 2
        
        contract_address = os.getenv("RESONANCE_SCORE_ADDRESS", "")
        basescan_url = f"https://basescan.org/address/{contract_address}"
        
        return {
            "address": address,
            "own_score": own_score,
            "follower_bonus": avg_follower_score,
            "follower_count": follower_count,
            "total_resonance": total_resonance,
            "blockchain_score": blockchain_score,
            "sync_pending": sync_pending,
            "last_sync": user['last_blockchain_sync'],
            "next_sync_at": next_sync_at,
            "contract_address": contract_address,
            "basescan_url": basescan_url,
            # Legacy fields for backwards compatibility
            "db_score": own_score
        }
        
    except Exception as e:
        log_activity("ERROR", "API", f"Blockchain score error: {str(e)}")
        return {"error": str(e)}


@app.get("/api/blockchain/interactions/{address}")
async def get_blockchain_interactions(address: str, offset: int = 0, limit: int = 10):
    """
    Get user's interaction history from blockchain
    
    Query Parameters:
        offset: Pagination offset (default 0)
        limit: Results per page (default 10, max 50)
    
    Returns:
        {
            "address": "0x...",
            "interactions": [
                {
                    "initiator": "0x...",
                    "responder": "0x...",
                    "interaction_type": 0,
                    "interaction_type_name": "FOLLOW",
                    "timestamp": 1701360000,
                    "dashboard_link": "https://...",
                    "basescan_url": "https://basescan.org/tx/0x..."
                }
            ],
            "total": 5,
            "offset": 0,
            "limit": 10
        }
    """
    try:
        address = address.lower()
        limit = min(limit, 50)  # Max 50 per request
        
        # Get interactions from blockchain
        interactions = await web3_service.get_user_interactions(address, offset, limit)
        
        # Map interaction types
        type_names = {
            0: "FOLLOW",
            1: "SHARE",
            2: "ENGAGE",
            3: "COLLABORATE",
            4: "MILESTONE"
        }
        
        # Enhance with type names and Basescan URLs
        enhanced_interactions = []
        for interaction in interactions:
            tx_hash = interaction.get("tx_hash", "")
            enhanced_interactions.append({
                "initiator": interaction["initiator"],
                "responder": interaction["responder"],
                "interaction_type": interaction["interaction_type"],
                "interaction_type_name": type_names.get(interaction["interaction_type"], "UNKNOWN"),
                "timestamp": interaction["timestamp"],
                "link_id": interaction.get("link_id", ""),  # Changed from dashboard_link to link_id
                "weight_follower": interaction.get("weight_follower", 0),
                "weight_creator": interaction.get("weight_creator", 0),
                "tx_hash": tx_hash,  # ✅ Add tx_hash field for frontend
                "basescan_url": f"https://basescan.org/tx/{tx_hash}" if tx_hash else None
            })
        
        return {
            "address": address,
            "interactions": enhanced_interactions,
            "total": len(interactions),
            "offset": offset,
            "limit": limit
        }
        
    except Exception as e:
        log_activity("ERROR", "API", f"Blockchain interactions error: {str(e)}")
        return {"error": str(e), "interactions": []}


@app.get("/api/blockchain/stats")
async def get_blockchain_stats():
    """
    Get blockchain system statistics and health
    
    Returns:
        {
            "blockchain_health": {
                "connected": true,
                "chain_id": 8453,
                "latest_block": 12345678,
                "gas_price_gwei": 0.5
            },
            "contracts": {
                "identity_nft": "0x...",
                "resonance_score": "0x...",
                "registry": "0x..."
            },
            "stats": {
                "total_identities": 150,
                "total_interactions": 420,
                "total_score_synced": 7500
            },
            "basescan_base_url": "https://basescan.org"
        }
    """
    try:
        # Get blockchain health
        health = await web3_service.get_blockchain_health()
        
        # Get DB stats
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) as count FROM users WHERE identity_status='active'")
        total_identities = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM users WHERE blockchain_score > 0")
        users_with_score = cursor.fetchone()['count']
        
        cursor.execute("SELECT SUM(blockchain_score) as total FROM users")
        total_score_synced = cursor.fetchone()['total'] or 0
        
        conn.close()
        
        # Get interaction count (estimate from blockchain if available)
        # For now use DB follower count as proxy
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as count FROM followers WHERE follow_confirmed=1")
        total_interactions = cursor.fetchone()['count']
        conn.close()
        
        return {
            "blockchain_health": health,
            "contracts": {
                "identity_nft": os.getenv("IDENTITY_NFT_ADDRESS", ""),
                "resonance_score": os.getenv("RESONANCE_SCORE_ADDRESS", ""),
                "registry": os.getenv("REGISTRY_ADDRESS", "")
            },
            "stats": {
                "total_identities": total_identities,
                "total_interactions": total_interactions,
                "total_score_synced": total_score_synced,
                "users_with_blockchain_score": users_with_score
            },
            "basescan_base_url": "https://basescan.org"
        }
        
    except Exception as e:
        log_activity("ERROR", "API", f"Blockchain stats error: {str(e)}")
        return {"error": str(e)}


@app.post("/api/verify-token")
async def verify_token_endpoint(req: Request):
    """
    Verifiziert einen gespeicherten Token (für Auto-Login) MIT SIGNATUR-VERIFIZIERUNG
    
    Request:
        {
            "token": "address:expiry:signature",
            "address": "0x...",
            "nonce": "...",
            "message": "...",
            "signature": "0x..."
        }
    
    Response:
        {
            "valid": true,
            "address": "0x...",
            "resonance_score": 55,
            "message": "Auto-logged in"
        }
    """
    try:
        data = await req.json()
        token = data.get("token", "")
        address = data.get("address", "").lower()
        nonce = data.get("nonce", "")
        message_to_verify = data.get("message", "")
        signature = data.get("signature", "")
        
        if not token:
            return {"valid": False, "error": "No token provided"}
        
        # ===== NEUE SIGNATUR-VERIFIZIERUNG FÜR AUTO-LOGIN =====
        log_activity("INFO", "AUTH", "Auto-login with token - signature verification", address=address[:10] if address else "unknown")
        
        if not signature:
            log_activity("ERROR", "AUTH", "Auto-login: No signature provided - REJECTING", address=address[:10])
            return {"valid": False, "error": "No signature provided - MetaMask sign required for auto-login!"}
        
        if not nonce:
            log_activity("ERROR", "AUTH", "Auto-login: No nonce provided", address=address[:10])
            return {"valid": False, "error": "No nonce provided"}
        
        # Validiere Adresse
        if not address or not address.startswith("0x") or len(address) != 42:
            log_activity("ERROR", "AUTH", "Auto-login: Invalid address format", address=address[:10])
            return {"valid": False, "error": "Invalid address format"}
        
        # ===== VALIDIERE SIGNATURE MIT web3.py =====
        try:
            from eth_account.messages import encode_defunct
            from eth_account import Account
            
            message = encode_defunct(text=message_to_verify)
            
            # Verifiziere Signature
            recovered_address = Account.recover_message(message, signature=signature)
            
            if recovered_address.lower() != address:
                log_activity("ERROR", "AUTH", "Auto-login: Signature verification FAILED", address=address[:10], recovered=recovered_address[:10])
                return {"valid": False, "error": "Signature verification failed", "is_human": False}
            
            log_activity("INFO", "AUTH", "✓✓✓ Auto-login: Signature VERIFIED", address=address[:10])
            
        except ImportError:
            log_activity("WARNING", "AUTH", "Auto-login: eth_account not available - skipping signature check")
        except Exception as e:
            log_activity("ERROR", "AUTH", f"Auto-login: Signature verification error: {str(e)}", address=address[:10])
            return {"valid": False, "error": f"Signature error: {str(e)}", "is_human": False}
        
        # ===== NACH SIGNATUR-VERIFIZIERUNG: TOKEN VERIFIZIEREN =====
        result = verify_token(token)
        
        if not result["valid"]:
            return result
        
        # Validiere dass Token-Adresse mit Request-Adresse übereinstimmt
        if result["address"].lower() != address:
            log_activity("ERROR", "AUTH", "Auto-login: Address mismatch between token and request", token_addr=result["address"][:10], req_addr=address[:10])
            return {"valid": False, "error": "Address mismatch"}
        
        # Hole aktuelle Daten aus Datenbank
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE address=?", (address,))
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            return {"valid": False, "error": "User not found"}
        
        log_activity("INFO", "AUTH", "✓ Auto-login SUCCESSFUL (signature + token verified)", address=address[:10], score=user['score'])
        
        return {
            "valid": True,
            "address": address,
            "resonance_score": user['score'],
            "login_count": user['login_count'],
            "first_seen": user['first_seen'],
            "message": "Auto-logged in successfully (signature verified)"
        }
        
    except Exception as e:
        return {"valid": False, "error": str(e)}


# ============================================================================
# ===== OAUTH 2.0 + API v1 ENDPOINTS FOR THIRD-PARTY INTEGRATION =====
# ============================================================================

import jwt
import base64
from urllib.parse import urlencode, parse_qs, urlparse

# JWT Secret for OAuth tokens - MUST be an independent random secret.
# It is deliberately NOT derived from TOKEN_SECRET: deriving it would mean a
# single compromised secret breaks both the wallet-session and the OAuth layer.
OAUTH_JWT_SECRET = _require_auth_secret("OAUTH_JWT_SECRET")
if OAUTH_JWT_SECRET == TOKEN_SECRET:
    raise RuntimeError("OAUTH_JWT_SECRET must be different from TOKEN_SECRET.")
_AGENT_SECRET_PRESENT = os.getenv("AGENT_JWT_SECRET", "")
if _AGENT_SECRET_PRESENT and _AGENT_SECRET_PRESENT in (TOKEN_SECRET, OAUTH_JWT_SECRET):
    raise RuntimeError(
        "AGENT_JWT_SECRET must be different from TOKEN_SECRET and OAUTH_JWT_SECRET."
    )

# Admin key for privileged OAuth client management (/api/v1/clients/register).
# MUST be an independent secret: it previously fell back to TOKEN_SECRET, so
# knowing a wallet-session secret granted client-registration privileges.
# Reusing one secret across trust boundaries is not acceptable.
OAUTH_ADMIN_KEY = _require_auth_secret("OAUTH_ADMIN_KEY")
if OAUTH_ADMIN_KEY in (TOKEN_SECRET, OAUTH_JWT_SECRET):
    raise RuntimeError(
        "OAUTH_ADMIN_KEY must be different from TOKEN_SECRET and OAUTH_JWT_SECRET."
    )
if _AGENT_SECRET_PRESENT and OAUTH_ADMIN_KEY == _AGENT_SECRET_PRESENT:
    raise RuntimeError("OAUTH_ADMIN_KEY must be different from AGENT_JWT_SECRET.")

OAUTH_TOKEN_EXPIRY_HOURS = int(os.getenv("OAUTH_TOKEN_EXPIRY_HOURS", 24))
OAUTH_CODE_EXPIRY_SECONDS = 60  # Authorization code valid for 60 seconds

# Dashboard JWT Token Expiry (7 days for dashboard sessions)
DASHBOARD_TOKEN_EXPIRY_DAYS = 7

def generate_dashboard_jwt(address: str, has_nft: bool = False) -> str:
    """
    Generate a JWT token for dashboard authentication.
    Used for SDK app management and other dashboard features.
    """
    now = datetime.now(timezone.utc)
    payload = {
        "iss": "aeralogin.com",
        "sub": address.lower(),
        "address": address.lower(),  # For compatibility with SDK app endpoints
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(days=DASHBOARD_TOKEN_EXPIRY_DAYS)).timestamp()),
        "jti": secrets.token_hex(16),
        "has_nft": has_nft,
        "type": "dashboard"
    }
    return jwt.encode(payload, TOKEN_SECRET, algorithm="HS256")

def hash_client_secret(secret: str) -> str:
    """Hash client secret for storage"""
    return hashlib.sha256(secret.encode()).hexdigest()

def verify_client_secret(secret: str, stored_hash: str) -> bool:
    """Verify client secret against stored hash"""
    return hashlib.sha256(secret.encode()).hexdigest() == stored_hash

def generate_oauth_code() -> str:
    """Generate a secure authorization code"""
    return secrets.token_urlsafe(32)

def generate_oauth_session_token(client_id: str, address: str, score: int,
                                 has_nft: bool, jti: str = None) -> str:
    """
    Mint a signed OAuth access token (JWT).

    Pure minting only - it does NOT create the S-02 lifecycle record.
    Production code must use issue_oauth_access_token() so that minting and
    lifecycle persistence happen together.
    """
    now = datetime.now(timezone.utc)
    payload = {
        "iss": "aeralogin.com",
        "sub": address.lower(),
        "aud": client_id,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=OAUTH_TOKEN_EXPIRY_HOURS)).timestamp()),
        "jti": jti or secrets.token_hex(16),
        "score": score,
        "has_nft": has_nft,
        "chain_id": 8453
    }
    return jwt.encode(payload, OAUTH_JWT_SECRET, algorithm="HS256")


# ---------------------------------------------------------------------------
# S-02 - OAuth access-token lifecycle (issuance / revocation)
# ---------------------------------------------------------------------------
class OAuthTokenLifecycleError(Exception):
    """Raised when the lifecycle record for a token cannot be persisted."""


def issue_oauth_access_token(client_id: str, address: str, score: int,
                             has_nft: bool, cursor=None) -> str:
    """
    Mint an OAuth access token AND persist its lifecycle record.

    FAIL CLOSED: if the lifecycle row cannot be written, no token is returned.
    A token that exists without a revocation record could never be revoked,
    which is exactly the situation S-02 removes.

    When `cursor` is supplied the INSERT joins the caller's transaction, so
    issuance and persistence commit atomically together.
    """
    jti = secrets.token_hex(16)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(hours=OAUTH_TOKEN_EXPIRY_HOURS)

    row = (jti, address.lower(), client_id,
           now.isoformat(), expires_at.isoformat(), 'active')
    sql = ("INSERT INTO oauth_token_jti "
           "(jti, sub, client_id, issued_at, expires_at, status) "
           "VALUES (?, ?, ?, ?, ?, ?)")

    try:
        if cursor is not None:
            cursor.execute(sql, row)
        else:
            conn = get_db_connection()
            try:
                conn.execute(sql, row)
                conn.commit()
            finally:
                conn.close()
    except Exception as exc:
        # No lifecycle record -> no token. Never leak the exception text to
        # the caller and never log token material.
        log_activity("ERROR", "OAUTH",
                     f"Token lifecycle persistence failed for {client_id[:20]}")
        raise OAuthTokenLifecycleError("lifecycle persistence failed") from exc

    return generate_oauth_session_token(client_id, address, score, has_nft,
                                        jti=jti)


def revoke_oauth_token(jti: str, reason: str = "revoked",
                       client_id: str = None) -> bool:
    """
    Revoke a single OAuth access token by jti. Idempotent.

    When `client_id` is given the revocation only applies to a token owned by
    that client, so one client can never revoke another client's token.
    Returns True if the jti is known (and now revoked), False if unknown.
    """
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        if client_id:
            existing = cur.execute(
                "SELECT status FROM oauth_token_jti WHERE jti = ? AND client_id = ?",
                (jti, client_id)).fetchone()
        else:
            existing = cur.execute(
                "SELECT status FROM oauth_token_jti WHERE jti = ?",
                (jti,)).fetchone()
        if existing is None:
            return False
        if existing["status"] == "revoked":
            return True  # idempotent - keep the original revocation metadata
        cur.execute(
            "UPDATE oauth_token_jti SET status = 'revoked', revoked_at = ?, "
            "revocation_reason = ? WHERE jti = ?",
            (datetime.now(timezone.utc).isoformat(), reason, jti))
        conn.commit()
        return True
    finally:
        conn.close()


def revoke_oauth_tokens_for_client(client_id: str,
                                   reason: str = "client_disabled") -> int:
    """Revoke every active token bound to a client. Returns rows affected."""
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE oauth_token_jti SET status = 'revoked', revoked_at = ?, "
            "revocation_reason = ? WHERE client_id = ? AND status = 'active'",
            (datetime.now(timezone.utc).isoformat(), reason, client_id))
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


def revoke_oauth_tokens_for_subject(address: str,
                                    reason: str = "subject_revoked") -> int:
    """Revoke every active token issued for a wallet. Returns rows affected."""
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE oauth_token_jti SET status = 'revoked', revoked_at = ?, "
            "revocation_reason = ? WHERE sub = ? AND status = 'active'",
            (datetime.now(timezone.utc).isoformat(), reason, address.lower()))
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# N3 - strict OAuth access-token verification (issuer + audience)
# ---------------------------------------------------------------------------
# The single producer of OAUTH_JWT_SECRET tokens is
# generate_oauth_session_token() above. It always emits:
#     iss = "aeralogin.com"   (fixed)
#     aud = <client_id>       (client-specific, always a plain string)
# The verifier below enforces exactly that contract. Expected values come
# from server-side configuration / the client registry only - NEVER from the
# incoming request.
OAUTH_EXPECTED_ISSUER = "aeralogin.com"

# Claims that a legitimate AEra OAuth access token always carries.
OAUTH_REQUIRED_CLAIMS = ["iss", "sub", "aud", "iat", "exp", "jti"]


def _is_registered_active_client(client_id: str) -> bool:
    """True if client_id is a currently active, registered OAuth client."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT 1 FROM oauth_clients WHERE client_id = ? AND is_active = 1",
            (client_id,),
        )
        row = cursor.fetchone()
        conn.close()
        return row is not None
    except Exception:
        # Fail closed: if the registry cannot be consulted we do not trust
        # the audience.
        return False


def verify_oauth_access_token(token: str, expected_client_id: str = None) -> dict:
    """
    Strictly verify an AEra OAuth access token.

    Always enforced:
      * HS256 signature under OAUTH_JWT_SECRET (no other algorithm, no "none")
      * iss == OAUTH_EXPECTED_ISSUER
      * exp / iat
      * presence of all OAUTH_REQUIRED_CLAIMS
      * aud is a single string (never a list - the producer never emits one,
        and accepting a list would silently widen the trust boundary)

    Audience binding:
      * expected_client_id given  -> aud must equal it exactly. Used wherever
        the caller's identity is known (authenticated client, or explicit
        opt-in via X-AEra-Client-Id).
      * expected_client_id None   -> aud must be a registered, ACTIVE
        client_id. This rejects arbitrary / attacker-invented audiences and
        revoked clients while remaining compatible with existing publisher
        integrations that do not transmit their client_id.

    Raises jwt.InvalidTokenError (or a subclass) on every failure.
    """
    options = {
        "require": OAUTH_REQUIRED_CLAIMS,
        "verify_signature": True,
        "verify_exp": True,
        "verify_iat": True,
        "verify_iss": True,
    }

    if expected_client_id:
        payload = jwt.decode(
            token,
            OAUTH_JWT_SECRET,
            algorithms=["HS256"],
            issuer=OAUTH_EXPECTED_ISSUER,
            audience=expected_client_id,
            options=options,
        )
    else:
        payload = jwt.decode(
            token,
            OAUTH_JWT_SECRET,
            algorithms=["HS256"],
            issuer=OAUTH_EXPECTED_ISSUER,
            options={**options, "verify_aud": False},
        )

    aud = payload.get("aud")
    if not isinstance(aud, str) or not aud:
        raise jwt.InvalidAudienceError(
            "audience must be a single registered client_id"
        )

    if expected_client_id:
        # Defence in depth: PyJWT already matched, but a list audience
        # containing the expected value would have passed there.
        if aud != expected_client_id:
            raise jwt.InvalidAudienceError("audience does not match client")
    elif not _is_registered_active_client(aud):
        raise jwt.InvalidAudienceError(
            "audience is not a registered active client"
        )

    # ---- S-02: server-side lifecycle -------------------------------------
    # The token must correspond to a known, active lifecycle record whose
    # stored binding matches the claims. Verification NEVER creates a record.
    jti = payload.get("jti")
    if not isinstance(jti, str) or not jti:
        raise jwt.InvalidTokenError("missing jti")

    conn = get_db_connection()
    try:
        row = conn.execute(
            "SELECT sub, client_id, expires_at, status "
            "FROM oauth_token_jti WHERE jti = ?", (jti,)).fetchone()
    finally:
        conn.close()

    if row is None:
        raise jwt.InvalidTokenError("unknown token")
    if row["status"] != "active":
        raise jwt.InvalidTokenError("revoked token")

    # Binding: the persisted record is authoritative. A forged claim that
    # survived signature verification (it cannot, but defence in depth) must
    # still disagree with the stored record.
    if (row["sub"] or "").lower() != (payload.get("sub") or "").lower():
        raise jwt.InvalidTokenError("subject mismatch")
    if row["client_id"] != aud:
        raise jwt.InvalidTokenError("client binding mismatch")

    try:
        record_exp = datetime.fromisoformat(row["expires_at"])
        if record_exp.tzinfo is None:
            record_exp = record_exp.replace(tzinfo=timezone.utc)
        if record_exp <= datetime.now(timezone.utc):
            raise jwt.ExpiredSignatureError("lifecycle record expired")
    except (TypeError, ValueError):
        raise jwt.InvalidTokenError("invalid lifecycle record")

    # Cascade: a disabled client must not authenticate, even on the strict
    # path where the audience was matched against expected_client_id.
    if expected_client_id and not _is_registered_active_client(aud):
        raise jwt.InvalidAudienceError("client is no longer active")

    return payload


@app.get("/oauth/authorize", response_class=HTMLResponse)
async def oauth_authorize(
    request: Request,
    client_id: str = None,
    redirect_uri: str = None,
    state: str = None,
    response_type: str = "code"
):
    """
    OAuth 2.0 Authorization Endpoint
    
    Redirects user to AEra login flow, then back to publisher with authorization code.
    
    Parameters:
        client_id: Registered OAuth client ID
        redirect_uri: Where to redirect after authorization
        state: CSRF protection state parameter
        response_type: Only "code" is supported
    """
    if not client_id or not redirect_uri:
        return HTMLResponse(content="""
            <html><body style="font-family: sans-serif; text-align: center; padding: 50px;">
                <h1>❌ Invalid Request</h1>
                <p>Missing required parameters: client_id and redirect_uri</p>
            </body></html>
        """, status_code=400)
    
    # Validate client_id
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM oauth_clients WHERE client_id = ? AND is_active = 1", (client_id,))
    client = cursor.fetchone()
    conn.close()
    
    if not client:
        log_activity("WARNING", "OAUTH", f"Invalid client_id: {client_id[:20]}")
        return HTMLResponse(content="""
            <html><body style="font-family: sans-serif; text-align: center; padding: 50px;">
                <h1>❌ Unknown Application</h1>
                <p>This application is not registered with AEraLogIn.</p>
            </body></html>
        """, status_code=400)
    
    # Validate redirect_uri against whitelist
    allowed_uris = json.loads(client['redirect_uris'])
    if redirect_uri not in allowed_uris:
        log_activity("WARNING", "OAUTH", f"Invalid redirect_uri for {client_id}: {redirect_uri[:50]}")
        return HTMLResponse(content="""
            <html><body style="font-family: sans-serif; text-align: center; padding: 50px;">
                <h1>❌ Invalid Redirect URI</h1>
                <p>The redirect URI is not authorized for this application.</p>
            </body></html>
        """, status_code=400)
    
    # Store authorization request in session and redirect to dashboard for login
    nonce = secrets.token_hex(16)
    
    # Store pending authorization in database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO oauth_codes (code, client_id, address, redirect_uri, state, nonce, created_at, expires_at, used)
        VALUES (?, ?, '', ?, ?, ?, ?, ?, 0)
    """, (
        nonce,  # Use nonce as temporary code placeholder
        client_id,
        redirect_uri,
        state or '',
        nonce,
        datetime.now(timezone.utc).isoformat(),
        (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
    ))
    conn.commit()
    conn.close()
    
    # Redirect to a special OAuth login page
    oauth_params = urlencode({
        'oauth_nonce': nonce,
        'client_name': client['client_name'],
        'redirect_uri': redirect_uri
    })
    
    return HTMLResponse(content=f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Sign in with AEraLogIn</title>
            <style>
                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Inter', sans-serif;
                    background: linear-gradient(135deg, #050814 0%, #0a0e27 100%);
                    color: #f0f4ff;
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }}
                .container {{
                    background: rgba(255, 255, 255, 0.05);
                    border: 1px solid rgba(255, 255, 255, 0.1);
                    border-radius: 20px;
                    padding: 3rem;
                    max-width: 450px;
                    text-align: center;
                    backdrop-filter: blur(10px);
                }}
                .logo {{ font-size: 4rem; margin-bottom: 1rem; }}
                h1 {{ font-size: 1.8rem; margin-bottom: 0.5rem; }}
                .client-name {{
                    color: #00d4ff;
                    font-weight: 600;
                    font-size: 1.2rem;
                    margin-bottom: 2rem;
                }}
                .info {{
                    background: rgba(0, 212, 255, 0.1);
                    border: 1px solid #00d4ff;
                    border-radius: 12px;
                    padding: 1rem;
                    margin-bottom: 2rem;
                    font-size: 0.9rem;
                }}
                .button {{
                    background: linear-gradient(135deg, #0052ff, #6366f1);
                    color: white;
                    border: none;
                    padding: 1rem 2rem;
                    border-radius: 12px;
                    font-size: 1.1rem;
                    font-weight: 600;
                    cursor: pointer;
                    width: 100%;
                    margin-bottom: 1rem;
                }}
                .button:hover {{ transform: translateY(-2px); box-shadow: 0 10px 30px rgba(0, 82, 255, 0.4); }}
                .cancel {{ background: rgba(255, 255, 255, 0.1); }}
                #status {{ margin-top: 1rem; padding: 1rem; border-radius: 8px; display: none; }}
                .status-error {{ background: rgba(239, 68, 68, 0.2); border: 1px solid #ef4444; }}
                .status-success {{ background: rgba(16, 185, 129, 0.2); border: 1px solid #10b981; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="logo">🌀</div>
                <h1>Sign in with AEraLogIn</h1>
                <p class="client-name">{client['client_name']}</p>
                
                <div class="info">
                    <p>🔐 This application wants to verify your identity using your AEra Identity NFT.</p>
                    <p style="margin-top: 0.5rem; opacity: 0.8;">Requirements: Identity NFT + Min Score: {client['min_score']}</p>
                </div>
                
                <button class="button" onclick="connectWallet()">🦊 Connect Wallet</button>
                <button class="button cancel" onclick="window.close()">Cancel</button>
                
                <div id="status"></div>
            </div>
            
            <script>
                const API_BASE = window.location.origin;
                const oauthNonce = '{nonce}';
                const redirectUri = '{redirect_uri}';
                const state = '{state or ""}';
                const minScore = {client['min_score']};
                const requireNFT = {str(client['require_nft']).lower()};
                
                function showStatus(msg, type) {{
                    const status = document.getElementById('status');
                    status.textContent = msg;
                    status.className = 'status-' + type;
                    status.style.display = 'block';
                }}
                
                /**
                 * Robust wallet signing with multiple fallback strategies
                 * Handles different wallet implementations (MetaMask, Coinbase, Base, Rainbow, etc.)
                 * 
                 * Strategy Order:
                 * 1. Base Wallet SIWE Capabilities (wallet_connect with signInWithEthereum)
                 * 2. Standard personal_sign [message, address] (MetaMask, Rainbow, Trust)
                 * 3. Reversed personal_sign [address, message] (some Coinbase versions)
                 * 4. Hex-encoded personal_sign (fallback)
                 */
                async function robustWalletSign(message, address) {{
                    const ua = navigator.userAgent.toLowerCase();
                    const isBaseWallet = ua.includes('base') || 
                                         ua.includes('coinbasewallet') || 
                                         (window.ethereum && window.ethereum.isCoinbaseWallet);
                    
                    console.log('[OAuth] Attempting signature (Base/Coinbase detected:', isBaseWallet, ')');
                    
                    // Extract nonce from SIWE message
                    const nonceMatch = message.match(/Nonce: ([a-zA-Z0-9]+)/);
                    const nonce = nonceMatch ? nonceMatch[1] : Date.now().toString();
                    
                    // ========================================
                    // STRATEGY 1: Base Wallet SIWE Capabilities
                    // ========================================
                    if (isBaseWallet && window.ethereum) {{
                        try {{
                            console.log('[OAuth] Trying Base Wallet SIWE Capabilities...');
                            const result = await window.ethereum.request({{
                                method: 'wallet_connect',
                                params: [{{
                                    version: '1',
                                    capabilities: {{
                                        signInWithEthereum: {{
                                            nonce: nonce,
                                            chainId: '0x2105'  // Base Mainnet (8453)
                                        }}
                                    }}
                                }}]
                            }});
                            
                            if (result && result.signature) {{
                                console.log('[OAuth] ✅ Base Wallet SIWE successful!');
                                return result.signature;
                            }}
                        }} catch (siweError) {{
                            console.log('[OAuth] Base SIWE not supported:', siweError.message);
                        }}
                    }}
                    
                    // ========================================
                    // STRATEGY 2: Standard personal_sign [message, address]
                    // ========================================
                    try {{
                        console.log('[OAuth] Trying standard personal_sign...');
                        const signature = await window.ethereum.request({{
                            method: 'personal_sign',
                            params: [message, address]
                        }});
                        if (signature) {{
                            console.log('[OAuth] ✅ Standard personal_sign successful!');
                            return signature;
                        }}
                    }} catch (error1) {{
                        console.log('[OAuth] Standard method failed:', error1.message);
                        
                        // ========================================
                        // STRATEGY 3: Reversed personal_sign [address, message]
                        // ========================================
                        try {{
                            console.log('[OAuth] Trying reversed personal_sign...');
                            const signature = await window.ethereum.request({{
                                method: 'personal_sign',
                                params: [address, message]
                            }});
                            if (signature) {{
                                console.log('[OAuth] ✅ Reversed personal_sign successful!');
                                return signature;
                            }}
                        }} catch (error2) {{
                            console.log('[OAuth] Reversed method failed:', error2.message);
                            
                            // ========================================
                            // STRATEGY 4: Hex-encoded personal_sign
                            // ========================================
                            try {{
                                console.log('[OAuth] Trying hex-encoded personal_sign...');
                                const hexMessage = '0x' + Array.from(new TextEncoder().encode(message))
                                    .map(b => b.toString(16).padStart(2, '0')).join('');
                                const signature = await window.ethereum.request({{
                                    method: 'personal_sign',
                                    params: [hexMessage, address]
                                }});
                                if (signature) {{
                                    console.log('[OAuth] ✅ Hex-encoded personal_sign successful!');
                                    return signature;
                                }}
                            }} catch (error3) {{
                                console.log('[OAuth] All signature methods failed');
                                throw new Error(`Signature rejected: ${{error1.message}}`);
                            }}
                        }}
                    }}
                    
                    throw new Error('No signature received');
                }}
                
                async function connectWallet() {{
                    if (!window.ethereum) {{
                        showStatus('❌ No Web3 wallet found. Please install MetaMask or use a wallet browser.', 'error');
                        return;
                    }}
                    
                    try {{
                        showStatus('⏳ Connecting wallet...', 'success');
                        
                        // Request wallet connection
                        const accounts = await window.ethereum.request({{ method: 'eth_requestAccounts' }});
                        const address = accounts[0].toLowerCase();
                        
                        // Get nonce from backend
                        const nonceResp = await fetch(`${{API_BASE}}/api/nonce`, {{
                            method: 'POST',
                            headers: {{ 'Content-Type': 'application/json' }},
                            body: JSON.stringify({{ address }})
                        }});
                        const nonceData = await nonceResp.json();
                        if (!nonceData.success) throw new Error('Failed to get nonce');
                        
                        // Build SIWE message
                        const domain = window.location.host;
                        const uri = window.location.origin;
                        const issuedAt = new Date().toISOString();
                        const messageToSign = `${{domain}} wants you to sign in with your Ethereum account:
${{address}}

Sign in to AEraLogIn for third-party authorization

URI: ${{uri}}
Version: 1
Chain ID: 8453
Nonce: ${{nonceData.nonce}}
Issued At: ${{issuedAt}}`;
                        
                        showStatus('⏳ Please sign the message in your wallet...', 'success');
                        
                        // ========================================
                        // ROBUST WALLET SIGNING (Multi-Strategy)
                        // ========================================
                        const signature = await robustWalletSign(messageToSign, address);
                        
                        showStatus('⏳ Verifying identity...', 'success');
                        
                        // Complete OAuth flow
                        const oauthResp = await fetch(`${{API_BASE}}/oauth/complete`, {{
                            method: 'POST',
                            headers: {{ 'Content-Type': 'application/json' }},
                            body: JSON.stringify({{
                                oauth_nonce: oauthNonce,
                                address: address,
                                nonce: nonceData.nonce,
                                message: messageToSign,
                                signature: signature
                            }})
                        }});
                        
                        const oauthData = await oauthResp.json();
                        
                        if (!oauthData.success) {{
                            throw new Error(oauthData.error || 'Authorization failed');
                        }}
                        
                        showStatus('✅ Authorized! Redirecting...', 'success');
                        
                        // Redirect back to publisher with authorization code
                        setTimeout(() => {{
                            const params = new URLSearchParams();
                            params.set('code', oauthData.code);
                            if (state) params.set('state', state);
                            window.location.href = redirectUri + '?' + params.toString();
                        }}, 1000);
                        
                    }} catch (error) {{
                        console.error('OAuth error:', error);
                        if (error.code === 4001) {{
                            showStatus('❌ You rejected the wallet signature.', 'error');
                        }} else {{
                            showStatus('❌ ' + error.message, 'error');
                        }}
                    }}
                }}
            </script>
        </body>
        </html>
    """)


@app.post("/oauth/complete")
async def oauth_complete(req: Request):
    """
    Complete OAuth authorization after wallet signature
    
    ✅ FIXED: Now supports Smart Contract Wallets (EIP-1271)
    
    Request:
        {{
            "oauth_nonce": "...",
            "address": "0x...",
            "nonce": "...",
            "message": "...",
            "signature": "0x..."
        }}
    
    Response:
        {{
            "success": true,
            "code": "authorization_code"
        }}
    """
    try:
        data = await req.json()
        oauth_nonce = data.get("oauth_nonce", "")
        address = data.get("address", "").lower()
        nonce = data.get("nonce", "")
        message = data.get("message", "")
        signature = data.get("signature", "")
        
        if not all([oauth_nonce, address, nonce, message, signature]):
            return {"success": False, "error": "Missing required parameters"}
        
        # Find pending authorization
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT oc.*, c.min_score, c.require_nft 
            FROM oauth_codes oc
            JOIN oauth_clients c ON oc.client_id = c.client_id
            WHERE oc.nonce = ? AND oc.used = 0 AND oc.expires_at > ?
        """, (oauth_nonce, datetime.now(timezone.utc).isoformat()))
        pending = cursor.fetchone()
        
        if not pending:
            conn.close()
            return {"success": False, "error": "Invalid or expired authorization request"}
        
        # ========================================
        # ENHANCED SIGNATURE VERIFICATION
        # Supports: EOA, Smart Contract Wallets (EIP-1271), BASE Wallet
        # ========================================
        signature_valid = False
        
        # Detect Smart Contract Wallet signature (EIP-6492)
        # These signatures are much longer than 65 bytes
        is_smart_wallet_sig = len(signature) > 200 if signature else False
        
        log_activity("INFO", "OAUTH", f"Signature verification start", 
                    address=address[:10],
                    sig_length=len(signature) if signature else 0,
                    is_smart_wallet=is_smart_wallet_sig)
        
        try:
            from eth_account.messages import encode_defunct, defunct_hash_message
            from eth_account import Account
            
            # ========================================
            # SMART CONTRACT WALLET (EIP-1271) VERIFICATION
            # Coinbase Smart Wallet, Safe, Base Wallet, etc.
            # ========================================
            if is_smart_wallet_sig and message and nonce in message:
                log_activity("INFO", "OAUTH", f"Attempting EIP-1271 Smart Contract Wallet verification...")
                try:
                    from web3 import Web3
                    
                    # Connect to BASE mainnet via Alchemy (faster)
                    alchemy_url = os.getenv("BASE_ALCHEMY_API_URL") or os.getenv("BASE_RPC_URL", "https://mainnet.base.org")
                    w3 = Web3(Web3.HTTPProvider(alchemy_url))
                    
                    # EIP-1271 ABI - just the isValidSignature function
                    EIP1271_ABI = [
                        {
                            "inputs": [
                                {"name": "_hash", "type": "bytes32"},
                                {"name": "_signature", "type": "bytes"}
                            ],
                            "name": "isValidSignature",
                            "outputs": [{"name": "", "type": "bytes4"}],
                            "stateMutability": "view",
                            "type": "function"
                        }
                    ]
                    
                    # Hash the message (EIP-191 personal sign format)
                    message_hash = defunct_hash_message(text=message)
                    log_activity("INFO", "OAUTH", f"Message hash: {message_hash.hex()[:20]}...")
                    
                    # Create contract instance
                    wallet_contract = w3.eth.contract(
                        address=Web3.to_checksum_address(address),
                        abi=EIP1271_ABI
                    )
                    
                    # Convert signature to bytes
                    sig_bytes = bytes.fromhex(signature[2:]) if signature.startswith('0x') else bytes.fromhex(signature)
                    
                    # Call isValidSignature on the smart contract wallet
                    try:
                        result = wallet_contract.functions.isValidSignature(
                            message_hash,
                            sig_bytes
                        ).call()
                        
                        # EIP-1271 magic value for valid signature
                        MAGIC_VALUE = bytes.fromhex('1626ba7e')
                        
                        if result == MAGIC_VALUE:
                            signature_valid = True
                            log_activity("INFO", "OAUTH", f"✅ EIP-1271 Smart Contract Wallet verification SUCCESS!")
                        else:
                            log_activity("INFO", "OAUTH", f"EIP-1271 returned: {result.hex()} (expected 1626ba7e)")
                    except Exception as contract_error:
                        log_activity("INFO", "OAUTH", f"EIP-1271 contract call failed: {str(contract_error)}")
                        
                except Exception as eip1271_error:
                    log_activity("INFO", "OAUTH", f"EIP-1271 verification error: {str(eip1271_error)}")
            
            # ========================================
            # STANDARD EOA SIGNATURE VERIFICATION
            # MetaMask, Rainbow, Trust, etc.
            # ========================================
            if not signature_valid:
                # If frontend sent the message, use it directly
                if message and nonce in message:
                    try:
                        msg = encode_defunct(text=message)
                        recovered = Account.recover_message(msg, signature=signature)
                        
                        if recovered.lower() == address:
                            signature_valid = True
                            log_activity("INFO", "OAUTH", f"✅ EOA signature verification SUCCESS")
                        else:
                            log_activity("ERROR", "OAUTH", f"Signature verification FAILED", 
                                       address=address[:10], 
                                       recovered=recovered[:10])
                    except Exception as e:
                        log_activity("ERROR", "OAUTH", f"EOA verification error: {str(e)}")
            
            if not signature_valid:
                conn.close()
                return {"success": False, "error": "Signature verification failed - wallet signature invalid"}
            
            # 🔐 SIWE: Also verify nonce is in the message (anti-replay)
            if message and nonce not in message:
                conn.close()
                log_activity("ERROR", "OAUTH", "SIWE nonce mismatch", address=address[:10])
                return {"success": False, "error": "Nonce mismatch in SIWE message"}
                
        except Exception as e:
            conn.close()
            log_activity("ERROR", "OAUTH", f"Signature verification error: {str(e)}", address=address[:10])
            return {"success": False, "error": f"Signature error: {str(e)}"}
        
        # Check user exists and meets requirements
        cursor.execute("SELECT * FROM users WHERE address = ?", (address,))
        user = cursor.fetchone()
        
        if not user:
            # Create user if doesn't exist (triggers NFT minting)
            conn.close()
            return {"success": False, "error": "Please register on AEraLogIn dashboard first to get your Identity NFT"}
        
        # Check NFT requirement (using identity_status from users table)
        if pending['require_nft']:
            if user['identity_status'] != 'active':
                conn.close()
                return {"success": False, "error": "Identity NFT required. Please mint your NFT on the dashboard first."}
        
        # Check score requirement
        if user['score'] < pending['min_score']:
            conn.close()
            return {"success": False, "error": f"Minimum Resonance Score of {pending['min_score']} required. Your score: {user['score']}"}
        
        # Generate authorization code
        auth_code = generate_oauth_code()
        
        # Update the authorization record with actual data
        cursor.execute("""
            UPDATE oauth_codes 
            SET code = ?, address = ?, created_at = ?, expires_at = ?
            WHERE nonce = ?
        """, (
            auth_code,
            address,
            datetime.now(timezone.utc).isoformat(),
            (datetime.now(timezone.utc) + timedelta(seconds=OAUTH_CODE_EXPIRY_SECONDS)).isoformat(),
            oauth_nonce
        ))
        conn.commit()
        conn.close()
        
        log_activity("INFO", "OAUTH", f"✅ Authorization code generated for {address[:10]}", client_id=pending['client_id'])
        
        return {"success": True, "code": auth_code}
        
    except Exception as e:
        log_activity("ERROR", "OAUTH", f"OAuth complete error: {str(e)}")
        return {"success": False, "error": str(e)}


@app.post("/oauth/token")
async def oauth_token(req: Request):
    """
    OAuth 2.0 Token Endpoint
    
    Exchange authorization code for access token.
    
    Request (application/json or application/x-www-form-urlencoded):
        {{
            "grant_type": "authorization_code",
            "code": "...",
            "redirect_uri": "...",
            "client_id": "...",
            "client_secret": "..."
        }}
    
    Response:
        {{
            "access_token": "jwt...",
            "token_type": "Bearer",
            "expires_in": 86400,
            "wallet": "0x...",
            "score": 55,
            "has_nft": true
        }}
    """
    try:
        # Support both JSON and form-urlencoded
        content_type = req.headers.get("content-type", "")
        if "application/json" in content_type:
            data = await req.json()
        else:
            body = await req.body()
            data = dict(parse_qs(body.decode()))
            data = {k: v[0] if isinstance(v, list) else v for k, v in data.items()}
        
        grant_type = data.get("grant_type", "")
        code = data.get("code", "")
        redirect_uri = data.get("redirect_uri", "")
        client_id = data.get("client_id", "")
        client_secret = data.get("client_secret", "")
        
        if grant_type != "authorization_code":
            return {"error": "unsupported_grant_type", "error_description": "Only authorization_code grant is supported"}
        
        if not all([code, redirect_uri, client_id, client_secret]):
            return {"error": "invalid_request", "error_description": "Missing required parameters"}
        
        # Validate client credentials
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM oauth_clients WHERE client_id = ? AND is_active = 1", (client_id,))
        client = cursor.fetchone()
        
        if not client:
            conn.close()
            return {"error": "invalid_client", "error_description": "Unknown client"}
        
        if hash_client_secret(client_secret) != client['client_secret_hash']:
            conn.close()
            log_activity("WARNING", "OAUTH", f"Invalid client_secret for {client_id}")
            return {"error": "invalid_client", "error_description": "Invalid client credentials"}
        
        # Validate authorization code
        cursor.execute("""
            SELECT * FROM oauth_codes 
            WHERE code = ? AND client_id = ? AND redirect_uri = ? AND used = 0 AND expires_at > ?
        """, (code, client_id, redirect_uri, datetime.now(timezone.utc).isoformat()))
        auth_code = cursor.fetchone()
        
        if not auth_code:
            conn.close()
            return {"error": "invalid_grant", "error_description": "Invalid or expired authorization code"}
        
        # Mark code as used
        cursor.execute("UPDATE oauth_codes SET used = 1 WHERE code = ?", (code,))
        
        # Get user data
        cursor.execute("SELECT * FROM users WHERE address = ?", (auth_code['address'],))
        user = cursor.fetchone()
        
        # Check NFT status (using identity_status from users table)
        has_nft = user and user['identity_status'] == 'active'
        
        # Generate session token together with its S-02 lifecycle record.
        # The INSERT joins this transaction, so the token and its revocation
        # record commit atomically. On failure nothing is returned.
        try:
            access_token = issue_oauth_access_token(
                client_id=client_id,
                address=auth_code['address'],
                score=user['score'] if user else 0,
                has_nft=has_nft,
                cursor=cursor,
            )
        except OAuthTokenLifecycleError:
            conn.rollback()
            conn.close()
            return {"error": "server_error",
                    "error_description": "Token issuance failed"}
        
        # Store session
        session_id = secrets.token_hex(16)
        cursor.execute("""
            INSERT INTO oauth_sessions (session_id, client_id, address, score, has_nft, created_at, expires_at, is_active)
            VALUES (?, ?, ?, ?, ?, ?, ?, 1)
        """, (
            session_id,
            client_id,
            auth_code['address'],
            user['score'] if user else 0,
            has_nft,
            datetime.now(timezone.utc).isoformat(),
            (datetime.now(timezone.utc) + timedelta(hours=OAUTH_TOKEN_EXPIRY_HOURS)).isoformat()
        ))
        conn.commit()
        conn.close()
        
        log_activity("INFO", "OAUTH", f"Token issued for {auth_code['address'][:10]}", client_id=client_id)
        
        # Build response
        token_response = {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": OAUTH_TOKEN_EXPIRY_HOURS * 3600,
            "wallet": auth_code['address'],
            "score": user['score'] if user else 0,
            "has_nft": has_nft
        }
        
        # N10: the previous debug block printed the access token prefix
        # (JWT header + start of payload) and every response field to stdout,
        # where systemd captures it in the journal. Removed - no OAuth token
        # material is written to stdout/journal any more.
        # Operational visibility is already covered by the log_activity()
        # call above ("Token issued for <addr-prefix>", client_id), so no
        # replacement logging is introduced here.
        return token_response
        
    except Exception as e:
        log_activity("ERROR", "OAUTH", f"Token exchange error: {str(e)}")
        return {"error": "server_error", "error_description": str(e)}


@app.post("/api/v1/verify")
async def api_v1_verify(req: Request):
    """
    API v1: Verify AEra Session Token
    
    Used by publishers to verify user authentication server-side.
    
    Request:
        Headers:
            Authorization: Bearer <aera_session_token>
    
    Response:
        {{
            "valid": true,
            "wallet": "0x...",
            "score": 42,
            "has_nft": true,
            "chain_id": 8453,
            "issued_at": "2025-01-01T00:00:00Z",
            "expires_at": "2025-01-02T00:00:00Z"
        }}
    """
    try:
        # Get token from Authorization header
        auth_header = req.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return {"valid": False, "authenticated": False, "error": "Missing or invalid Authorization header"}
        
        token = auth_header[7:]  # Remove "Bearer " prefix
        
        # N3: strict issuer + audience validation.
        # Callers that know their own client_id SHOULD send it via the
        # X-AEra-Client-Id header (or a client_id JSON field); the token is
        # then bound to that client exactly. Callers that do not send it keep
        # working, but the audience must still be a registered active client.
        expected_client_id = req.headers.get("X-AEra-Client-Id") or None
        if not expected_client_id:
            try:
                body = await req.json()
                if isinstance(body, dict):
                    expected_client_id = body.get("client_id") or None
            except Exception:
                expected_client_id = None

        try:
            payload = verify_oauth_access_token(
                token, expected_client_id=expected_client_id
            )
        except jwt.ExpiredSignatureError:
            return {"valid": False, "authenticated": False, "error": "Token expired"}
        except jwt.InvalidTokenError:
            return {"valid": False, "authenticated": False, "error": "Invalid token"}
        
        # Get fresh user data
        address = payload.get("sub", "")
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE address = ?", (address,))
        user = cursor.fetchone()
        conn.close()
        
        # Check NFT status using identity_status from users table
        has_nft = user and user['identity_status'] == 'active'
        
        return {
            "valid": True,
            "authenticated": True,  # Alias for compatibility
            "wallet": address,
            "score": user['score'] if user else payload.get("score", 0),
            "has_nft": has_nft,
            "chain_id": payload.get("chain_id", 8453),
            "issued_at": datetime.fromtimestamp(payload.get("iat", 0), tz=timezone.utc).isoformat(),
            "expires_at": datetime.fromtimestamp(payload.get("exp", 0), tz=timezone.utc).isoformat(),
            "client_id": payload.get("aud"),
            "jti": payload.get("jti")
        }
        
    except Exception as e:
        log_activity("ERROR", "API", f"v1/verify error: {str(e)}")
        return {"valid": False, "authenticated": False, "error": str(e)}


@app.post("/api/v1/clients/register")
async def register_oauth_client(req: Request):
    """
    Register a new OAuth client (for development/admin use)
    
    Request:
        {{
            "admin_key": "...",
            "client_name": "My App",
            "redirect_uris": ["https://myapp.com/callback"],
            "allowed_origins": ["https://myapp.com"],
            "min_score": 0,
            "require_nft": true
        }}
    
    Response:
        {{
            "success": true,
            "client_id": "...",
            "client_secret": "..."
        }}
    """
    try:
        data = await req.json()
        admin_key = data.get("admin_key", "")
        
        # Admin key check. OAUTH_ADMIN_KEY is a mandatory, independent secret
        # (validated at startup). It deliberately has NO fallback to
        # TOKEN_SECRET any more. Compared in constant time.
        if not admin_key or not hmac.compare_digest(str(admin_key), OAUTH_ADMIN_KEY):
            return {"success": False, "error": "Invalid admin key"}
        
        client_name = data.get("client_name", "")
        redirect_uris = data.get("redirect_uris", [])
        allowed_origins = data.get("allowed_origins", [])
        min_score = data.get("min_score", 0)
        require_nft = data.get("require_nft", True)
        
        if not client_name or not redirect_uris:
            return {"success": False, "error": "client_name and redirect_uris are required"}
        
        # Generate credentials
        client_id = "aera_" + secrets.token_hex(16)
        client_secret = secrets.token_urlsafe(32)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO oauth_clients (client_id, client_secret_hash, client_name, redirect_uris, allowed_origins, min_score, require_nft, created_at, is_active)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
        """, (
            client_id,
            hash_client_secret(client_secret),
            client_name,
            json.dumps(redirect_uris),
            json.dumps(allowed_origins),
            min_score,
            require_nft,
            datetime.now(timezone.utc).isoformat()
        ))
        conn.commit()
        conn.close()
        
        log_activity("INFO", "OAUTH", f"New client registered: {client_name}", client_id=client_id)
        
        return {
            "success": True,
            "client_id": client_id,
            "client_secret": client_secret,
            "message": "Store the client_secret securely - it cannot be retrieved later!"
        }
        
    except Exception as e:
        log_activity("ERROR", "OAUTH", f"Client registration error: {str(e)}")
        return {"success": False, "error": str(e)}


@app.post("/api/oauth/verify-nft")
async def oauth_verify_nft(req: Request):
    """
    🔐 OAuth NFT Verification Endpoint for Third-Party Integration
    
    Allows registered OAuth clients to verify a user's NFT ownership
    using their client credentials.
    
    Request:
        {
            "access_token": "user's access token",
            "client_id": "your_client_id",
            "client_secret": "your_client_secret"
        }
    
    Response (success):
        {
            "valid": true,
            "wallet": "0x...",
            "has_nft": true,
            "score": 42,
            "chain_id": 8453
        }
    
    Response (failure):
        {
            "valid": false,
            "error": "Invalid credentials"
        }
    """
    try:
        data = await req.json()
        access_token = data.get("access_token", "")
        client_id = data.get("client_id", "")
        client_secret = data.get("client_secret", "")
        
        if not access_token or not client_id or not client_secret:
            return {"valid": False, "error": "Missing required fields"}
        
        # Verify client credentials
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM oauth_clients WHERE client_id = ? AND is_active = 1", (client_id,))
        client = cursor.fetchone()
        
        if not client:
            conn.close()
            log_activity("WARNING", "OAUTH", f"Invalid client_id: {client_id[:20]}")
            return {"valid": False, "error": "Invalid client credentials"}
        
        # Verify client secret
        if not verify_client_secret(client_secret, client['client_secret_hash']):
            conn.close()
            log_activity("WARNING", "OAUTH", f"Invalid client_secret for: {client_id[:20]}")
            return {"valid": False, "error": "Invalid client credentials"}
        
        # N3: the caller has just proven which client it is, so the token
        # MUST be bound to that same client. This closes cross-client token
        # confusion (a token minted for client A replayed by client B).
        try:
            payload = verify_oauth_access_token(
                access_token, expected_client_id=client_id
            )
        except jwt.ExpiredSignatureError:
            conn.close()
            return {"valid": False, "error": "Token expired"}
        except jwt.InvalidTokenError:
            conn.close()
            log_activity("WARNING", "OAUTH",
                         f"Rejected token for client {client_id[:20]}")
            return {"valid": False, "error": "Invalid token"}
        
        address = payload.get("sub", "")
        
        # Get fresh NFT status
        has_nft = await web3_service.has_identity_nft(address)
        
        # Get user score
        cursor.execute("SELECT score FROM users WHERE LOWER(address) = ?", (address.lower(),))
        user = cursor.fetchone()
        score = user['score'] if user else 0
        
        conn.close()
        
        log_activity("INFO", "OAUTH", f"NFT verified for {address[:10]}", 
                    client_id=client_id[:20], has_nft=has_nft)
        
        return {
            "valid": True,
            "wallet": address,
            "has_nft": has_nft,
            "score": score,
            "chain_id": 8453,
            "client_id": client_id
        }
        
    except Exception as e:
        log_activity("ERROR", "OAUTH", f"verify-nft error: {str(e)}")
        return {"valid": False, "error": str(e)}


# ============================================================================
# ===== OAUTH CLIENT MANAGEMENT (User-Facing Dashboard) =====
# ============================================================================

@app.post("/api/oauth/my-apps/register")
async def register_user_oauth_app(req: Request):
    """
    🔐 Register a new OAuth client for authenticated NFT holders
    
    Users must be authenticated via JWT and hold an AEra NFT to register apps.
    
    Request Headers:
        Authorization: Bearer <jwt_token>
    
    Request Body:
        {
            "app_name": "My Website",
            "website_url": "https://mywebsite.com",
            "redirect_uri": "https://mywebsite.com/callback",
            "description": "Optional description"
        }
    
    Response:
        {
            "success": true,
            "client_id": "aera_xxx...",
            "client_secret": "xxx...",  // Only shown ONCE!
            "message": "Save your client_secret now - it cannot be retrieved later!"
        }
    """
    try:
        # Get JWT from Authorization header
        auth_header = req.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return {"success": False, "error": "Missing or invalid Authorization header"}
        
        token = auth_header.replace("Bearer ", "")
        
        # Verify JWT and get wallet address
        try:
            payload = jwt.decode(token, TOKEN_SECRET, algorithms=["HS256"])
            owner_address = payload.get("address", "").lower()
        except jwt.ExpiredSignatureError:
            return {"success": False, "error": "Token expired"}
        except jwt.InvalidTokenError:
            return {"success": False, "error": "Invalid token"}
        
        if not owner_address:
            return {"success": False, "error": "Invalid token payload"}
        
        # Verify user has NFT (identity_status = 'active')
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT identity_status FROM users WHERE address=?", (owner_address,))
        user = cursor.fetchone()
        
        if not user or user[0] != 'active':
            conn.close()
            return {"success": False, "error": "NFT required to register apps. Please mint your AEra Identity NFT first."}
        
        # Parse request data
        data = await req.json()
        app_name = data.get("app_name", "").strip()
        website_url = data.get("website_url", "").strip()
        redirect_uri = data.get("redirect_uri", "").strip()
        description = data.get("description", "").strip()
        
        # Validation
        if not app_name or len(app_name) < 3:
            conn.close()
            return {"success": False, "error": "App name must be at least 3 characters"}
        
        if not website_url or not website_url.startswith("http"):
            conn.close()
            return {"success": False, "error": "Valid website URL required (must start with http:// or https://)"}
        
        if not redirect_uri or not redirect_uri.startswith("http"):
            conn.close()
            return {"success": False, "error": "Valid redirect URI required (must start with http:// or https://)"}
        
        # Check if user already has too many apps (limit: 5)
        cursor.execute("SELECT COUNT(*) as count FROM oauth_clients WHERE owner_address=? AND is_active=1", (owner_address,))
        count_result = cursor.fetchone()
        if count_result and count_result['count'] >= 5:
            conn.close()
            return {"success": False, "error": "Maximum 5 apps per account. Please delete an existing app first."}
        
        # Generate credentials
        client_id = "aera_" + secrets.token_hex(16)
        client_secret = secrets.token_urlsafe(32)
        client_secret_hash = hashlib.sha256(client_secret.encode()).hexdigest()
        
        # Extract origin from website URL
        from urllib.parse import urlparse
        parsed_url = urlparse(website_url)
        allowed_origin = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        # Insert into database
        cursor.execute("""
            INSERT INTO oauth_clients (
                client_id, client_secret_hash, client_name, redirect_uris, 
                allowed_origins, min_score, require_nft, created_at, is_active,
                owner_address, website_url, description
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
        """, (
            client_id,
            client_secret_hash,
            app_name,
            json.dumps([redirect_uri]),
            json.dumps([allowed_origin]),
            0,  # min_score
            1,  # require_nft
            datetime.now(timezone.utc).isoformat(),
            owner_address,
            website_url,
            description
        ))
        conn.commit()
        conn.close()
        
        log_activity("INFO", "OAUTH", f"User registered new app: {app_name}", client_id=client_id, address=owner_address)
        
        return {
            "success": True,
            "client_id": client_id,
            "client_secret": client_secret,
            "app_name": app_name,
            "website_url": website_url,
            "redirect_uri": redirect_uri,
            "message": "⚠️ IMPORTANT: Save your client_secret NOW! It cannot be retrieved later."
        }
        
    except Exception as e:
        log_activity("ERROR", "OAUTH", f"User app registration error: {str(e)}")
        return {"success": False, "error": str(e)}


@app.get("/api/oauth/my-apps")
async def list_user_oauth_apps(req: Request):
    """
    📋 List all OAuth apps registered by the authenticated user
    
    Request Headers:
        Authorization: Bearer <jwt_token>
    
    Response:
        {
            "success": true,
            "apps": [
                {
                    "client_id": "aera_xxx...",
                    "app_name": "My Website",
                    "website_url": "https://...",
                    "redirect_uri": "https://...",
                    "created_at": "2025-12-20T...",
                    "is_active": true
                }
            ]
        }
    """
    try:
        # Get JWT from Authorization header
        auth_header = req.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return {"success": False, "error": "Missing or invalid Authorization header"}
        
        token = auth_header.replace("Bearer ", "")
        
        # Verify JWT
        try:
            payload = jwt.decode(token, TOKEN_SECRET, algorithms=["HS256"])
            owner_address = payload.get("address", "").lower()
        except jwt.ExpiredSignatureError:
            return {"success": False, "error": "Token expired"}
        except jwt.InvalidTokenError:
            return {"success": False, "error": "Invalid token"}
        
        if not owner_address:
            return {"success": False, "error": "Invalid token payload"}
        
        # Get user's apps
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT client_id, client_name, website_url, redirect_uris, 
                   allowed_origins, created_at, is_active, description
            FROM oauth_clients 
            WHERE owner_address=? 
            ORDER BY created_at DESC
        """, (owner_address,))
        
        apps = []
        for row in cursor.fetchall():
            redirect_uris = json.loads(row['redirect_uris']) if row['redirect_uris'] else []
            apps.append({
                "client_id": row['client_id'],
                "app_name": row['client_name'],
                "website_url": row['website_url'] or "",
                "redirect_uri": redirect_uris[0] if redirect_uris else "",
                "description": row['description'] or "",
                "created_at": row['created_at'],
                "is_active": bool(row['is_active'])
            })
        
        conn.close()
        
        return {
            "success": True,
            "apps": apps,
            "count": len(apps),
            "max_apps": 5
        }
        
    except Exception as e:
        log_activity("ERROR", "OAUTH", f"List apps error: {str(e)}")
        return {"success": False, "error": str(e)}


@app.delete("/api/oauth/my-apps/{client_id}")
async def delete_user_oauth_app(client_id: str, req: Request):
    """
    🗑️ Delete/Deactivate an OAuth app
    
    Users can only delete their own apps.
    
    Request Headers:
        Authorization: Bearer <jwt_token>
    """
    try:
        # Get JWT from Authorization header
        auth_header = req.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return {"success": False, "error": "Missing or invalid Authorization header"}
        
        token = auth_header.replace("Bearer ", "")
        
        # Verify JWT
        try:
            payload = jwt.decode(token, TOKEN_SECRET, algorithms=["HS256"])
            owner_address = payload.get("address", "").lower()
        except jwt.ExpiredSignatureError:
            return {"success": False, "error": "Token expired"}
        except jwt.InvalidTokenError:
            return {"success": False, "error": "Invalid token"}
        
        if not owner_address:
            return {"success": False, "error": "Invalid token payload"}
        
        # Delete app (only if owned by user)
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check ownership
        cursor.execute("SELECT client_name FROM oauth_clients WHERE client_id=? AND owner_address=?", 
                      (client_id, owner_address))
        app = cursor.fetchone()
        
        if not app:
            conn.close()
            return {"success": False, "error": "App not found or you don't have permission to delete it"}
        
        # Soft delete (set is_active = 0)
        cursor.execute("UPDATE oauth_clients SET is_active=0 WHERE client_id=?", (client_id,))
        # S-02 cascade: revoke this client's still-active access tokens in the
        # same transaction, so deleting an app immediately invalidates the
        # tokens it issued instead of leaving them valid until exp.
        cursor.execute(
            "UPDATE oauth_token_jti SET status = 'revoked', revoked_at = ?, "
            "revocation_reason = 'client_disabled' "
            "WHERE client_id = ? AND status = 'active'",
            (datetime.now(timezone.utc).isoformat(), client_id))
        revoked_tokens = cursor.rowcount
        conn.commit()
        conn.close()
        if revoked_tokens:
            log_activity("INFO", "OAUTH",
                         f"Revoked {revoked_tokens} token(s) for disabled client",
                         client_id=client_id)
        
        log_activity("INFO", "OAUTH", f"User deleted app: {app['client_name']}", client_id=client_id, address=owner_address)
        
        return {
            "success": True,
            "message": f"App '{app['client_name']}' has been deleted"
        }
        
    except Exception as e:
        log_activity("ERROR", "OAUTH", f"Delete app error: {str(e)}")
        return {"success": False, "error": str(e)}


@app.post("/api/oauth/my-apps/{client_id}/regenerate-secret")
async def regenerate_client_secret(client_id: str, req: Request):
    """
    🔄 Regenerate client secret for an app
    
    Users can regenerate secrets for their own apps.
    The old secret will be invalidated immediately.
    """
    try:
        # Get JWT from Authorization header
        auth_header = req.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return {"success": False, "error": "Missing or invalid Authorization header"}
        
        token = auth_header.replace("Bearer ", "")
        
        # Verify JWT
        try:
            payload = jwt.decode(token, TOKEN_SECRET, algorithms=["HS256"])
            owner_address = payload.get("address", "").lower()
        except jwt.ExpiredSignatureError:
            return {"success": False, "error": "Token expired"}
        except jwt.InvalidTokenError:
            return {"success": False, "error": "Invalid token"}
        
        if not owner_address:
            return {"success": False, "error": "Invalid token payload"}
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check ownership
        cursor.execute("SELECT client_name FROM oauth_clients WHERE client_id=? AND owner_address=? AND is_active=1", 
                      (client_id, owner_address))
        app = cursor.fetchone()
        
        if not app:
            conn.close()
            return {"success": False, "error": "App not found or you don't have permission"}
        
        # Generate new secret
        new_secret = secrets.token_urlsafe(32)
        new_secret_hash = hashlib.sha256(new_secret.encode()).hexdigest()
        
        # Update database
        cursor.execute("UPDATE oauth_clients SET client_secret_hash=? WHERE client_id=?", 
                      (new_secret_hash, client_id))
        conn.commit()
        conn.close()
        
        log_activity("INFO", "OAUTH", f"Secret regenerated for: {app['client_name']}", client_id=client_id, address=owner_address)
        
        return {
            "success": True,
            "client_id": client_id,
            "client_secret": new_secret,
            "message": "⚠️ Save this new secret NOW! The old secret is no longer valid."
        }
        
    except Exception as e:
        log_activity("ERROR", "OAUTH", f"Regenerate secret error: {str(e)}")
        return {"success": False, "error": str(e)}


# ============================================================================
# ===== END OF OAUTH ENDPOINTS =====
# ============================================================================


# ============================================================================
# ===== AGENT DASHBOARD ENDPOINTS (read-only owner views) =====
# ============================================================================
# The Agent Identity Layer under /api/agents/* is NOT modified by the dashboard.
# Every MUTATING operation (register / key add / rotate / key revoke / agent
# revoke / capabilities) is performed by the browser directly against those
# existing endpoints, which enforce the owner challenge + EIP-191 signature.
#
# The Agent Identity Layer is keyed by agent_id and therefore has no
# "list my agents" operation. These two READ endpoints fill exactly that gap
# and nothing more. They introduce no new authentication mechanism: they reuse
# the same dashboard session JWT (TOKEN_SECRET, `address` claim) that
# /api/oauth/my-apps already uses, and ownership is resolved from that token --
# never from a wallet address supplied by the browser.

# Mirrors agent/constants.py CAPABILITY_ALLOWLIST. Imported, never redefined,
# so the dashboard can never offer a capability the backend would reject.
try:
    from agent.constants import CAPABILITY_ALLOWLIST as _AGENT_CAPS
    AGENT_CAPABILITY_ALLOWLIST = sorted(_AGENT_CAPS)
except Exception:  # pragma: no cover - agent layer always present in prod
    AGENT_CAPABILITY_ALLOWLIST = []


def _dashboard_owner_from_request(req: Request) -> str:
    """Resolve the owner wallet from the dashboard session JWT.

    Returns "" when the caller is not authenticated.
    """
    auth_header = req.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return ""
    token = auth_header[len("Bearer "):]
    try:
        payload = jwt.decode(token, TOKEN_SECRET, algorithms=["HS256"])
    except jwt.PyJWTError:
        return ""
    return (payload.get("address") or "").lower()


def _agent_row_to_dashboard_dict(agent_row, key_rows) -> dict:
    """Shape an agent for the dashboard.

    Returns ONLY public identity metadata. No private key material exists
    server-side at all (AEra only ever receives Ed25519 *public* keys), and no
    agent JWT is minted or returned here. Public keys are omitted as well --
    the management UI has no use for them.
    """
    try:
        capabilities = json.loads(agent_row["capabilities"] or "[]")
    except (ValueError, TypeError):
        capabilities = []
    keys = [
        {
            "key_id": k["key_id"],
            "algorithm": k["algorithm"],
            "status": k["status"],
            "created_at": k["created_at"],
        }
        for k in key_rows
    ]
    active_keys = [k for k in keys if k["status"] == "active"]
    return {
        "agent_id": agent_row["agent_id"],
        "owner_wallet": agent_row["owner_wallet"],
        "status": agent_row["status"],
        "label": agent_row["label"],
        "capabilities": capabilities,
        "created_at": agent_row["created_at"],
        "updated_at": agent_row["updated_at"],
        "keys": keys,
        "active_key_id": active_keys[0]["key_id"] if active_keys else None,
        "active_key_count": len(active_keys),
    }


@app.get("/api/dashboard/agents")
async def list_my_agents(req: Request):
    """List the AEra Agents owned by the authenticated dashboard user."""
    owner = _dashboard_owner_from_request(req)
    if not owner:
        return JSONResponse(status_code=401,
                            content={"success": False, "error": "unauthorized"})
    try:
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT agent_id, owner_wallet, status, capabilities, label, "
                "created_at, updated_at FROM agents "
                "WHERE lower(owner_wallet) = ? ORDER BY created_at DESC",
                (owner,),
            )
            agents = cursor.fetchall()
            out = []
            for a in agents:
                cursor.execute(
                    "SELECT key_id, algorithm, status, created_at FROM agent_keys "
                    "WHERE agent_id = ? ORDER BY created_at DESC",
                    (a["agent_id"],),
                )
                out.append(_agent_row_to_dashboard_dict(a, cursor.fetchall()))
        finally:
            conn.close()
        return {"success": True, "agents": out,
                "capability_allowlist": AGENT_CAPABILITY_ALLOWLIST}
    except Exception as e:
        log_activity("ERROR", "AGENTS", f"list_my_agents error: {str(e)}")
        return JSONResponse(status_code=500,
                            content={"success": False, "error": "internal_error"})


@app.get("/api/dashboard/agents/{agent_id}")
async def get_my_agent(agent_id: str, req: Request):
    """Detail view for one agent. Ownership is enforced server-side."""
    owner = _dashboard_owner_from_request(req)
    if not owner:
        return JSONResponse(status_code=401,
                            content={"success": False, "error": "unauthorized"})
    try:
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT agent_id, owner_wallet, status, capabilities, label, "
                "created_at, updated_at FROM agents WHERE agent_id = ?",
                (agent_id,),
            )
            a = cursor.fetchone()
            # Same 404 whether the agent is absent or owned by somebody else,
            # so this endpoint cannot be used to enumerate other owners' agents.
            if a is None or (a["owner_wallet"] or "").lower() != owner:
                return JSONResponse(
                    status_code=404,
                    content={"success": False, "error": "unknown_agent"})
            cursor.execute(
                "SELECT key_id, algorithm, status, created_at FROM agent_keys "
                "WHERE agent_id = ? ORDER BY created_at DESC",
                (agent_id,),
            )
            agent = _agent_row_to_dashboard_dict(a, cursor.fetchall())
        finally:
            conn.close()
        return {"success": True, "agent": agent,
                "capability_allowlist": AGENT_CAPABILITY_ALLOWLIST}
    except Exception as e:
        log_activity("ERROR", "AGENTS", f"get_my_agent error: {str(e)}")
        return JSONResponse(status_code=500,
                            content={"success": False, "error": "internal_error"})


# ============================================================================
# ===== AGENT ENROLLMENT (runtime pairing) — dashboard side =====
# ============================================================================
# The owner starts a pairing from the dashboard session. The runtime claims it
# with its locally generated public key (+ proof of possession) via
# /api/agents/enrollments/claim, and the owner finishes with a wallet
# signature via /api/agents/enrollments/{id}/complete. See agent/enrollment.py.
#
# The owner is taken from the session JWT, never from the body. No private key
# ever reaches these endpoints; there is no field that could carry one.

def _enrollment_unavailable():
    return JSONResponse(status_code=404,
                        content={"success": False, "error": "agent_layer_disabled"})


def _enrollment_enabled() -> bool:
    try:
        import agent as _agent_pkg
        return _agent_pkg.is_enabled()
    except Exception:
        return False


@app.post("/api/dashboard/agents/enrollments")
async def create_agent_enrollment(req: Request):
    owner = _dashboard_owner_from_request(req)
    if not owner:
        return JSONResponse(status_code=401,
                            content={"success": False, "error": "unauthorized"})
    if not _enrollment_enabled():
        return _enrollment_unavailable()
    from agent import enrollment as _enr
    from agent import ratelimit as _rl
    try:
        body = await req.json()
    except Exception:
        body = None
    if not isinstance(body, dict):
        return JSONResponse(status_code=400,
                            content={"success": False, "error": "invalid_body"})
    caps = body.get("capabilities")
    if caps is not None and not (isinstance(caps, list)
                                 and all(isinstance(c, str) for c in caps)):
        return JSONResponse(status_code=400,
                            content={"success": False, "error": "invalid_capabilities"})
    label = body.get("label")
    if label is not None and not isinstance(label, str):
        return JSONResponse(status_code=400,
                            content={"success": False, "error": "invalid_label"})
    if not _rl.check("enroll-create", owner, limit=10, window_seconds=60):
        return JSONResponse(status_code=429,
                            content={"success": False, "error": "rate_limited"})
    try:
        out = _enr.create(owner_wallet=owner, label=label, capabilities=caps)
    except _enr.EnrollmentError as e:
        return JSONResponse(status_code=e.http_status,
                            content={"success": False, "error": e.code})
    except Exception as e:
        log_activity("ERROR", "AGENTS", f"create_enrollment error: {type(e).__name__}")
        return JSONResponse(status_code=500,
                            content={"success": False, "error": "internal_error"})
    return {"success": True, "enrollment": out}


@app.get("/api/dashboard/agents/enrollments/{enrollment_id}")
async def get_agent_enrollment(enrollment_id: str, req: Request):
    owner = _dashboard_owner_from_request(req)
    if not owner:
        return JSONResponse(status_code=401,
                            content={"success": False, "error": "unauthorized"})
    if not _enrollment_enabled():
        return _enrollment_unavailable()
    from agent import enrollment as _enr
    try:
        view = _enr.owner_view(owner_wallet=owner, enrollment_id=enrollment_id)
    except _enr.EnrollmentError as e:
        return JSONResponse(status_code=e.http_status,
                            content={"success": False, "error": e.code})
    return {"success": True, "enrollment": view}


@app.delete("/api/dashboard/agents/enrollments/{enrollment_id}")
async def cancel_agent_enrollment(enrollment_id: str, req: Request):
    owner = _dashboard_owner_from_request(req)
    if not owner:
        return JSONResponse(status_code=401,
                            content={"success": False, "error": "unauthorized"})
    if not _enrollment_enabled():
        return _enrollment_unavailable()
    from agent import enrollment as _enr
    try:
        out = _enr.cancel(owner_wallet=owner, enrollment_id=enrollment_id)
    except _enr.EnrollmentError as e:
        return JSONResponse(status_code=e.http_status,
                            content={"success": False, "error": e.code})
    return {"success": True, "enrollment": out}


# ============================================================================
# ===== EXTERNAL A2A PEER CREDENTIALS (owner-issued, LEVEL 3) =====
# ============================================================================
# These endpoints mint credentials for EXTERNAL peers -- other people's agents
# that want to talk to yours over the public A2A gateway.
#
# Three properties are load-bearing:
#
#   1. Only an authenticated agent OWNER may issue. There is no self-service
#      registration: an external party cannot obtain a credential by asking.
#   2. The owner is taken from the dashboard session JWT, never from the
#      request body. A body-supplied owner would be a trivial impersonation.
#   3. The plaintext credential is returned exactly once and is never stored.
#
# An issued credential authenticates an external peer to the GATEWAY. It is not
# an AEra agent token, carries a different audience, and grants no access to
# /api/agents/* or to anything else in the Agent Identity Layer.


def _a2a_cred_conn():
    """Connection to the credential store, with the schema ensured."""
    from a2a_gateway import credentials as _gw_cred

    conn = get_db_connection()
    _gw_cred.init_schema(conn)
    return conn


@app.get("/api/dashboard/a2a-credentials")
async def list_a2a_credentials(req: Request):
    """List the credentials this owner has issued. Never includes a secret."""
    owner = _dashboard_owner_from_request(req)
    if not owner:
        return JSONResponse(status_code=401,
                            content={"success": False, "error": "unauthorized"})
    try:
        from a2a_gateway import credentials as _gw_cred

        conn = _a2a_cred_conn()
        try:
            records = _gw_cred.list_for_owner(conn, owner)
        finally:
            conn.close()
        return {"success": True,
                "credentials": [r.to_owner_dict() for r in records]}
    except Exception as e:
        log_activity("ERROR", "A2A_CRED", f"list error: {str(e)}")
        return JSONResponse(status_code=500,
                            content={"success": False, "error": "internal_error"})


@app.post("/api/dashboard/a2a-credentials")
async def issue_a2a_credential(req: Request):
    """Issue a credential to an external peer.

    Body: {"peer_label": str?, "scoped_agents": [agent_id], "scoped_skills": [id],
           "ttl_days": int?}

    `scoped_agents` is verified against the caller's own agents. Scoping a
    credential to an agent you do not own would let you hand out access to
    somebody else's agent, so that is rejected rather than silently dropped.
    """
    owner = _dashboard_owner_from_request(req)
    if not owner:
        return JSONResponse(status_code=401,
                            content={"success": False, "error": "unauthorized"})
    try:
        from a2a_gateway import credentials as _gw_cred
        from a2a_gateway.constants import SUPPORTED_SKILLS

        try:
            body = await req.json()
        except Exception:
            body = {}
        if not isinstance(body, dict):
            body = {}

        scoped_agents = body.get("scoped_agents") or []
        scoped_skills = body.get("scoped_skills") or []
        if not isinstance(scoped_agents, list) or not isinstance(scoped_skills, list):
            return JSONResponse(
                status_code=400,
                content={"success": False, "error": "invalid_scope"})
        scoped_agents = [str(a) for a in scoped_agents][:50]
        scoped_skills = [str(s) for s in scoped_skills][:20]

        # Only skills the gateway can actually fulfil. Accepting an unknown
        # skill would store a scope that can never match anything, producing a
        # credential that silently never works.
        unknown_skills = [s for s in scoped_skills if s not in SUPPORTED_SKILLS]
        if unknown_skills:
            return JSONResponse(
                status_code=400,
                content={"success": False, "error": "unknown_skill",
                         "detail": unknown_skills})

        label = body.get("peer_label")
        label = str(label)[:100] if label else None
        ttl_days = body.get("ttl_days")
        try:
            ttl_days = int(ttl_days) if ttl_days is not None else None
        except (TypeError, ValueError):
            ttl_days = None

        conn = _a2a_cred_conn()
        try:
            not_owned = _gw_cred.verify_owns_agents(conn, owner, scoped_agents)
            if not_owned:
                return JSONResponse(
                    status_code=403,
                    content={"success": False, "error": "not_your_agent",
                             "detail": not_owned})
            issued = _gw_cred.issue_credential(
                conn, owner_address=owner, scoped_agents=scoped_agents,
                scoped_skills=scoped_skills, peer_label=label, ttl_days=ttl_days)
            conn.commit()
        finally:
            conn.close()

        # Audit the issuance, but log the cred_id only -- never the plaintext.
        log_activity("INFO", "A2A_CRED",
                     f"issued {issued.record.cred_id} peer={issued.record.peer_id} "
                     f"owner={owner}")
        return {"success": True, **issued.to_issue_response()}
    except Exception as e:
        log_activity("ERROR", "A2A_CRED", f"issue error: {str(e)}")
        return JSONResponse(status_code=500,
                            content={"success": False, "error": "internal_error"})


@app.post("/api/dashboard/a2a-credentials/{cred_id}/revoke")
async def revoke_a2a_credential(cred_id: str, req: Request):
    """Revoke a credential. Effective immediately, on the very next request."""
    owner = _dashboard_owner_from_request(req)
    if not owner:
        return JSONResponse(status_code=401,
                            content={"success": False, "error": "unauthorized"})
    try:
        from a2a_gateway import credentials as _gw_cred

        try:
            body = await req.json()
        except Exception:
            body = {}
        reason = str((body or {}).get("reason") or "")[:200]

        conn = _a2a_cred_conn()
        try:
            ok = _gw_cred.revoke_credential(conn, cred_id=cred_id,
                                            owner_address=owner, reason=reason)
            conn.commit()
        finally:
            conn.close()
        if not ok:
            # Same 404 whether the credential is absent, already revoked, or
            # belongs to another owner -- otherwise this enumerates cred_ids.
            return JSONResponse(
                status_code=404,
                content={"success": False, "error": "unknown_credential"})
        log_activity("INFO", "A2A_CRED", f"revoked {cred_id} owner={owner}")
        return {"success": True, "cred_id": cred_id, "status": "revoked"}
    except Exception as e:
        log_activity("ERROR", "A2A_CRED", f"revoke error: {str(e)}")
        return JSONResponse(status_code=500,
                            content={"success": False, "error": "internal_error"})


# ============================================================================
# ===== EXTERNAL PEER TRUST ASSESSMENT (READ-ONLY) =====
# ============================================================================
#
# AEra derives this assessment itself, from evidence it observed. It is NOT an
# owner-controlled setting, and there is deliberately no endpoint to set it:
# an owner can decide who gets a credential and what it may reach, which is
# authorisation, and that is already exposed above. How much AEra believes a
# peer is AEra's own conclusion, and a "set trust" button would turn the whole
# layer back into the owner flag it exists to replace.


@app.get("/api/dashboard/a2a-peer-trust")
async def list_a2a_peer_trust(req: Request):
    """AEra's assessment of the external peers this owner issued credentials to.

    Read-only by construction. The response carries `owner_settable: false` on
    every entry so a dashboard cannot accidentally render an editable control.
    """
    owner = _dashboard_owner_from_request(req)
    if not owner:
        return JSONResponse(status_code=401,
                            content={"success": False, "error": "unauthorized"})
    try:
        from a2a_gateway import trust as _gw_trust

        conn = _a2a_cred_conn()
        try:
            _gw_trust.init_schema(conn)
            assessments = _gw_trust.assess_peers_for_owner(conn, owner)
        finally:
            conn.close()
        return {
            "success": True,
            "assessed_by": "aera",
            "policy_version": _gw_trust.POLICY_VERSION,
            "enforcement": _gw_trust.enforcement_mode(),
            "enforces_authorization": _gw_trust.trust_enforces_authorization(),
            "peers": [a.to_owner_dict() for a in assessments],
        }
    except Exception as e:
        log_activity("ERROR", "A2A_TRUST", f"list error: {str(e)}")
        return JSONResponse(status_code=500,
                            content={"success": False, "error": "internal_error"})



# ============================================================================
# ===== OAUTH SESSION CLEANUP JOB =====
# ============================================================================

async def oauth_session_cleanup_loop():
    """
    Background task that periodically deactivates expired OAuth sessions.
    
    AUDIT COMPLIANCE:
    - Sessions are NOT deleted - all data is preserved for audit purposes
    - Only sets is_active = 0 for expired sessions
    - Runs every hour
    - Logs all cleanup operations
    """
    # Initial delay before first cleanup
    await asyncio.sleep(60)  # 1 minute initial delay
    
    while True:
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Count expired sessions before cleanup
            cursor.execute("""
                SELECT COUNT(*) as count FROM oauth_sessions 
                WHERE is_active = 1 AND datetime(expires_at) <= datetime('now')
            """)
            expired_count = cursor.fetchone()['count']
            
            if expired_count > 0:
                # Deactivate expired sessions (preserve data for audit)
                cursor.execute("""
                    UPDATE oauth_sessions 
                    SET is_active = 0, 
                        deactivated_at = datetime('now'),
                        deactivation_reason = 'expired_cleanup_job'
                    WHERE is_active = 1 AND datetime(expires_at) <= datetime('now')
                """)
                conn.commit()
                
                logger.info(f"🧹 OAuth Cleanup: {expired_count} expired sessions deactivated (data preserved for audit)")
                log_activity("INFO", "OAUTH_CLEANUP", f"Deactivated {expired_count} expired sessions", 
                           details=f"Sessions preserved for audit compliance")
            
            conn.close()
            
        except Exception as e:
            logger.error(f"❌ OAuth Cleanup error: {str(e)}")
            log_activity("ERROR", "OAUTH_CLEANUP", f"Cleanup failed: {str(e)}")
        
        # Run every hour
        await asyncio.sleep(3600)


@app.get("/api/airdrop-status/{address}")
async def get_airdrop_status(address: str):
    """
    Prüft den Airdrop-Status einer Wallet
    """
    try:
        address = address.lower()
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM airdrops WHERE address=?", (address,))
        airdrop = cursor.fetchone()
        conn.close()
        
        if not airdrop:
            return {
                "address": address,
                "status": "not_registered",
                "message": "No airdrop record found"
            }
        
        return {
            "address": address,
            "status": airdrop['status'],
            "amount": airdrop['amount'],
            "tx_hash": airdrop['tx_hash'],
            "created_at": airdrop['created_at']
        }
        
    except Exception as e:
        return {"error": str(e)}

# 🔐 SECURITY: Challenge-Response Authentication for Dashboard
# Requires ACTIVE MetaMask confirmation via personal_sign
dashboard_challenges = {}  # {address: {nonce, timestamp}}

@app.post("/admin/challenge")
async def get_dashboard_challenge(data: dict):
    """
    🔐 SECURITY: Get a challenge to sign with MetaMask (personal_sign)
    
    This requires:
    - ACTIVE MetaMask confirmation (cannot be bypassed)
    - User MUST click "Sign" in MetaMask every time
    - Even if MetaMask is unlocked
    
    Request body: {"owner": "0x..."}
    Response: {"success": true, "nonce": "...", "message": "..."}
    """
    try:
        import secrets
        
        owner = data.get("owner", "").lower()
        
        if not owner or not owner.startswith("0x") or len(owner) != 42:
            return {"success": False, "error": "Invalid owner wallet"}
        
        # Generate unique nonce
        nonce = secrets.token_hex(16)
        
        # Store challenge with timestamp (5 min expiry)
        dashboard_challenges[owner] = {
            "nonce": nonce,
            "timestamp": time.time(),
            "expiry": 300
        }
        
        log_activity("INFO", "AUTH", "Dashboard challenge created", owner=owner[:10], nonce=nonce[:10])
        
        return {
            "success": True,
            "nonce": nonce,
            "message": "🔐 Sign this in MetaMask to access your dashboard"
        }
    except Exception as e:
        log_activity("ERROR", "AUTH", "Challenge creation failed", error=str(e))
        return {"success": False, "error": str(e)}

@app.post("/admin/verify-signature")
async def verify_dashboard_signature(data: dict):
    """
    🔐 SECURITY: Verify personal_sign signature (supports SIWE/EIP-4361)
    
    Request body:
        {
            "owner": "0x...",
            "signature": "0x...",
            "nonce": "...",
            "message": "..." (optional - the signed message for SIWE)
        }
    
    Response:
        {
            "success": true,
            "verified": true,
            "message": "✓ Verified"
        }
    """
    try:
        from eth_account.messages import encode_defunct
        from eth_account import Account
        
        owner = data.get("owner", "").lower()
        signature = data.get("signature", "")
        nonce = data.get("nonce", "")
        
        if not owner or not signature or not nonce:
            return {"success": False, "error": "owner, signature, and nonce required"}
        
        # Get stored challenge
        if owner not in dashboard_challenges:
            log_activity("WARNING", "AUTH", "No challenge found", owner=owner[:10])
            return {"success": False, "error": "No challenge found. Request a new one."}
        
        challenge_data = dashboard_challenges[owner]
        
        # Verify nonce matches
        if challenge_data["nonce"] != nonce:
            log_activity("WARNING", "AUTH", "Nonce mismatch", owner=owner[:10])
            return {"success": False, "error": "Invalid nonce"}
        
        # Check if challenge expired (5 minutes)
        if time.time() - challenge_data["timestamp"] > challenge_data["expiry"]:
            del dashboard_challenges[owner]
            log_activity("WARNING", "AUTH", "Challenge expired", owner=owner[:10])
            return {"success": False, "error": "Challenge expired"}
        
        # Verify signature - supports EOA, SIWE (EIP-4361), and Smart Contract Wallets (EIP-1271/EIP-6492)
        from eth_account.messages import encode_defunct
        
        recovered_address = None
        signed_message = data.get("message", "")  # Frontend can send the signed message
        
        # DEBUG: Log received data FIRST (before any try/except)
        log_activity("INFO", "AUTH", f"=== SIGNATURE DEBUG START ===")
        log_activity("INFO", "AUTH", f"Owner: {owner}")
        log_activity("INFO", "AUTH", f"Signature length: {len(signature) if signature else 0}")
        log_activity("INFO", "AUTH", f"Signature (first 40): {signature[:40] if signature else 'None'}...")
        log_activity("INFO", "AUTH", f"Message length: {len(signed_message) if signed_message else 0}")
        log_activity("INFO", "AUTH", f"Message (first 150): {signed_message[:150] if signed_message else 'None'}")
        log_activity("INFO", "AUTH", f"Nonce: {nonce}")
        log_activity("INFO", "AUTH", f"Nonce in message: {nonce in signed_message if signed_message else False}")
        
        # Detect Smart Contract Wallet signature (EIP-6492)
        # These signatures are much longer than 65 bytes and often start with zeros
        is_smart_wallet_sig = len(signature) > 200 if signature else False
        log_activity("INFO", "AUTH", f"Smart Contract Wallet detected: {is_smart_wallet_sig}")
        
        try:
            # ========================================
            # SMART CONTRACT WALLET (EIP-1271) VERIFICATION
            # Base Wallet, Coinbase Smart Wallet, Safe, etc.
            # ========================================
            if is_smart_wallet_sig and signed_message and nonce in signed_message:
                log_activity("INFO", "AUTH", "Attempting EIP-1271 Smart Contract Wallet verification...")
                try:
                    # For Smart Contract Wallets, we verify via on-chain call
                    # The wallet contract implements isValidSignature(bytes32 hash, bytes signature)
                    # Magic value 0x1626ba7e means valid
                    
                    from web3 import Web3
                    from eth_account.messages import defunct_hash_message
                    
                    # Connect to BASE mainnet via Alchemy (faster & more reliable)
                    alchemy_url = os.getenv("BASE_ALCHEMY_API_URL") or os.getenv("BASE_RPC_URL", "https://mainnet.base.org")
                    w3 = Web3(Web3.HTTPProvider(alchemy_url))
                    
                    # EIP-1271 ABI - just the isValidSignature function
                    EIP1271_ABI = [
                        {
                            "inputs": [
                                {"name": "_hash", "type": "bytes32"},
                                {"name": "_signature", "type": "bytes"}
                            ],
                            "name": "isValidSignature",
                            "outputs": [{"name": "", "type": "bytes4"}],
                            "stateMutability": "view",
                            "type": "function"
                        }
                    ]
                    
                    # Hash the message (EIP-191 personal sign format)
                    message_hash = defunct_hash_message(text=signed_message)
                    log_activity("INFO", "AUTH", f"Message hash: {message_hash.hex()}")
                    
                    # Create contract instance
                    wallet_contract = w3.eth.contract(
                        address=Web3.to_checksum_address(owner),
                        abi=EIP1271_ABI
                    )
                    
                    # Convert signature to bytes
                    sig_bytes = bytes.fromhex(signature[2:]) if signature.startswith('0x') else bytes.fromhex(signature)
                    
                    # Call isValidSignature on the smart contract wallet
                    try:
                        result = wallet_contract.functions.isValidSignature(
                            message_hash,
                            sig_bytes
                        ).call()
                        
                        # EIP-1271 magic value for valid signature
                        MAGIC_VALUE = bytes.fromhex('1626ba7e')
                        
                        if result == MAGIC_VALUE:
                            recovered_address = owner  # Smart contract wallet verified!
                            log_activity("INFO", "AUTH", f"✅ EIP-1271 Smart Contract Wallet verification SUCCESS!")
                        else:
                            log_activity("INFO", "AUTH", f"EIP-1271 returned: {result.hex()} (expected 1626ba7e)")
                    except Exception as contract_error:
                        log_activity("INFO", "AUTH", f"EIP-1271 contract call failed: {str(contract_error)}")
                        
                except Exception as eip1271_error:
                    log_activity("INFO", "AUTH", f"EIP-1271 verification error: {str(eip1271_error)}")
            
            # ========================================
            # STANDARD EOA SIGNATURE VERIFICATION
            # MetaMask, Rainbow, Trust, etc.
            # ========================================
            if recovered_address != owner:
                # If frontend sent the message, use it directly
                if signed_message and nonce in signed_message:
                    try:
                        message = encode_defunct(text=signed_message)
                        recovered_address = Account.recover_message(message, signature=signature).lower()
                        log_activity("INFO", "AUTH", f"SIWE verification SUCCESS - recovered: {recovered_address}", owner=owner[:10])
                    except Exception as e:
                        log_activity("INFO", "AUTH", f"SIWE verification FAILED: {str(e)}")
                
                # Fallback: Try old format for backwards compatibility
                if recovered_address != owner:
                    old_message = f"VEra-Resonance Dashboard Access\n\nNonce: {nonce}\n\nPlease confirm in your Web3 wallet to access your dashboard."
                    try:
                        message = encode_defunct(text=old_message)
                        recovered_address = Account.recover_message(message, signature=signature).lower()
                        log_activity("INFO", "AUTH", "Old format verification SUCCESS", owner=owner[:10])
                    except Exception as e2:
                        log_activity("INFO", "AUTH", f"Old format verification FAILED: {str(e2)}")
            
            if not recovered_address or recovered_address != owner:
                raise Exception("Could not recover address from signature")
                
        except Exception as e:
            log_activity("ERROR", "AUTH", "Signature recovery failed", owner=owner[:10], error=str(e))
            return {"success": False, "error": f"Invalid signature: {str(e)}"}
        
        # Check if signature matches owner
        if recovered_address != owner:
            log_activity("WARNING", "AUTH", "Signature mismatch", expected=owner[:10], got=recovered_address[:10])
            return {"success": False, "error": "Signature mismatch"}
        
        # Verified! Delete challenge (one-time use)
        del dashboard_challenges[owner]
        
        log_activity("INFO", "AUTH", "✓ Dashboard signature verified", owner=owner[:10])
        
        # ===== SYNC STATUS TRACKING =====
        sync_status = {
            "signature_verified": True,
            "score_synced": False,
            "login_updated": False,
            "resonance_synced": False,
            "nft_checked": False,
            "steps_completed": ["✓ Signature verified"],
            "errors": []
        }
        
        # ===== NFT RETRY LOGIC + NEW USER REGISTRATION =====
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute("SELECT identity_status, identity_mint_tx_hash, score FROM users WHERE address=?", (owner,))
            result = cursor.fetchone()
            
            if not result:
                # ===== NEW USER: First-time Dashboard access =====
                log_activity("INFO", "AUTH", "🆕 First-time dashboard user - creating account", address=owner[:10])
                
                # Create user with initial score
                current_iso = datetime.now(timezone.utc).isoformat()
                cursor.execute(
                    """INSERT INTO users (address, score, created_at, identity_status)
                       VALUES (?, ?, ?, ?)""",
                    (owner, INITIAL_SCORE, current_iso, 'pending')
                )
                conn.commit()
                sync_status["steps_completed"].append("✓ New user account created")
                
                # Sync initial score to blockchain
                log_activity("INFO", "BLOCKCHAIN", "🔄 Syncing initial score", address=owner[:10])
                await sync_score_after_update(owner, INITIAL_SCORE, conn)
                sync_status["steps_completed"].append(f"✓ Initial score {INITIAL_SCORE} synced")
                sync_status["score_synced"] = True
                
                # Wait 2 seconds (nonce conflict prevention)
                await asyncio.sleep(2)
                
                # Mint NFT for new user
                log_activity("INFO", "BLOCKCHAIN", "🎨 Starting Identity NFT mint for new dashboard user", address=owner[:10])
                success, mint_result = await web3_service.mint_identity_nft(owner)
                
                if success:
                    # Extract tx_hash from result dict
                    new_tx_hash = mint_result.get("tx_hash") if isinstance(mint_result, dict) else mint_result
                    cursor.execute(
                        """UPDATE users 
                           SET identity_status='minting', identity_mint_tx_hash=?, identity_minted_at=?
                           WHERE address=?""",
                        (new_tx_hash, current_iso, owner)
                    )
                    conn.commit()
                    log_activity("INFO", "BLOCKCHAIN", "✅ NFT mint transaction sent for new user", 
                                address=owner[:10], 
                                tx_hash=new_tx_hash[:16] + "..." if new_tx_hash else "N/A")
                    sync_status["steps_completed"].append("✓ Identity NFT minting started")
                    sync_status["nft_checked"] = True
                else:
                    error_msg = mint_result
                    cursor.execute("UPDATE users SET identity_status='failed' WHERE address=?", (owner,))
                    conn.commit()
                    log_activity("WARNING", "BLOCKCHAIN", f"NFT minting failed for new user: {error_msg}", address=owner[:10])
                    sync_status["errors"].append(f"NFT mint failed: {str(error_msg)[:50]}")
            
            elif result:
                # ===== EXISTING USER: Check for retry =====
                db_identity_status = result[0]
                tx_hash = result[1]
                current_score = result[2] if len(result) > 2 else INITIAL_SCORE
                
                # ===== SYNC YOUR SCORE FROM REGISTRY CONTRACT ON LOGIN =====
                # Your Score = 50 (Initial) + Interaction Count + Follow Bonuses
                try:
                    log_activity("INFO", "BLOCKCHAIN", "🔄 Reading Your Score from Registry Contract", address=owner[:10])
                    
                    # Get current DB score
                    cursor.execute("SELECT score FROM users WHERE address=?", (owner,))
                    score_data = cursor.fetchone()
                    db_score = score_data[0] if score_data else INITIAL_SCORE
                    
                    # Read interaction count from blockchain (each interaction = 1 point)
                    interaction_count = await web3_service.get_user_interaction_count(owner)
                    
                    # Calculate base score from blockchain: INITIAL_SCORE (50) + interactions
                    blockchain_base_score = INITIAL_SCORE + interaction_count
                    
                    # Calculate follow bonuses (local points not yet on blockchain)
                    # These are points from follow interactions that haven't been synced to blockchain yet
                    follow_bonus = max(0, db_score - blockchain_base_score)
                    
                    # Total score = blockchain base + local follow bonuses
                    total_score = blockchain_base_score + follow_bonus
                    
                    # Only update if blockchain shows more interactions than we have locally
                    # This handles the case where user made onchain interactions we didn't track yet
                    if blockchain_base_score > db_score:
                        # User has more onchain interactions than local score
                        cursor.execute(
                            """UPDATE users SET score=? WHERE address=?""",
                            (blockchain_base_score, owner)
                        )
                        conn.commit()
                        log_activity("INFO", "BLOCKCHAIN", "✓ Your Score synced UP from Registry Contract", 
                                    address=owner[:10], 
                                    old_score=db_score, 
                                    new_score=blockchain_base_score,
                                    interactions=interaction_count)
                        sync_status["steps_completed"].append(f"✓ Score synced UP: {db_score} → {blockchain_base_score}")
                    elif blockchain_base_score < db_score:
                        # Blockchain API returns fewer events than DB score
                        # This can happen due to Blockscout API caching/indexing delays
                        # DO NOT correct score downwards - trust the local DB
                        log_activity("INFO", "BLOCKCHAIN", f"⚠️ Blockscout API lag detected (API: {blockchain_base_score}, DB: {db_score}) - keeping DB score", 
                                    address=owner[:10], 
                                    db_score=db_score, 
                                    api_score=blockchain_base_score,
                                    interactions=interaction_count)
                        sync_status["steps_completed"].append(f"⚠️ Blockscout lag: API shows {blockchain_base_score}, keeping DB score {db_score}")
                    else:
                        # Score is in sync (blockchain_base_score <= db_score and we have follow bonuses)
                        log_activity("INFO", "BLOCKCHAIN", f"✓ Your Score in sync (blockchain: {blockchain_base_score} + follow bonus: {follow_bonus} = {total_score})", 
                                    address=owner[:10], score=db_score, interactions=interaction_count)
                        sync_status["steps_completed"].append(f"✓ Score in sync: {db_score} (base: {blockchain_base_score} + follow: {follow_bonus})")
                    
                    sync_status["score_synced"] = True
                    
                    # Update last_login and login_count
                    current_timestamp = int(time.time())
                    cursor.execute("SELECT last_login, login_count FROM users WHERE address=?", (owner,))
                    login_data = cursor.fetchone()
                    if login_data:
                        last_login = login_data[0] or 0
                        current_login_count = login_data[1] or 0
                        
                        # Only update if last login was more than 60 seconds ago
                        if current_timestamp - last_login > 60:
                            new_login_count = current_login_count + 1
                            cursor.execute(
                                """UPDATE users SET last_login=?, login_count=? WHERE address=?""",
                                (current_timestamp, new_login_count, owner)
                            )
                            conn.commit()
                            sync_status["steps_completed"].append(f"✓ Login #{new_login_count} recorded")
                        else:
                            sync_status["steps_completed"].append("✓ Login count (already recent)")
                    
                    sync_status["login_updated"] = True
                            
                except Exception as score_err:
                    log_activity("WARNING", "BLOCKCHAIN", f"Score sync from Registry failed: {score_err}", address=owner[:10])
                    sync_status["errors"].append(f"Score sync failed: {str(score_err)[:50]}")
                # ===== END SCORE SYNC =====
                
                # ===== BLOCKCHAIN RESONANCE SCORE SYNC ON LOGIN =====
                # Force sync resonance score (total) to blockchain if there's a pending difference >= 2 points
                try:
                    log_activity("INFO", "BLOCKCHAIN", "🔄 Force sync check for Resonance Score", address=owner[:10])
                    await force_sync_on_login(owner, conn)
                    sync_status["resonance_synced"] = True
                    sync_status["steps_completed"].append("✓ Resonance Score blockchain sync checked")
                except Exception as sync_err:
                    log_activity("WARNING", "BLOCKCHAIN", f"Resonance Score sync on login failed: {sync_err}", address=owner[:10])
                    sync_status["errors"].append(f"Resonance sync: {str(sync_err)[:50]}")
                # ===== END RESONANCE SCORE SYNC =====
                
                # RETRY if status is 'minting' without tx_hash OR 'failed'
                if db_identity_status in ['failed', 'pending'] or (db_identity_status == 'minting' and not tx_hash):
                    log_activity("INFO", "BLOCKCHAIN", "🔄 Retry: NFT mint for dashboard login", address=owner[:10])
                    
                    # Check if user already has NFT on-chain
                    has_identity = await web3_service.has_identity_nft(owner)
                    
                    if not has_identity:
                        # Attempt NFT mint
                        success, mint_result = await web3_service.mint_identity_nft(owner)
                        
                        if success:
                            # Extract tx_hash from result dict
                            new_tx_hash = mint_result.get("tx_hash") if isinstance(mint_result, dict) else mint_result
                            cursor.execute(
                                """UPDATE users 
                                   SET identity_status='minting', identity_mint_tx_hash=?, identity_minted_at=?
                                   WHERE address=?""",
                                (new_tx_hash, datetime.now(timezone.utc).isoformat(), owner)
                            )
                            conn.commit()
                            log_activity("INFO", "BLOCKCHAIN", "✅ NFT mint retry successful", 
                                        address=owner[:10], 
                                        tx_hash=new_tx_hash[:16] + "..." if new_tx_hash else "N/A")
                            sync_status["steps_completed"].append("✓ NFT mint initiated")
                        else:
                            error_msg = mint_result
                            cursor.execute("UPDATE users SET identity_status='failed' WHERE address=?", (owner,))
                            conn.commit()
                            log_activity("WARNING", "BLOCKCHAIN", f"NFT retry failed: {error_msg}", address=owner[:10])
                            sync_status["errors"].append(f"NFT mint failed: {str(error_msg)[:50]}")
                    else:
                        # User already has NFT - update status
                        token_id = await web3_service.get_identity_token_id(owner)
                        if token_id is not None:
                            cursor.execute(
                                """UPDATE users 
                                   SET identity_nft_token_id=?, identity_status='active'
                                   WHERE address=?""",
                                (token_id, owner)
                            )
                            conn.commit()
                            log_activity("INFO", "BLOCKCHAIN", "✓ NFT already minted, status updated", 
                                        address=owner[:10], token_id=token_id)
                            sync_status["steps_completed"].append(f"✓ NFT verified (Token #{token_id})")
                else:
                    # NFT status is already OK
                    sync_status["steps_completed"].append(f"✓ NFT status: {db_identity_status}")
                
                sync_status["nft_checked"] = True
            
            # Get NFT status for JWT token before closing connection
            cursor.execute("SELECT identity_status FROM users WHERE address=?", (owner,))
            nft_result = cursor.fetchone()
            has_nft = nft_result and nft_result[0] == 'active' if nft_result else False
            
            conn.close()
        except Exception as e:
            log_activity("WARNING", "BLOCKCHAIN", f"NFT retry check failed: {str(e)}", address=owner[:10])
            sync_status["errors"].append(f"NFT check failed: {str(e)[:50]}")
            has_nft = False
        # ===== END NFT RETRY LOGIC =====
        
        # Generate JWT token for dashboard session
        dashboard_jwt = generate_dashboard_jwt(owner, has_nft)
        log_activity("INFO", "AUTH", "✅ Dashboard JWT token generated", address=owner[:10], has_nft=has_nft)
        
        return {
            "success": True,
            "verified": True,
            "message": "✓ Verified - Dashboard access granted",
            "sync_status": sync_status,
            "jwt_token": dashboard_jwt
        }
    except Exception as e:
        log_activity("ERROR", "AUTH", "Signature verification failed", error=str(e))
        return {"success": False, "error": str(e)}

@app.get("/admin/followers")
async def get_followers_dashboard(req: Request):
    """
    Admin Dashboard - Shows all verified followers for an owner
    
    Query Parameters:
        owner: Owner wallet address (required)
        token: Optional signature for verification
    
    Returns:
        {
            "owner": "0x...",
            "total_followers": 42,
            "followers": [
                {
                    "follower_address": "0x...",
                    "resonance_score": 51,
                    "verified_at": "2025-11-21T10:00:00",
                    "source_platform": "twitter",
                    "verified": true
                }
            ],
            "statistics": {
                "average_score": 65.5,
                "verified_count": 42,
                "by_platform": {"twitter": 15, "discord": 8}
            }
        }
    """
    try:
        # Get owner from query params
        owner_wallet = req.query_params.get("owner", "").lower()
        
        if not owner_wallet:
            return {"error": "owner parameter required", "success": False}
        
        if not owner_wallet.startswith("0x") or len(owner_wallet) != 42:
            return {"error": "Invalid owner wallet format", "success": False}
        
        log_activity("INFO", "ADMIN", "Dashboard requested", owner=owner_wallet[:10])
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get all followers for this owner with CURRENT scores from users table
        cursor.execute("""
            SELECT 
                f.id,
                f.follower_address,
                f.follower_score as original_score,
                COALESCE(u.score, f.follower_score) as current_score,
                f.follower_display_name,
                f.verified_at,
                f.source_platform,
                f.verified,
                u.login_count,
                u.last_login,
                u.created_at,
                u.blockchain_score
            FROM followers f
            LEFT JOIN users u ON f.follower_address = u.address
            WHERE f.owner_wallet = ?
            ORDER BY f.verified_at DESC
        """, (owner_wallet,))
        
        followers = cursor.fetchall()
        
        # Calculate statistics using CURRENT scores
        if followers:
            total_verified = len(followers)
            avg_score = sum(f['current_score'] if f['current_score'] else 0 for f in followers) / len(followers)
            
            # Group by platform
            platform_counts = {}
            for f in followers:
                platform = f['source_platform'] or 'unknown'
                platform_counts[platform] = platform_counts.get(platform, 0) + 1
        else:
            total_verified = 0
            avg_score = 0
            platform_counts = {}
        
        # Get owner stats
        cursor.execute("SELECT score, login_count, created_at FROM users WHERE address=?", (owner_wallet,))
        owner_data = cursor.fetchone()
        
        conn.close()
        
        log_activity("INFO", "ADMIN", "Dashboard returned", 
                    owner=owner_wallet[:10], 
                    followers_count=total_verified)
        
        return {
            "success": True,
            "owner": owner_wallet,
            "owner_score": owner_data['score'] if owner_data else None,
            "total_followers": total_verified,
            "followers": [
                {
                    "follower_address": f['follower_address'],
                    "display_name": f['follower_display_name'],
                    "resonance_score": f['current_score'],  # Current score from users table
                    "original_score": f['original_score'],   # Score at follow time
                    "blockchain_score": f['blockchain_score'],  # On-chain score
                    "verified_at": f['verified_at'],
                    "source_platform": f['source_platform'],
                    "verified": bool(f['verified']),
                    "login_count": f['login_count'] or 0,
                    "last_login": f['last_login']
                }
                for f in followers
            ],
            "statistics": {
                "average_score": round(avg_score, 2),
                "verified_count": total_verified,
                "by_platform": platform_counts,
                "timestamp": int(time.time())
            }
        }
        
    except Exception as e:
        log_activity("ERROR", "ADMIN", f"Dashboard error: {str(e)}")
        return {"error": str(e), "success": False}


@app.post("/api/user/profile-with-follow-status")
async def get_user_profile_with_follow_status(req: Request):
    """
    Get user profile data with mutual follow status check
    
    Request:
        {
            "address": "0x..." (target user to view),
            "viewer": "0x..." (current logged-in user)
        }
    
    Response:
        {
            "success": true,
            "profile": { ... user profile data ... },
            "follow_status": {
                "viewer_follows_target": true/false,
                "target_follows_viewer": true/false,
                "mutual": true/false
            },
            "follow_back_link": "https://..." (if viewer doesn't follow target)
        }
    """
    try:
        data = await req.json()
        target_address = data.get("address", "").lower()
        viewer_address = data.get("viewer", "").lower()
        
        if not target_address or not target_address.startswith("0x") or len(target_address) != 42:
            return {"success": False, "error": "Invalid target address"}
        
        if not viewer_address or not viewer_address.startswith("0x") or len(viewer_address) != 42:
            return {"success": False, "error": "Invalid viewer address"}
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get target user profile
        cursor.execute("""
            SELECT 
                address, display_name, avatar_emoji, score, blockchain_score,
                created_at, identity_status, identity_nft_token_id, first_seen, login_count
            FROM users 
            WHERE LOWER(address) = ?
        """, (target_address,))
        
        user_row = cursor.fetchone()
        
        if not user_row:
            conn.close()
            return {"success": False, "error": "User not found"}
        
        # Calculate Resonance Score with follower bonus
        from resonance_calculator import calculate_resonance_score
        own_score, follower_bonus, follower_count, total_resonance = calculate_resonance_score(target_address, conn)
        
        # Check follow status: Does viewer follow target?
        cursor.execute("""
            SELECT 1 FROM followers 
            WHERE owner_wallet = ? AND follower_address = ?
        """, (target_address, viewer_address))
        viewer_follows_target = cursor.fetchone() is not None
        
        # Check follow status: Does target follow viewer?
        cursor.execute("""
            SELECT 1 FROM followers 
            WHERE owner_wallet = ? AND follower_address = ?
        """, (viewer_address, target_address))
        target_follows_viewer = cursor.fetchone() is not None
        
        # Get community count
        cursor.execute("""
            SELECT COUNT(DISTINCT owner_wallet) as community_count
            FROM telegram_invites 
            WHERE LOWER(address) = ? AND granted = 1
        """, (target_address,))
        community_row = cursor.fetchone()
        community_count = community_row['community_count'] if community_row else 0
        
        conn.close()
        
        # Build follow back link if viewer doesn't follow target yet
        # PRODUCTION FIX: Always use PUBLIC_URL (aeralogin.com)
        follow_back_link = None
        if not viewer_follows_target:
            base_url = PUBLIC_URL
            follow_back_link = f"{base_url}/follow?owner={target_address}&source=followback"
        
        # Build response
        short_addr = target_address[:6] + '...' + target_address[-4:]
        display_name = user_row['display_name'] if user_row['display_name'] else f"Builder {short_addr}"
        
        return {
            "success": True,
            "profile": {
                "address": target_address,
                "short_address": short_addr,
                "display_name": display_name,
                "avatar_emoji": user_row['avatar_emoji'] if user_row['avatar_emoji'] else '👤',
                "score": float(total_resonance) if total_resonance else 0.0,
                "own_score": float(own_score) if own_score else 0.0,
                "follower_bonus": float(follower_bonus) if follower_bonus else 0.0,
                "follower_count": follower_count,
                "blockchain_score": float(user_row['blockchain_score']) if user_row['blockchain_score'] else 0.0,
                "nft_verified": user_row['identity_status'] == 'active' and user_row['identity_nft_token_id'] is not None,
                "token_id": user_row['identity_nft_token_id'],
                "communities": community_count,
                "join_date": user_row['created_at'] or user_row['first_seen'],
                "login_count": user_row['login_count'] or 0
            },
            "follow_status": {
                "viewer_follows_target": viewer_follows_target,
                "target_follows_viewer": target_follows_viewer,
                "mutual": viewer_follows_target and target_follows_viewer
            },
            "follow_back_link": follow_back_link
        }
        
    except Exception as e:
        log_activity("ERROR", "USER_PROFILE", f"Profile with follow status error: {str(e)}")
        return {"success": False, "error": str(e)}


@app.get("/admin/follower-link")
async def generate_follower_link(req: Request):
    """
    Generate a custom follower link for an owner
    
    Query Parameters:
        owner: Owner wallet address (required)
        source: Social media platform (optional: twitter, discord, telegram, etc.)
    
    Returns:
        {
            "owner": "0x...",
            "follower_link": "https://ngrok.url/?owner=0x...&source=twitter",
            "qr_code": "data:image/png;base64,..."
        }
    """
    try:
        owner_wallet = req.query_params.get("owner", "").lower()
        source = req.query_params.get("source", "direct")
        
        if not owner_wallet or not owner_wallet.startswith("0x") or len(owner_wallet) != 42:
            return {"error": "Invalid owner wallet", "success": False}
        
        # PRODUCTION FIX: Always use PUBLIC_URL for follower links
        # Only use ngrok for local development when PUBLIC_URL is localhost
        base_url = PUBLIC_URL
        
        # Only try ngrok detection for LOCAL development (localhost/127.0.0.1)
        if "localhost" in PUBLIC_URL or "127.0.0.1" in PUBLIC_URL:
            if NGROK_URL:
                base_url = NGROK_URL
            else:
                try:
                    import urllib.request
                    ngrok_response = urllib.request.urlopen("http://127.0.0.1:4040/api/tunnels", timeout=2)
                    import json as json_lib
                    tunnels_data = json_lib.loads(ngrok_response.read().decode())
                    tunnels = tunnels_data.get("tunnels", [])
                    for tunnel in tunnels:
                        if tunnel.get("proto") == "https":
                            base_url = tunnel.get("public_url", base_url)
                            break
                except:
                    pass  # Keep PUBLIC_URL if ngrok not available
        
        # Build follower link (using /follow route)
        follower_link = f"{base_url}/follow?owner={owner_wallet}&source={source}"
        
        log_activity("INFO", "ADMIN", "Follower link generated", 
                    owner=owner_wallet[:10], 
                    source=source,
                    base_url=base_url)
        
        return {
            "success": True,
            "owner": owner_wallet,
            "source": source,
            "follower_link": follower_link,
            "base_url": base_url,
            "instructions": {
                "step1": "Share this link with your followers",
                "step2": "They click the link and verify with their wallet",
                "step3": "They appear in your dashboard at /admin/followers?owner=" + owner_wallet,
                "step4": "Track their Resonance Score and engagement"
            }
        }
        
    except Exception as e:
        return {"error": str(e), "success": False}

@app.post("/admin/confirm-follower")
async def confirm_follower(req: Request):
    """
    Confirm a follower from the follower's side (after MetaMask verification)
    
    Request Body:
        {
            "owner": "0x...",
            "follower": "0x..."
        }
    
    Updates followers table to set follow_confirmed = 1
    """
    try:
        data = await req.json()
        owner = data.get("owner", "").lower()
        follower = data.get("follower", "").lower()
        
        if not owner or not owner.startswith("0x") or len(owner) != 42:
            return {"error": "Invalid owner wallet", "success": False}
        
        if not follower or not follower.startswith("0x") or len(follower) != 42:
            return {"error": "Invalid follower wallet", "success": False}
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if follower record exists
        cursor.execute(
            "SELECT * FROM followers WHERE owner_wallet = ? AND follower_address = ?",
            (owner, follower)
        )
        follower_record = cursor.fetchone()
        
        if not follower_record:
            conn.close()
            return {"error": "Follower record not found", "success": False}
        
        # Update to mark as confirmed
        cursor.execute(
            "UPDATE followers SET follow_confirmed = 1, confirmed_at = datetime('now') WHERE owner_wallet = ? AND follower_address = ?",
            (owner, follower)
        )
        conn.commit()
        conn.close()
        
        log_activity("INFO", "ADMIN", "Follow confirmed",
                    owner=owner[:10],
                    follower=follower[:10])
        
        # NOTE: record_interaction() is NOT called here anymore!
        # The blockchain interaction was already recorded when the follower first followed.
        # This endpoint only confirms an existing follow - no duplicate blockchain write needed.
        
        # ===== TRIGGER BLOCKCHAIN SCORE SYNC =====
        # After follow confirmation, check if owner's score needs blockchain sync
        try:
            from resonance_calculator import calculate_resonance_score
            from blockchain_sync import add_to_sync_queue
            
            conn = get_db_connection()
            own, follower_bonus, count, total_resonance = calculate_resonance_score(owner, conn)
            conn.close()
            
            # Check if it's a milestone (every 2 points) and add to sync queue
            if total_resonance > 0 and total_resonance % 2 == 0:
                await add_to_sync_queue(owner, total_resonance)
                logger.info(f"📊 Added {owner[:10]} to sync queue after follow confirmation (score: {total_resonance})")
        except Exception as e:
            logger.warning(f"⚠️ Could not trigger sync after follow confirm: {e}")
        
        return {
            "success": True,
            "message": "Follow request confirmed",
            "owner": owner,
            "follower": follower
        }
        
    except Exception as e:
        logger.error(f"❌ confirm_follower error: {str(e)}")
        return {"error": str(e), "success": False}


# ===== SYSTEM ADMIN PANEL =====
# Admin-only endpoints for comprehensive system statistics

# Admin wallet addresses (case-insensitive comparison)
ADMIN_WALLETS = [
    "0x9de3772a1b2e958561d8371ee34364dcd90967ba",  # Admin
    "0xc9e1e237b24b892141551b45cdabc224932630c4"   # Notfall/Ledger
]

@app.get("/admin-panel", response_class=HTMLResponse)
async def admin_panel():
    """System Admin Panel - Comprehensive stats dashboard (Admin wallets only)"""
    from fastapi.responses import HTMLResponse as HR
    with open(os.path.join(os.path.dirname(__file__), "admin-panel.html"), "r") as f:
        content = f.read()
    return HR(content=content, headers={"Cache-Control": "no-cache, no-store, must-revalidate"})

@app.get("/admin-panel.html", response_class=HTMLResponse)
async def admin_panel_html():
    """System Admin Panel with .html extension"""
    from fastapi.responses import HTMLResponse as HR
    with open(os.path.join(os.path.dirname(__file__), "admin-panel.html"), "r") as f:
        content = f.read()
    return HR(content=content, headers={"Cache-Control": "no-cache, no-store, must-revalidate"})

@app.get("/api/admin/stats")
async def get_admin_stats(req: Request):
    """
    Comprehensive admin statistics endpoint.
    Returns system health, user stats, auth monitoring, gate overview, and funnel data.
    
    Query Parameters:
        wallet: Admin wallet address (required for authentication)
        period: Time period filter (24h, 7d, 30d, all) - default: 7d
    
    Security: Only accessible by admin wallets defined in ADMIN_WALLETS
    """
    try:
        # Verify admin wallet
        wallet = req.query_params.get("wallet", "").lower()
        period = req.query_params.get("period", "7d")
        
        if not wallet:
            return {"error": "Wallet address required", "success": False, "code": 401}
        
        if wallet not in ADMIN_WALLETS:
            log_activity("WARN", "ADMIN", "Unauthorized admin access attempt", address=wallet[:10])
            return {"error": "Unauthorized: Admin access only", "success": False, "code": 403}
        
        log_activity("INFO", "ADMIN", "Admin stats requested", address=wallet[:10], period=period)
        
        # Calculate time filter
        now = int(time.time())
        if period == "24h":
            time_filter = now - (24 * 60 * 60)
        elif period == "7d":
            time_filter = now - (7 * 24 * 60 * 60)
        elif period == "30d":
            time_filter = now - (30 * 24 * 60 * 60)
        else:  # all
            time_filter = 0
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # ===== SYSTEM STATUS =====
        system_status = {
            "backend_online": True,
            "server_uptime": "Running",  # Could be enhanced with actual uptime tracking
            "database_status": "Connected",
            "last_check": datetime.now().isoformat()
        }
        
        # Check bot status (look for recent bot activity in events)
        cursor.execute("""
            SELECT COUNT(*) as count FROM events 
            WHERE event_type LIKE '%bot%' AND timestamp > ?
        """, (now - 3600,))  # Last hour
        bot_activity = cursor.fetchone()['count']
        system_status["bots_active"] = bot_activity > 0
        
        # Recent errors (events with error type)
        cursor.execute("""
            SELECT COUNT(*) as count FROM events 
            WHERE event_type LIKE '%error%' AND timestamp > ?
        """, (time_filter,))
        error_count = cursor.fetchone()['count']
        system_status["error_count"] = error_count
        
        # ===== USER OVERVIEW =====
        # Total users
        cursor.execute("SELECT COUNT(*) as total FROM users")
        total_users = cursor.fetchone()['total']
        
        # Active users in period
        cursor.execute("""
            SELECT COUNT(*) as count FROM users 
            WHERE last_login > ?
        """, (time_filter,))
        active_users = cursor.fetchone()['count']
        
        # New users in period
        cursor.execute("""
            SELECT COUNT(*) as count FROM users 
            WHERE first_seen > ?
        """, (time_filter,))
        new_users = cursor.fetchone()['count']
        
        # Online now (last 5 minutes)
        cursor.execute("""
            SELECT COUNT(*) as count FROM users 
            WHERE last_login > ?
        """, (now - 300,))
        online_now = cursor.fetchone()['count']
        
        # Average score
        cursor.execute("SELECT AVG(score) as avg_score FROM users")
        avg_score_row = cursor.fetchone()
        avg_score = round(avg_score_row['avg_score'], 1) if avg_score_row['avg_score'] else 0
        
        # Score distribution
        cursor.execute("""
            SELECT 
                CASE 
                    WHEN score < 50 THEN '0-49'
                    WHEN score < 75 THEN '50-74'
                    WHEN score < 100 THEN '75-99'
                    WHEN score < 150 THEN '100-149'
                    ELSE '150+'
                END as range,
                COUNT(*) as count
            FROM users
            GROUP BY range
            ORDER BY range
        """)
        score_distribution = {row['range']: row['count'] for row in cursor.fetchall()}
        
        user_stats = {
            "total_users": total_users,
            "active_users": active_users,
            "new_users": new_users,
            "online_now": online_now,
            "average_score": avg_score,
            "score_distribution": score_distribution
        }
        
        # ===== AUTH MONITORING =====
        # Total logins
        cursor.execute("""
            SELECT COUNT(*) as count FROM events 
            WHERE event_type = 'login' AND timestamp > ?
        """, (time_filter,))
        total_logins = cursor.fetchone()['count']
        
        # SIWE verifications (successful logins with signature)
        cursor.execute("""
            SELECT COUNT(*) as count FROM events 
            WHERE event_type IN ('login', 'siwe_verify', 'wallet_verify') AND timestamp > ?
        """, (time_filter,))
        siwe_logins = cursor.fetchone()['count']
        
        # Failed logins (if tracked)
        cursor.execute("""
            SELECT COUNT(*) as count FROM events 
            WHERE event_type LIKE '%fail%' AND timestamp > ?
        """, (time_filter,))
        failed_logins = cursor.fetchone()['count']
        
        # OAuth sessions (active and not expired)
        cursor.execute("""
            SELECT COUNT(*) as count FROM oauth_sessions 
            WHERE is_active = 1 AND datetime(expires_at) > datetime('now')
        """)
        active_oauth_sessions = cursor.fetchone()['count']
        
        # Total OAuth sessions (for audit overview)
        cursor.execute("SELECT COUNT(*) as count FROM oauth_sessions")
        total_oauth_sessions = cursor.fetchone()['count']
        
        # Deactivated sessions (audit trail)
        cursor.execute("SELECT COUNT(*) as count FROM oauth_sessions WHERE is_active = 0")
        deactivated_oauth_sessions = cursor.fetchone()['count']
        
        # OAuth clients
        cursor.execute("SELECT COUNT(*) as count FROM oauth_clients WHERE is_active = 1")
        active_oauth_clients = cursor.fetchone()['count']
        
        # Logins by referrer source
        cursor.execute("""
            SELECT referrer, COUNT(*) as count FROM events 
            WHERE event_type = 'login' AND timestamp > ? AND referrer IS NOT NULL
            GROUP BY referrer
            ORDER BY count DESC
            LIMIT 10
        """, (time_filter,))
        logins_by_source = {row['referrer']: row['count'] for row in cursor.fetchall()}
        
        auth_stats = {
            "total_logins": total_logins,
            "siwe_verifications": siwe_logins,
            "failed_logins": failed_logins,
            "active_oauth_sessions": active_oauth_sessions,
            "active_oauth_clients": active_oauth_clients,
            "logins_by_source": logins_by_source,
            # Audit data
            "total_oauth_sessions_audit": total_oauth_sessions,
            "deactivated_oauth_sessions": deactivated_oauth_sessions
        }
        
        # ===== GATE OVERVIEW =====
        # Total gates
        cursor.execute("SELECT COUNT(*) as count FROM owner_gate_configs WHERE is_active = 1")
        total_gates = cursor.fetchone()['count']
        
        # Gates by platform
        cursor.execute("""
            SELECT platform, COUNT(*) as count FROM owner_gate_configs 
            WHERE is_active = 1
            GROUP BY platform
        """)
        gates_by_platform = {row['platform']: row['count'] for row in cursor.fetchall()}
        
        # Total gate passages (telegram_invites)
        cursor.execute("""
            SELECT COUNT(*) as count FROM telegram_invites 
            WHERE granted = 1
        """)
        total_passages = cursor.fetchone()['count']
        
        # Recent passages in period
        cursor.execute("""
            SELECT COUNT(*) as count FROM telegram_invites 
            WHERE granted = 1 AND datetime(invited_at) > datetime(?, 'unixepoch')
        """, (time_filter,))
        recent_passages = cursor.fetchone()['count']
        
        # Top gates by passage count (include group_id in JOIN and GROUP BY for multi-gate support)
        cursor.execute("""
            SELECT 
                g.owner_wallet,
                g.platform,
                g.group_name,
                g.group_id,
                COUNT(i.id) as passage_count
            FROM owner_gate_configs g
            LEFT JOIN telegram_invites i ON g.owner_wallet = i.owner_wallet 
                AND g.platform = i.platform 
                AND g.group_id = i.group_id
            WHERE g.is_active = 1
            GROUP BY g.owner_wallet, g.platform, g.group_id
            ORDER BY passage_count DESC
            LIMIT 10
        """)
        top_gates = [
            {
                "owner": row['owner_wallet'][:10] + "..." if row['owner_wallet'] else "Unknown",
                "platform": row['platform'],
                "name": row['group_name'] or "Unnamed Gate",
                "passages": row['passage_count']
            }
            for row in cursor.fetchall()
        ]
        
        gate_stats = {
            "total_gates": total_gates,
            "gates_by_platform": gates_by_platform,
            "total_passages": total_passages,
            "recent_passages": recent_passages,
            "top_gates": top_gates
        }
        
        # ===== FUNNEL ANALYSIS =====
        # Landing page visits (if tracked via events)
        cursor.execute("""
            SELECT COUNT(*) as count FROM events 
            WHERE event_type IN ('page_view', 'landing_visit') AND timestamp > ?
        """, (time_filter,))
        landing_visits = cursor.fetchone()['count'] or total_logins * 3  # Estimate if not tracked
        
        # Login starts
        cursor.execute("""
            SELECT COUNT(*) as count FROM events 
            WHERE event_type IN ('login_start', 'wallet_connect') AND timestamp > ?
        """, (time_filter,))
        login_starts = cursor.fetchone()['count'] or total_logins  # Use actual logins as minimum
        
        # Successful logins (dashboard reached)
        dashboard_reached = total_logins
        
        # Gate passage attempts
        cursor.execute("""
            SELECT COUNT(*) as count FROM telegram_invites 
            WHERE datetime(invited_at) > datetime(?, 'unixepoch')
        """, (time_filter,))
        gate_attempts = cursor.fetchone()['count']
        
        funnel_data = {
            "landing_visits": landing_visits,
            "login_starts": login_starts,
            "logins_completed": dashboard_reached,
            "gate_passages": gate_attempts,
            "conversion_rates": {
                "login_start_rate": round((login_starts / landing_visits * 100), 1) if landing_visits > 0 else 0,
                "login_complete_rate": round((dashboard_reached / login_starts * 100), 1) if login_starts > 0 else 0,
                "gate_passage_rate": round((gate_attempts / dashboard_reached * 100), 1) if dashboard_reached > 0 else 0
            }
        }
        
        # ===== FOLLOWERS OVERVIEW =====
        cursor.execute("SELECT COUNT(*) as count FROM followers")
        total_followers = cursor.fetchone()['count']
        
        cursor.execute("""
            SELECT COUNT(*) as count FROM followers 
            WHERE datetime(verified_at) > datetime(?, 'unixepoch')
        """, (time_filter,))
        new_followers = cursor.fetchone()['count']
        
        follower_stats = {
            "total_followers": total_followers,
            "new_followers": new_followers
        }
        
        # ===== NFT & TOKEN STATS =====
        # Minted Identity NFTs (active status)
        cursor.execute("""
            SELECT COUNT(*) as count FROM users 
            WHERE identity_status = 'active' AND identity_nft_token_id IS NOT NULL
        """)
        minted_nfts = cursor.fetchone()['count']
        
        # NFTs currently minting
        cursor.execute("""
            SELECT COUNT(*) as count FROM users 
            WHERE identity_status = 'minting'
        """)
        minting_nfts = cursor.fetchone()['count']
        
        # Failed NFT mints
        cursor.execute("""
            SELECT COUNT(*) as count FROM users 
            WHERE identity_status = 'failed'
        """)
        failed_nfts = cursor.fetchone()['count']
        
        # Total Resonance Score Tokens in circulation (sum of all blockchain_scores)
        cursor.execute("""
            SELECT COALESCE(SUM(blockchain_score), 0) as total FROM users 
            WHERE blockchain_score IS NOT NULL AND blockchain_score > 0
        """)
        total_tokens_circulation = cursor.fetchone()['total']
        
        # Users with tokens on-chain
        cursor.execute("""
            SELECT COUNT(*) as count FROM users 
            WHERE blockchain_score IS NOT NULL AND blockchain_score > 0
        """)
        users_with_tokens = cursor.fetchone()['count']
        
        # Average tokens per user (on-chain)
        avg_tokens_per_user = round(total_tokens_circulation / users_with_tokens, 1) if users_with_tokens > 0 else 0
        
        # Highest blockchain score
        cursor.execute("""
            SELECT MAX(blockchain_score) as max_score FROM users
        """)
        highest_score = cursor.fetchone()['max_score'] or 0
        
        # ===== PROFILE NFT STATS =====
        # Total Profile NFTs minted
        cursor.execute("""
            SELECT COUNT(*) as count FROM users 
            WHERE profile_nft_token_id IS NOT NULL
        """)
        profile_nfts_minted = cursor.fetchone()['count']
        
        # Profile NFTs by visibility
        cursor.execute("""
            SELECT profile_nft_visibility, COUNT(*) as count FROM users 
            WHERE profile_nft_token_id IS NOT NULL
            GROUP BY profile_nft_visibility
        """)
        profile_visibility = {row['profile_nft_visibility']: row['count'] for row in cursor.fetchall()}
        
        # ===== BLOCKCHAIN DATA (via Alchemy API) =====
        blockchain_data = {
            "identity_nfts_onchain": None,
            "profile_nfts_onchain": None,
            "total_resonance_onchain": None,
            "sync_status": "unknown"
        }
        
        try:
            import urllib.request
            import json as json_lib
            
            ALCHEMY_URL = os.getenv("BASE_ALCHEMY_API_URL", "")
            ALCHEMY_API_KEY = ALCHEMY_URL.split("/v2/")[-1] if "/v2/" in ALCHEMY_URL else None
            IDENTITY_NFT = os.getenv("IDENTITY_NFT_ADDRESS", "0xF9ff5DC523927B9632049bd19e17B610E9197d53")
            PROFILE_NFT = os.getenv("PROFILE_NFT_ADDRESS", "")
            RESONANCE_SCORE = os.getenv("RESONANCE_SCORE_ADDRESS", "0x9A814DBF7E2352CE9eA6293b4b731B2a24800102")
            
            if ALCHEMY_API_KEY:
                # Get Identity NFT count from blockchain
                identity_url = f"https://base-mainnet.g.alchemy.com/nft/v3/{ALCHEMY_API_KEY}/getOwnersForContract?contractAddress={IDENTITY_NFT}&withTokenBalances=true"
                with urllib.request.urlopen(identity_url, timeout=5) as resp:
                    data = json_lib.loads(resp.read().decode())
                    blockchain_data["identity_nfts_onchain"] = len(data.get("owners", []))
                
                # Get Profile NFT count if configured
                if PROFILE_NFT:
                    profile_url = f"https://base-mainnet.g.alchemy.com/nft/v3/{ALCHEMY_API_KEY}/getOwnersForContract?contractAddress={PROFILE_NFT}&withTokenBalances=true"
                    with urllib.request.urlopen(profile_url, timeout=5) as resp:
                        data = json_lib.loads(resp.read().decode())
                        blockchain_data["profile_nfts_onchain"] = len(data.get("owners", []))
                
                # Get Resonance Score totalSupply via RPC call
                if RESONANCE_SCORE and ALCHEMY_URL:
                    payload = {
                        'jsonrpc': '2.0',
                        'method': 'eth_call',
                        'params': [{
                            'to': RESONANCE_SCORE,
                            'data': '0x18160ddd'  # totalSupply()
                        }, 'latest'],
                        'id': 1
                    }
                    req = urllib.request.Request(ALCHEMY_URL, 
                        data=json_lib.dumps(payload).encode(),
                        headers={'Content-Type': 'application/json'})
                    with urllib.request.urlopen(req, timeout=5) as resp:
                        data = json_lib.loads(resp.read().decode())
                        result = data.get('result', '0x0')
                        blockchain_data["total_resonance_onchain"] = int(result, 16)
                
                # Check sync status for Identity NFTs
                if blockchain_data["identity_nfts_onchain"] is not None:
                    if blockchain_data["identity_nfts_onchain"] == minted_nfts:
                        blockchain_data["sync_status"] = "synced"
                    elif blockchain_data["identity_nfts_onchain"] > minted_nfts:
                        blockchain_data["sync_status"] = f"db_behind_{blockchain_data['identity_nfts_onchain'] - minted_nfts}"
                    else:
                        blockchain_data["sync_status"] = f"db_ahead_{minted_nfts - blockchain_data['identity_nfts_onchain']}"
                
                # Check sync status for Resonance Tokens
                if blockchain_data["total_resonance_onchain"] is not None:
                    onchain = blockchain_data["total_resonance_onchain"]
                    db_total = int(total_tokens_circulation)
                    diff = onchain - db_total
                    if diff == 0:
                        blockchain_data["resonance_sync_status"] = "synced"
                    elif diff > 0:
                        blockchain_data["resonance_sync_status"] = f"db_behind_{diff}_tokens"
                    else:
                        blockchain_data["resonance_sync_status"] = f"db_ahead_{abs(diff)}_tokens"
                        
        except Exception as bc_err:
            logger.warning(f"⚠️ Blockchain data fetch failed: {bc_err}")
            blockchain_data["sync_status"] = f"error: {str(bc_err)[:50]}"
        
        nft_token_stats = {
            "minted_nfts": minted_nfts,
            "minted_nfts_onchain": blockchain_data["identity_nfts_onchain"],
            "minting_nfts": minting_nfts,
            "failed_nfts": failed_nfts,
            "total_tokens_circulation": int(total_tokens_circulation),
            "total_tokens_onchain": blockchain_data["total_resonance_onchain"],
            "resonance_sync_status": blockchain_data.get("resonance_sync_status", "unknown"),
            "users_with_tokens": users_with_tokens,
            "avg_tokens_per_user": avg_tokens_per_user,
            "highest_score": int(highest_score),
            "profile_nfts_minted": profile_nfts_minted,
            "profile_nfts_onchain": blockchain_data["profile_nfts_onchain"],
            "profile_nfts_public": profile_visibility.get('public', 0),
            "profile_nfts_private": profile_visibility.get('private', 0),
            "blockchain_sync_status": blockchain_data["sync_status"]
        }
        
        # ===== PAGE VIEW STATS =====
        page_types = ['landing', 'dashboard', 'user-dashboard', 'privacy', 'security', 'admin']
        page_view_stats = {}
        
        for page in page_types:
            # Period count
            cursor.execute("""
                SELECT COUNT(*) as count FROM events 
                WHERE event_type = ? AND timestamp > ?
            """, (f"pageview_{page}", time_filter))
            page_view_stats[page.replace('-', '_')] = cursor.fetchone()['count']
            
            # All-time count
            cursor.execute("""
                SELECT COUNT(*) as count FROM events 
                WHERE event_type = ?
            """, (f"pageview_{page}",))
            page_view_stats[f"{page.replace('-', '_')}_all"] = cursor.fetchone()['count']
        
        # Total views
        cursor.execute("""
            SELECT COUNT(*) as count FROM events 
            WHERE event_type LIKE 'pageview_%' AND timestamp > ?
        """, (time_filter,))
        page_view_stats['total'] = cursor.fetchone()['count']
        
        cursor.execute("""
            SELECT COUNT(*) as count FROM events 
            WHERE event_type LIKE 'pageview_%'
        """)
        page_view_stats['total_all'] = cursor.fetchone()['count']
        
        conn.close()
        
        return {
            "success": True,
            "period": period,
            "generated_at": datetime.now().isoformat(),
            "system_status": system_status,
            "user_stats": user_stats,
            "auth_stats": auth_stats,
            "gate_stats": gate_stats,
            "funnel_data": funnel_data,
            "follower_stats": follower_stats,
            "nft_token_stats": nft_token_stats,
            "page_view_stats": page_view_stats
        }
        
    except Exception as e:
        logger.error(f"❌ Admin stats error: {str(e)}")
        return {"error": str(e), "success": False}

@app.get("/api/admin/verify")
async def verify_admin(req: Request):
    """
    Verify if a wallet address has admin access.
    
    Query Parameters:
        wallet: Wallet address to verify
    
    Returns:
        {
            "is_admin": true/false,
            "wallet": "0x..."
        }
    """
    wallet = req.query_params.get("wallet", "").lower()
    
    if not wallet:
        return {"error": "Wallet address required", "success": False}
    
    is_admin = wallet in ADMIN_WALLETS
    
    if is_admin:
        log_activity("INFO", "ADMIN", "Admin verified", address=wallet[:10])
    
    return {
        "success": True,
        "is_admin": is_admin,
        "wallet": wallet
    }


# ===== BLOCKCHAIN SYNC DEBUG ENDPOINTS =====

@app.get("/api/blockchain/sync-queue")
async def get_sync_queue():
    """Debug: Zeigt aktuelle Sync Queue"""
    from blockchain_sync import sync_queue
    return {
        "queue_size": len(sync_queue),
        "items": [
            {
                "address": item["address"][:10] + "...",
                "score": item["score"],
                "attempts": item["attempts"],
                "last_attempt": item["last_attempt"].isoformat() if item.get("last_attempt") else None
            }
            for item in sync_queue
        ]
    }

@app.post("/api/blockchain/trigger-sync/{address}")
async def trigger_sync(address: str):
    """Debug: Triggert manuellen Sync für User"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT score, blockchain_score FROM users WHERE LOWER(address) = LOWER(?)", (address,))
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return {"error": "User not found", "success": False}
        
        db_score, blockchain_score = result
        blockchain_score = blockchain_score or 0
        
        from blockchain_sync import add_to_sync_queue, should_sync_score
        
        if should_sync_score(db_score, blockchain_score):
            add_to_sync_queue(address, db_score)
            return {
                "success": True,
                "message": f"Added {address[:10]}... to sync queue",
                "db_score": db_score,
                "blockchain_score": blockchain_score
            }
        else:
            return {
                "success": False,
                "message": "User does not meet sync criteria",
                "db_score": db_score,
                "blockchain_score": blockchain_score,
                "next_milestone": ((db_score // 10) + 1) * 10
            }
    
    except Exception as e:
        logger.error(f"❌ trigger_sync error: {str(e)}")
        return {"error": str(e), "success": False}

# ============================================
# ANONYMOUS PAGE VIEW TRACKING (GDPR-compliant)
# ============================================
@app.post("/api/track/pageview")
async def track_pageview(request: Request):
    """Track anonymous page views without personal data"""
    try:
        data = await request.json()
        page = data.get("page", "unknown")
        
        # Only track known pages
        allowed_pages = ["landing", "dashboard", "admin", "follow", "privacy", "security", "user-dashboard"]
        if page not in allowed_pages:
            return {"success": False, "error": "Invalid page"}
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Insert anonymous page view event (using existing schema)
        cursor.execute("""
            INSERT INTO events (event_type, timestamp, created_at)
            VALUES (?, strftime('%s', 'now'), datetime('now'))
        """, (f"pageview_{page}",))
        
        conn.commit()
        conn.close()
        
        return {"success": True}
    except Exception as e:
        logger.error(f"Track pageview error: {str(e)}")
        return {"success": False}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host=HOST,
        port=PORT,
        log_level=os.getenv("LOG_LEVEL", "info").lower()
    )
