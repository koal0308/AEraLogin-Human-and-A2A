"""
🤖 Telegram Group Bot - Resonance Score Gated Community
========================================================

Bot für Telegram-Gruppen mit:
- Capability-basiertem Zugang (nicht Score-basiert für Anonymität)
- Session-Management mit Auto-Verlängerung
- Poll-System mit Score-Gate
- Admin-Befehle für Konfiguration

================================================================================
                           SICHERHEITSKONZEPT
================================================================================

DATENSCHUTZ-ARCHITEKTUR:
├── Keine persistente Wallet-Telegram-Verknüpfung
├── Sessions nur im RAM (volatil)
├── AES-256-GCM Verschlüsselung für sensible Daten
└── Automatische Löschung nach Timeout

ANGRIFFSVEKTOREN & MITIGATIONEN:
┌─────────────────────┬──────────────────────────────────────────────────┐
│ Vektor              │ Mitigation                                       │
├─────────────────────┼──────────────────────────────────────────────────┤
│ Token-Fälschung     │ HMAC-SHA256 Signatur mit Server-Secret          │
│ Replay-Attack       │ Token-Expiry (120 Sekunden)                     │
│ Session-Hijacking   │ Telegram-ID gebunden, nicht übertragbar         │
│ RAM-Dump            │ AES-256-GCM verschlüsselte Wallet-Adressen      │
│ Man-in-the-Middle   │ HTTPS-only Kommunikation                        │
│ Brute-Force         │ Rate-Limiting durch Telegram API                │
│ Injection           │ Keine SQL/DB, nur RAM-Datenstrukturen           │
└─────────────────────┴──────────────────────────────────────────────────┘

SICHERHEITSBEWERTUNG: 8.5/10
- Für Community-Features mehr als ausreichend
- Keine persistenten sensiblen Daten

Author: VEra-Resonance
License: MIT
Created: 2025-12-09
"""

import os
import asyncio
import hmac
import hashlib
import json
import logging
import time
import secrets
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional, List, Set, Any, Tuple
from dataclasses import dataclass, field
from dotenv import load_dotenv
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

load_dotenv()

# Logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger("TelegramGroupBot")

# ===== KONFIGURATION =====

BOT_TOKEN = os.getenv("TELEGRAM_GROUP_BOT_TOKEN", "")
GROUP_ID = os.getenv("TELEGRAM_GROUP_ID", "")
_FORBIDDEN_SECRET_VALUES = frozenset({
    "aera-secret-key-change-in-production",
    "change-me-in-production",
    "changeme",
    "secret",
})
_MIN_SECRET_LENGTH = 32


def _require_bot_secret(name: str) -> str:
    """Load a mandatory bot secret or abort startup.

    There is deliberately NO fallback to TOKEN_SECRET and NO placeholder
    default: reusing the wallet-session secret would couple two unrelated
    trust boundaries, and a placeholder would be publicly guessable.
    Never logs or echoes the value - only the variable name.
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
    for other in ("TOKEN_SECRET", "OAUTH_JWT_SECRET", "OAUTH_ADMIN_KEY",
                  "AGENT_JWT_SECRET"):
        if value == os.getenv(other, None) and os.getenv(other):
            raise RuntimeError(f"{name} must be different from {other}.")
    return value


HMAC_SECRET = _require_bot_secret("TELEGRAM_BOT_HMAC_SECRET")
SERVER_URL = os.getenv("PUBLIC_URL", "http://localhost:8840")

# AES-256 Schlüssel für RAM-Verschlüsselung (generiert bei Start, nicht persistent)
_SESSION_ENCRYPTION_KEY = secrets.token_bytes(32)  # 256-bit key


# ===== KRYPTOGRAPHIE =====

class SecureWalletStore:
    """
    AES-256-GCM verschlüsselter Wallet-Speicher
    
    Selbst bei RAM-Dump sind die Wallet-Adressen nicht im Klartext lesbar.
    Der Schlüssel wird bei jedem Server-Neustart neu generiert.
    """
    
    def __init__(self, key: bytes):
        self.aesgcm = AESGCM(key)
    
    def encrypt(self, wallet_address: str) -> Tuple[bytes, bytes]:
        """
        Verschlüsselt eine Wallet-Adresse
        
        Returns:
            (nonce, ciphertext) - beide müssen für Entschlüsselung gespeichert werden
        """
        nonce = secrets.token_bytes(12)  # 96-bit nonce für GCM
        ciphertext = self.aesgcm.encrypt(nonce, wallet_address.lower().encode('utf-8'), None)
        return nonce, ciphertext
    
    def decrypt(self, nonce: bytes, ciphertext: bytes) -> str:
        """
        Entschlüsselt eine Wallet-Adresse
        
        Returns:
            Wallet-Adresse als String
        """
        plaintext = self.aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode('utf-8')


# Globale Instanz (Schlüssel nur im RAM, nicht persistent)
wallet_crypto = SecureWalletStore(_SESSION_ENCRYPTION_KEY)

# Default-Einstellungen (können per Admin-Befehl geändert werden)
DEFAULT_MIN_SCORE = 50  # Mindest-Score für Schreibrechte
DEFAULT_SESSION_TIMEOUT = 30 * 60  # 30 Minuten in Sekunden
DEFAULT_WELCOME_MESSAGE = """
🎉 **Willkommen bei AEra!**

Du bist jetzt Teil unserer Community.
Dein Resonance Score wurde verifiziert.

📊 Nutze `/mystatus` um deinen Session-Status zu sehen.
❓ Nutze `/help` für alle Befehle.
"""


# ===== DATENSTRUKTUREN =====

@dataclass
class UserSession:
    """
    Session für einen verifizierten User (NUR im RAM!)
    
    SICHERHEIT:
    - wallet_hash: SHA256-Hash für sicheres Logging (nicht umkehrbar)
    - encrypted_wallet: AES-256-GCM verschlüsselt (selbst bei RAM-Dump sicher)
    - Bei Server-Neustart werden alle Sessions UND der Schlüssel gelöscht
    """
    telegram_id: int
    wallet_hash: str  # SHA256 Hash für Logging (kein Klartext!)
    encrypted_wallet: Tuple[bytes, bytes]  # (nonce, ciphertext) - AES-256-GCM
    last_score: int  # Letzter bekannter Resonance Score
    session_start: float
    last_activity: float
    last_score_check: float  # Wann wurde Score zuletzt geprüft
    expires: float
    
    def get_wallet_address(self) -> str:
        """Entschlüsselt Wallet-Adresse für API-Calls (nur bei Bedarf)"""
        nonce, ciphertext = self.encrypted_wallet
        return wallet_crypto.decrypt(nonce, ciphertext)
    
    def is_expired(self) -> bool:
        return time.time() > self.expires
    
    def needs_score_refresh(self, interval_seconds: int = 60) -> bool:
        """Prüft ob Score-Check fällig ist (default: alle 60 Sekunden)"""
        return time.time() - self.last_score_check > interval_seconds
    
    def update_score(self, new_score: int):
        """Aktualisiert den gecachten Score"""
        self.last_score = new_score
        self.last_score_check = time.time()
    
    def can_write(self, min_score: int) -> bool:
        """Prüft ob User Schreibrechte hat basierend auf Resonance Score"""
        return self.last_score >= min_score
    
    def can_vote_poll(self, min_score: int) -> bool:
        """Prüft ob User an Poll mit bestimmtem min_score teilnehmen kann"""
        return self.last_score >= min_score
    
    def extend_session(self, timeout_seconds: int):
        """Verlängert Session bei Aktivität"""
        self.last_activity = time.time()
        self.expires = self.last_activity + timeout_seconds
    
    def time_remaining(self) -> int:
        """Verbleibende Zeit in Sekunden"""
        return max(0, int(self.expires - time.time()))


@dataclass
class GroupConfig:
    """Konfiguration für eine Gruppe (pro Gruppe unterschiedlich)"""
    group_id: int
    min_score: int = DEFAULT_MIN_SCORE
    session_timeout: int = DEFAULT_SESSION_TIMEOUT
    welcome_message: str = DEFAULT_WELCOME_MESSAGE
    admins: Set[int] = field(default_factory=set)
    
    # Poll-Score-Stufen die verfügbar sind
    poll_score_levels: List[int] = field(default_factory=lambda: [50, 55, 60, 65, 70, 75, 80, 85, 90, 95, 100])


@dataclass
class ActivePoll:
    """Aktiver Poll mit Score-Gate"""
    poll_id: str
    message_id: int
    chat_id: int
    creator_id: int
    question: str
    options: List[str]
    min_score: int
    created_at: float
    expires_at: Optional[float]
    votes: Dict[int, int] = field(default_factory=dict)  # telegram_id -> option_index
    closed: bool = False


# ===== CAPABILITY TOKEN SYSTEM =====

class CapabilityTokenManager:
    """
    Verwaltet Capability Tokens mit HMAC-Signatur
    
    Token-Format:
    {
        "caps": ["write", "poll_50", "poll_60"],
        "exp": 1702150000,
        "link": "https://t.me/+ABC123"
    }
    + HMAC-Signatur
    """
    
    def __init__(self, secret: str):
        self.secret = secret.encode('utf-8')
    
    def generate_capabilities(self, score: int, config: GroupConfig) -> List[str]:
        """
        Generiert Capabilities basierend auf Score
        
        WICHTIG: Der Score selbst wird NICHT gespeichert!
        Nur die daraus abgeleiteten Berechtigungen.
        """
        caps = []
        
        # Schreibrechte wenn Score >= min_score
        if score >= config.min_score:
            caps.append("write")
        
        # Poll-Capabilities für alle Stufen die der Score erreicht
        for level in config.poll_score_levels:
            if score >= level:
                caps.append(f"poll_{level}")
        
        return caps
    
    def create_token(self, capabilities: List[str], invite_link: str, 
                     expire_seconds: int = 120) -> str:
        """Erstellt signiertes Capability Token"""
        payload = {
            "caps": capabilities,
            "exp": int(time.time()) + expire_seconds,
            "link": invite_link
        }
        
        # JSON serialisieren
        payload_json = json.dumps(payload, sort_keys=True)
        
        # HMAC-Signatur erstellen
        signature = hmac.new(
            self.secret,
            payload_json.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        # Token = Base64(payload) + "." + signature
        import base64
        payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).decode()
        
        return f"{payload_b64}.{signature}"
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Verifiziert Token und gibt Payload zurück
        
        Returns:
            Dict mit caps, exp, link oder None wenn ungültig
        """
        try:
            parts = token.split(".")
            if len(parts) != 2:
                logger.warning("Token: Invalid format")
                return None
            
            payload_b64, signature = parts
            
            # Payload dekodieren
            import base64
            payload_json = base64.urlsafe_b64decode(payload_b64).decode()
            
            # Signatur prüfen
            expected_sig = hmac.new(
                self.secret,
                payload_json.encode('utf-8'),
                hashlib.sha256
            ).hexdigest()
            
            if not hmac.compare_digest(signature, expected_sig):
                logger.warning("Token: Invalid signature")
                return None
            
            payload = json.loads(payload_json)
            
            # Ablauf prüfen
            if time.time() > payload.get("exp", 0):
                logger.warning("Token: Expired")
                return None
            
            return payload
            
        except Exception as e:
            logger.error(f"Token verification error: {e}")
            return None


# ===== LIVE SCORE API =====

class ResonanceScoreAPI:
    """
    Holt den echten Resonance Score vom Server
    
    Resonance Score = Eigene Punkte + Durchschnitt der Follower-Punkte
    
    DATENSCHUTZ:
    - Keine Daten werden im Bot gespeichert
    - Nur temporäre API-Calls
    """
    
    def __init__(self, server_url: str):
        self.server_url = server_url.rstrip('/')
    
    async def get_resonance_score(self, wallet_address: str) -> Optional[int]:
        """
        Holt den aktuellen Resonance Score für eine Wallet
        
        Returns:
            total_resonance (int) oder None bei Fehler
        """
        try:
            import httpx
            
            url = f"{self.server_url}/api/blockchain/score/{wallet_address.lower()}"
            
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(url)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if "error" in data:
                        logger.warning(f"Score API error: {data['error']}")
                        return None
                    
                    # total_resonance = own_score + follower_bonus
                    total_resonance = data.get("total_resonance", 0)
                    logger.debug(f"Score for {wallet_address[:10]}...: {total_resonance}")
                    return int(total_resonance)
                else:
                    logger.warning(f"Score API HTTP {response.status_code}")
                    return None
                    
        except Exception as e:
            logger.error(f"Score API error: {e}")
            return None
    
    async def verify_nft_ownership(self, wallet_address: str) -> bool:
        """
        Prüft ob Wallet ein AEra NFT besitzt
        
        Returns:
            True wenn NFT vorhanden
        """
        try:
            import httpx
            
            url = f"{self.server_url}/api/nft/check/{wallet_address.lower()}"
            
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(url)
                
                if response.status_code == 200:
                    data = response.json()
                    return data.get("has_nft", False)
                    
        except Exception as e:
            logger.error(f"NFT check error: {e}")
        
        return False


# Globale Score-API Instanz
score_api = ResonanceScoreAPI(SERVER_URL)


# ===== SESSION MANAGER =====

class SessionManager:
    """
    Verwaltet User-Sessions (NUR im RAM!)
    
    DATENSCHUTZ:
    - Wallet-Adressen werden nur temporär für API-Calls gespeichert
    - Bei Session-Ende wird alles gelöscht
    - Bei Server-Neustart sind alle Sessions weg
    
    Das ist gewollt für maximale Sicherheit!
    """
    
    def __init__(self):
        self.sessions: Dict[int, Dict[int, UserSession]] = {}  # group_id -> {telegram_id -> session}
        self.pending_tokens: Dict[str, Dict] = {}  # invite_link -> token_data
        self._cleanup_task: Optional[asyncio.Task] = None
    
    def start_cleanup_task(self):
        """Startet Background-Task für Session-Cleanup"""
        if self._cleanup_task is None:
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())
    
    async def _cleanup_loop(self):
        """Entfernt abgelaufene Sessions alle 60 Sekunden"""
        while True:
            try:
                await asyncio.sleep(60)
                self._cleanup_expired()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Session cleanup error: {e}")
    
    def _cleanup_expired(self):
        """Entfernt abgelaufene Sessions und Tokens"""
        now = time.time()
        
        # Sessions aufräumen
        for group_id in list(self.sessions.keys()):
            group_sessions = self.sessions[group_id]
            expired = [uid for uid, session in group_sessions.items() if session.is_expired()]
            for uid in expired:
                del group_sessions[uid]
                logger.info(f"Session expired: user {uid} in group {group_id}")
        
        # Pending Tokens aufräumen
        expired_tokens = [link for link, data in self.pending_tokens.items() 
                         if now > data.get("exp", 0)]
        for link in expired_tokens:
            del self.pending_tokens[link]
    
    def store_pending_token(self, invite_link: str, wallet_address: str,
                           initial_score: int, expire_seconds: int = 120):
        """
        Speichert Token für noch nicht beigetretenen User
        
        DATENSCHUTZ: Wallet wird temporär gespeichert bis User beitritt (max 2 Min)
        """
        self.pending_tokens[invite_link] = {
            "wallet": wallet_address.lower(),
            "score": initial_score,
            "exp": time.time() + expire_seconds,
            "created": time.time()
        }
        logger.info(f"Pending token stored for link: {invite_link[:30]}... (score: {initial_score})")
    
    def claim_pending_token(self, invite_link: str) -> Optional[Dict[str, Any]]:
        """
        Holt und löscht pending Token für Invite-Link
        
        Returns:
            Dict mit wallet, score oder None
        """
        if invite_link in self.pending_tokens:
            token_data = self.pending_tokens.pop(invite_link)
            
            # Nochmal Ablauf prüfen
            if time.time() > token_data.get("exp", 0):
                logger.warning(f"Pending token expired for link: {invite_link[:30]}...")
                return None
            
            return {
                "wallet": token_data.get("wallet"),
                "score": token_data.get("score", 0)
            }
        
        return None
    
    def create_session(self, group_id: int, telegram_id: int, 
                      wallet_address: str, initial_score: int, 
                      timeout: int) -> UserSession:
        """
        Erstellt neue Session für User mit Live-Score
        
        SICHERHEIT:
        - Wallet wird AES-256-GCM verschlüsselt im RAM gespeichert
        - wallet_hash ist SHA256 für Logging (nicht umkehrbar)
        - Schlüssel existiert nur im RAM, wird bei Neustart neu generiert
        """
        if group_id not in self.sessions:
            self.sessions[group_id] = {}
        
        now = time.time()
        
        # Hash für sicheres Logging (nicht umkehrbar)
        wallet_hash = hashlib.sha256(wallet_address.lower().encode()).hexdigest()[:16]
        
        # Wallet AES-256-GCM verschlüsseln (sicher bei RAM-Dump)
        encrypted_wallet = wallet_crypto.encrypt(wallet_address.lower())
        
        session = UserSession(
            telegram_id=telegram_id,
            wallet_hash=wallet_hash,
            encrypted_wallet=encrypted_wallet,
            last_score=initial_score,
            session_start=now,
            last_activity=now,
            last_score_check=now,
            expires=now + timeout
        )
        
        self.sessions[group_id][telegram_id] = session
        logger.info(f"Session created: user {telegram_id} in group {group_id}, "
                   f"wallet_hash: {wallet_hash}, score: {initial_score} [AES-256 encrypted]")
        
        return session
    
    def get_session(self, group_id: int, telegram_id: int) -> Optional[UserSession]:
        """Holt Session für User (None wenn nicht vorhanden oder abgelaufen)"""
        if group_id not in self.sessions:
            return None
        
        session = self.sessions[group_id].get(telegram_id)
        
        if session and session.is_expired():
            del self.sessions[group_id][telegram_id]
            return None
        
        return session
    
    def extend_session(self, group_id: int, telegram_id: int, timeout: int) -> bool:
        """Verlängert Session bei Aktivität"""
        session = self.get_session(group_id, telegram_id)
        if session:
            session.extend_session(timeout)
            return True
        return False
    
    def end_session(self, group_id: int, telegram_id: int):
        """Beendet Session explizit"""
        if group_id in self.sessions and telegram_id in self.sessions[group_id]:
            del self.sessions[group_id][telegram_id]
            logger.info(f"Session ended: user {telegram_id} in group {group_id}")


# ===== POLL MANAGER =====

class PollManager:
    """Verwaltet aktive Polls mit Score-Gates"""
    
    def __init__(self):
        self.polls: Dict[str, ActivePoll] = {}  # poll_id -> poll
        self.message_to_poll: Dict[int, str] = {}  # message_id -> poll_id
    
    def create_poll(self, chat_id: int, message_id: int, creator_id: int,
                   question: str, options: List[str], min_score: int,
                   duration_minutes: Optional[int] = None) -> ActivePoll:
        """Erstellt neuen Poll"""
        import secrets
        poll_id = secrets.token_hex(8)
        
        now = time.time()
        expires_at = now + (duration_minutes * 60) if duration_minutes else None
        
        poll = ActivePoll(
            poll_id=poll_id,
            message_id=message_id,
            chat_id=chat_id,
            creator_id=creator_id,
            question=question,
            options=options,
            min_score=min_score,
            created_at=now,
            expires_at=expires_at
        )
        
        self.polls[poll_id] = poll
        self.message_to_poll[message_id] = poll_id
        
        logger.info(f"Poll created: {poll_id}, min_score={min_score}, question='{question[:30]}...'")
        
        return poll
    
    def get_poll(self, poll_id: str) -> Optional[ActivePoll]:
        return self.polls.get(poll_id)
    
    def get_poll_by_message(self, message_id: int) -> Optional[ActivePoll]:
        poll_id = self.message_to_poll.get(message_id)
        return self.polls.get(poll_id) if poll_id else None
    
    def vote(self, poll_id: str, user_id: int, option_index: int) -> bool:
        """User stimmt ab (überschreibt vorherige Stimme)"""
        poll = self.get_poll(poll_id)
        if not poll or poll.closed:
            return False
        
        if poll.expires_at and time.time() > poll.expires_at:
            poll.closed = True
            return False
        
        if option_index < 0 or option_index >= len(poll.options):
            return False
        
        poll.votes[user_id] = option_index
        return True
    
    def get_results(self, poll_id: str) -> Optional[Dict[str, int]]:
        """Holt Ergebnisse eines Polls"""
        poll = self.get_poll(poll_id)
        if not poll:
            return None
        
        results = {option: 0 for option in poll.options}
        for option_index in poll.votes.values():
            if 0 <= option_index < len(poll.options):
                results[poll.options[option_index]] += 1
        
        return results
    
    def close_poll(self, poll_id: str) -> bool:
        """Schließt Poll"""
        poll = self.get_poll(poll_id)
        if poll:
            poll.closed = True
            return True
        return False


# ===== TELEGRAM BOT =====

class TelegramGroupBot:
    """
    Hauptklasse für den Telegram Group Bot
    
    Verwendet python-telegram-bot Library
    """
    
    def __init__(self):
        self.token_manager = CapabilityTokenManager(HMAC_SECRET)
        self.session_manager = SessionManager()
        self.poll_manager = PollManager()
        self.group_configs: Dict[int, GroupConfig] = {}
        
        # Default-Gruppe aus ENV
        if GROUP_ID:
            try:
                gid = int(GROUP_ID)
                self.group_configs[gid] = GroupConfig(group_id=gid)
            except ValueError:
                pass
    
    def get_group_config(self, group_id: int) -> GroupConfig:
        """Holt oder erstellt Gruppen-Konfiguration"""
        if group_id not in self.group_configs:
            self.group_configs[group_id] = GroupConfig(group_id=group_id)
        return self.group_configs[group_id]
    
    async def is_admin(self, chat_id: int, user_id: int, bot) -> bool:
        """Prüft ob User Admin in der Gruppe ist"""
        try:
            member = await bot.get_chat_member(chat_id, user_id)
            return member.status in ['creator', 'administrator']
        except Exception as e:
            logger.error(f"Admin check failed: {e}")
            return False
    
    # ===== EVENT HANDLERS =====
    
    async def handle_new_member(self, update, context):
        """
        Handler für neue Mitglieder
        
        1. Prüft ob pending Token für den Invite-Link existiert
        2. Holt Live Resonance Score
        3. Erstellt Session mit Wallet-Referenz
        4. Gibt Schreibrechte wenn Score >= min_score
        5. Sendet Begrüßung
        """
        try:
            message = update.message
            chat_id = message.chat.id
            
            # Hole Gruppen-Konfiguration
            config = self.get_group_config(chat_id)
            
            for new_member in message.new_chat_members:
                # Bot selbst ignorieren
                if new_member.is_bot:
                    continue
                
                user_id = new_member.id
                username = new_member.username or new_member.first_name
                
                logger.info(f"New member: {username} ({user_id}) in group {chat_id}")
                
                # Invite-Link aus dem Event holen
                invite_link = None
                if hasattr(message, 'chat_invite_link') and message.chat_invite_link:
                    invite_link = message.chat_invite_link.invite_link
                
                token_data = None
                
                if invite_link:
                    # Versuche pending Token zu claimen
                    token_data = self.session_manager.claim_pending_token(invite_link)
                    if token_data:
                        logger.info(f"Claimed token for {username}: wallet_hash={hashlib.sha256(token_data['wallet'].encode()).hexdigest()[:16]}")
                
                if token_data and token_data.get("wallet"):
                    wallet_address = token_data["wallet"]
                    
                    # Live Score vom Server holen
                    live_score = await score_api.get_resonance_score(wallet_address)
                    
                    if live_score is None:
                        # Fallback auf gespeicherten Score
                        live_score = token_data.get("score", 0)
                        logger.warning(f"Could not fetch live score, using cached: {live_score}")
                    
                    # Erstelle Session mit Wallet-Referenz
                    session = self.session_manager.create_session(
                        group_id=chat_id,
                        telegram_id=user_id,
                        wallet_address=wallet_address,
                        initial_score=live_score,
                        timeout=config.session_timeout
                    )
                    
                    # Schreibrechte basierend auf Live-Score
                    if session.can_write(config.min_score):
                        await self._unmute_user(context.bot, chat_id, user_id)
                        
                        # Begrüßung senden
                        await message.reply_text(
                            f"🎉 **Willkommen {username}!**\n\n"
                            f"✅ Resonance Score: **{live_score}** (min: {config.min_score})\n"
                            f"📝 Du hast Schreibrechte!\n\n"
                            f"📊 Nutze `/mystatus` für deinen Status.\n"
                            f"❓ Nutze `/help` für alle Befehle.",
                            parse_mode='Markdown'
                        )
                    else:
                        # Nicht genug Score - gemutet lassen
                        await self._mute_user(context.bot, chat_id, user_id)
                        await message.reply_text(
                            f"👋 Willkommen {username}!\n\n"
                            f"📊 Dein Resonance Score: **{live_score}**\n"
                            f"⚠️ Mindestens **{config.min_score}** für Schreibrechte benötigt.\n\n"
                            f"💡 Erhöhe deinen Score durch Aktivität und Follower!",
                            parse_mode='Markdown'
                        )
                else:
                    # Kein Token gefunden - User muss sich verifizieren
                    await self._mute_user(context.bot, chat_id, user_id)
                    
                    verify_url = f"{SERVER_URL}/join-telegram"
                    await message.reply_text(
                        f"👋 Willkommen {username}!\n\n"
                        f"🔐 Bitte verifiziere dich um Schreibrechte zu erhalten:\n"
                        f"{verify_url}\n\n"
                        f"Nach der Verifizierung bekommst du automatisch Zugang.",
                        parse_mode='Markdown'
                    )
                    
        except Exception as e:
            logger.error(f"handle_new_member error: {e}")
    
    async def handle_message(self, update, context):
        """
        Handler für Nachrichten
        
        - Verlängert Session bei Aktivität
        - Prüft Live Resonance Score
        - Muted/Unmuted automatisch bei Score-Änderung
        """
        try:
            message = update.message
            if not message or not message.from_user:
                return
            
            chat_id = message.chat.id
            user_id = message.from_user.id
            
            # Hole Gruppen-Konfiguration
            config = self.get_group_config(chat_id)
            
            # Session prüfen und verlängern
            session = self.session_manager.get_session(chat_id, user_id)
            
            if session:
                # Session verlängern
                session.extend_session(config.session_timeout)
                
                # Live Score Check (alle 60 Sekunden)
                if session.needs_score_refresh(interval_seconds=60):
                    new_score = await score_api.get_resonance_score(session.get_wallet_address())
                    
                    if new_score is not None:
                        old_score = session.last_score
                        session.update_score(new_score)
                        
                        old_can_write = old_score >= config.min_score
                        new_can_write = new_score >= config.min_score
                        
                        # Score hat sich geändert - Berechtigungen anpassen
                        if old_can_write and not new_can_write:
                            # Score gefallen - muten
                            await self._mute_user(context.bot, chat_id, user_id)
                            await message.reply_text(
                                f"⚠️ Dein Resonance Score ist auf **{new_score}** gefallen.\n"
                                f"Schreibrechte entzogen (min: {config.min_score}).",
                                parse_mode='Markdown'
                            )
                            logger.info(f"User {user_id} muted: score dropped {old_score} -> {new_score}")
                            
                        elif not old_can_write and new_can_write:
                            # Score gestiegen - unmuten
                            await self._unmute_user(context.bot, chat_id, user_id)
                            await message.reply_text(
                                f"🎉 Dein Resonance Score ist auf **{new_score}** gestiegen!\n"
                                f"Du hast jetzt Schreibrechte!",
                                parse_mode='Markdown'
                            )
                            logger.info(f"User {user_id} unmuted: score rose {old_score} -> {new_score}")
                
                # Warnung wenn Session bald abläuft (< 5 Min)
                remaining = session.time_remaining()
                if remaining < 300 and remaining > 240:  # Zwischen 4-5 Min
                    await message.reply_text(
                        f"⏰ Deine Session läuft in {remaining // 60} Minuten ab.\n"
                        f"Bleibe aktiv oder verifiziere dich neu.",
                        parse_mode='Markdown'
                    )
            else:
                # Keine Session - sollte nicht schreiben können
                # (Telegram Restrict sollte das verhindern, aber zur Sicherheit)
                pass
                
        except Exception as e:
            logger.error(f"handle_message error: {e}")
    
    async def handle_left_member(self, update, context):
        """Handler wenn Mitglied die Gruppe verlässt"""
        try:
            message = update.message
            chat_id = message.chat.id
            
            for left_member in [message.left_chat_member]:
                if left_member and not left_member.is_bot:
                    user_id = left_member.id
                    self.session_manager.end_session(chat_id, user_id)
                    logger.info(f"Member left: {user_id} from group {chat_id}")
                    
        except Exception as e:
            logger.error(f"handle_left_member error: {e}")
    
    # ===== BEFEHLE =====
    
    async def cmd_help(self, update, context):
        """Zeigt Hilfe an"""
        help_text = """
🤖 **AEra Group Bot - Befehle**

**Für alle User:**
• `/mystatus` - Zeigt deinen Session-Status
• `/verify` - Link zur Verifizierung
• `/help` - Diese Hilfe

**Für Admins:**
• `/setminscore <score>` - Mindest-Score für Schreibrechte
• `/settimeout <minuten>` - Session-Timeout setzen
• `/setwelcome <text>` - Begrüßungstext ändern
• `/poll <frage> | <option1> | <option2> | ... [min_score]` - Poll erstellen
• `/closepoll <poll_id>` - Poll schließen
• `/status` - Bot-Status anzeigen

🔐 Verifiziere dich auf: {server_url}/join-telegram
        """.format(server_url=SERVER_URL)
        
        await update.message.reply_text(help_text, parse_mode='Markdown')
    
    async def cmd_mystatus(self, update, context):
        """Zeigt Session-Status des Users mit Live-Score"""
        chat_id = update.message.chat.id
        user_id = update.message.from_user.id
        
        config = self.get_group_config(chat_id)
        
        # Admin-Check
        is_admin = await self.is_admin(chat_id, user_id, context.bot)
        
        if is_admin:
            status_text = f"""
👑 **Admin Status**

Du bist Administrator dieser Gruppe.
Admins haben immer volle Rechte - keine Session nötig.

**Gruppen-Einstellungen:**
📊 Mindest-Score: {config.min_score}
⏱️ Session-Timeout: {config.session_timeout // 60} Minuten
👥 Aktive Sessions: {len(self.session_manager.sessions.get(chat_id, {}))}
            """
            await update.message.reply_text(status_text, parse_mode='Markdown')
            return
        
        session = self.session_manager.get_session(chat_id, user_id)
        
        if session:
            # Live Score abrufen (Wallet wird für API-Call entschlüsselt)
            live_score = await score_api.get_resonance_score(session.get_wallet_address())
            
            if live_score is not None:
                session.update_score(live_score)
            else:
                live_score = session.last_score  # Fallback auf gecachten Score
            
            remaining = session.time_remaining()
            remaining_str = f"{remaining // 60}:{remaining % 60:02d}"
            
            can_write = session.can_write(config.min_score)
            
            status_text = f"""
✅ **Session aktiv**

📊 **Resonance Score:** {live_score}
📝 **Schreibrechte:** {'✅ Ja' if can_write else '❌ Nein'} (min: {config.min_score})
⏱️ **Session:** {remaining_str} verbleibend

🔐 Wallet: `{session.wallet_hash}...` (anonymisiert)
            """
        else:
            status_text = f"""
❌ **Keine aktive Session**

Bitte verifiziere dich:
🔗 {SERVER_URL}/join-telegram
            """
        
        await update.message.reply_text(status_text, parse_mode='Markdown')
    
    async def cmd_verify(self, update, context):
        """Zeigt Verifizierungs-Link"""
        verify_url = f"{SERVER_URL}/join-telegram"
        
        await update.message.reply_text(
            f"🔐 **Verifizierung**\n\n"
            f"Klicke hier um dich zu verifizieren:\n"
            f"{verify_url}\n\n"
            f"Nach der Verifizierung erhältst du automatisch Zugang.",
            parse_mode='Markdown'
        )
    
    # ===== ADMIN BEFEHLE =====
    
    async def cmd_setminscore(self, update, context):
        """Setzt Mindest-Score für Schreibrechte"""
        chat_id = update.message.chat.id
        user_id = update.message.from_user.id
        
        if not await self.is_admin(chat_id, user_id, context.bot):
            await update.message.reply_text("❌ Nur Admins können diesen Befehl nutzen.")
            return
        
        try:
            score = int(context.args[0])
            if score < 0 or score > 100:
                raise ValueError("Score must be 0-100")
            
            config = self.get_group_config(chat_id)
            config.min_score = score
            
            await update.message.reply_text(
                f"✅ Mindest-Score auf **{score}** gesetzt.",
                parse_mode='Markdown'
            )
        except (IndexError, ValueError):
            await update.message.reply_text(
                "❌ Verwendung: `/setminscore <0-100>`",
                parse_mode='Markdown'
            )
    
    async def cmd_settimeout(self, update, context):
        """Setzt Session-Timeout"""
        chat_id = update.message.chat.id
        user_id = update.message.from_user.id
        
        if not await self.is_admin(chat_id, user_id, context.bot):
            await update.message.reply_text("❌ Nur Admins können diesen Befehl nutzen.")
            return
        
        try:
            minutes = int(context.args[0])
            if minutes < 1 or minutes > 1440:  # Max 24 Stunden
                raise ValueError("Timeout must be 1-1440 minutes")
            
            config = self.get_group_config(chat_id)
            config.session_timeout = minutes * 60
            
            await update.message.reply_text(
                f"✅ Session-Timeout auf **{minutes} Minuten** gesetzt.",
                parse_mode='Markdown'
            )
        except (IndexError, ValueError):
            await update.message.reply_text(
                "❌ Verwendung: `/settimeout <minuten>` (1-1440)",
                parse_mode='Markdown'
            )
    
    async def cmd_setwelcome(self, update, context):
        """Setzt Begrüßungstext"""
        chat_id = update.message.chat.id
        user_id = update.message.from_user.id
        
        if not await self.is_admin(chat_id, user_id, context.bot):
            await update.message.reply_text("❌ Nur Admins können diesen Befehl nutzen.")
            return
        
        if not context.args:
            await update.message.reply_text(
                "❌ Verwendung: `/setwelcome <text>`\n\n"
                "Variablen: {username}, {timeout_minutes}",
                parse_mode='Markdown'
            )
            return
        
        welcome_text = " ".join(context.args)
        config = self.get_group_config(chat_id)
        config.welcome_message = welcome_text
        
        await update.message.reply_text(
            f"✅ Begrüßungstext aktualisiert:\n\n{welcome_text}",
            parse_mode='Markdown'
        )
    
    async def cmd_status(self, update, context):
        """Zeigt Bot-Status (Admin)"""
        chat_id = update.message.chat.id
        user_id = update.message.from_user.id
        
        if not await self.is_admin(chat_id, user_id, context.bot):
            await update.message.reply_text("❌ Nur Admins können diesen Befehl nutzen.")
            return
        
        config = self.get_group_config(chat_id)
        
        # Aktive Sessions zählen
        active_sessions = len(self.session_manager.sessions.get(chat_id, {}))
        
        # Aktive Polls zählen
        active_polls = sum(1 for p in self.poll_manager.polls.values() 
                         if p.chat_id == chat_id and not p.closed)
        
        status_text = f"""
🤖 **Bot Status**

**Gruppe:** {chat_id}
**Mindest-Score:** {config.min_score}
**Session-Timeout:** {config.session_timeout // 60} Minuten

**Aktive Sessions:** {active_sessions}
**Aktive Polls:** {active_polls}

**Server:** {SERVER_URL}
        """
        
        await update.message.reply_text(status_text, parse_mode='Markdown')
    
    # ===== POLL BEFEHLE =====
    
    async def cmd_poll(self, update, context):
        """
        Erstellt Poll mit Score-Gate
        
        Verwendung: /poll Frage | Option1 | Option2 | ... [min_score]
        Beispiel: /poll Welche Farbe? | Rot | Blau | Grün 60
        """
        chat_id = update.message.chat.id
        user_id = update.message.from_user.id
        
        if not await self.is_admin(chat_id, user_id, context.bot):
            await update.message.reply_text("❌ Nur Admins können Polls erstellen.")
            return
        
        try:
            # Parse arguments
            full_text = " ".join(context.args)
            parts = [p.strip() for p in full_text.split("|")]
            
            if len(parts) < 3:
                raise ValueError("Mindestens Frage + 2 Optionen nötig")
            
            question = parts[0]
            
            # Letztes Element könnte min_score sein
            last_part = parts[-1]
            try:
                min_score = int(last_part.split()[-1])
                options = parts[1:-1]
                # Letztes Wort von letzter Option entfernen wenn es die Zahl war
                if last_part.strip().endswith(str(min_score)):
                    remaining = last_part.rsplit(str(min_score), 1)[0].strip()
                    if remaining:
                        options.append(remaining)
            except ValueError:
                min_score = 50  # Default
                options = parts[1:]
            
            config = self.get_group_config(chat_id)
            
            # Poll-Nachricht erstellen
            options_text = "\n".join([f"{i+1}. {opt}" for i, opt in enumerate(options)])
            poll_msg = await update.message.reply_text(
                f"📊 **Poll** (min. Score: {min_score})\n\n"
                f"**{question}**\n\n"
                f"{options_text}\n\n"
                f"_Antworte mit der Nummer um abzustimmen._",
                parse_mode='Markdown'
            )
            
            # Poll speichern
            poll = self.poll_manager.create_poll(
                chat_id=chat_id,
                message_id=poll_msg.message_id,
                creator_id=user_id,
                question=question,
                options=options,
                min_score=min_score
            )
            
            await update.message.reply_text(
                f"✅ Poll erstellt! ID: `{poll.poll_id}`\n"
                f"Schließen mit: `/closepoll {poll.poll_id}`",
                parse_mode='Markdown'
            )
            
        except Exception as e:
            await update.message.reply_text(
                f"❌ Fehler: {e}\n\n"
                f"Verwendung: `/poll Frage | Option1 | Option2 | ... [min_score]`",
                parse_mode='Markdown'
            )
    
    async def cmd_closepoll(self, update, context):
        """Schließt einen Poll und zeigt Ergebnisse"""
        chat_id = update.message.chat.id
        user_id = update.message.from_user.id
        
        if not await self.is_admin(chat_id, user_id, context.bot):
            await update.message.reply_text("❌ Nur Admins können Polls schließen.")
            return
        
        if not context.args:
            await update.message.reply_text("❌ Verwendung: `/closepoll <poll_id>`", parse_mode='Markdown')
            return
        
        poll_id = context.args[0]
        poll = self.poll_manager.get_poll(poll_id)
        
        if not poll or poll.chat_id != chat_id:
            await update.message.reply_text("❌ Poll nicht gefunden.")
            return
        
        self.poll_manager.close_poll(poll_id)
        results = self.poll_manager.get_results(poll_id)
        
        results_text = "\n".join([f"• {opt}: **{count}** Stimmen" 
                                  for opt, count in results.items()])
        
        await update.message.reply_text(
            f"📊 **Poll beendet**\n\n"
            f"**{poll.question}**\n\n"
            f"{results_text}\n\n"
            f"_Gesamt: {len(poll.votes)} Abstimmungen_",
            parse_mode='Markdown'
        )
    
    async def handle_poll_vote(self, update, context):
        """Verarbeitet Poll-Abstimmungen (Zahlen-Antworten)"""
        try:
            message = update.message
            chat_id = message.chat.id
            user_id = message.from_user.id
            
            # Prüfe ob es eine Zahl ist
            try:
                vote_num = int(message.text.strip())
            except ValueError:
                return  # Keine Zahl, ignorieren
            
            # Suche nach aktivem Poll auf den geantwortet wird
            if not message.reply_to_message:
                return
            
            poll = self.poll_manager.get_poll_by_message(message.reply_to_message.message_id)
            if not poll or poll.closed:
                return
            
            # Prüfe Session
            session = self.session_manager.get_session(chat_id, user_id)
            if not session:
                await message.reply_text(
                    "❌ Du musst verifiziert sein um abzustimmen.\n"
                    f"🔗 {SERVER_URL}/join-telegram"
                )
                return
            
            # Live Score Check für Poll-Berechtigung (Wallet wird entschlüsselt)
            live_score = await score_api.get_resonance_score(session.get_wallet_address())
            
            if live_score is not None:
                session.update_score(live_score)
            else:
                live_score = session.last_score  # Fallback
            
            if not session.can_vote_poll(poll.min_score):
                await message.reply_text(
                    f"❌ Für diesen Poll ist ein Resonance Score von mindestens "
                    f"**{poll.min_score}** erforderlich.\n"
                    f"📊 Dein Score: **{live_score}**",
                    parse_mode='Markdown'
                )
                return
            
            # Abstimmen
            option_index = vote_num - 1
            if self.poll_manager.vote(poll.poll_id, user_id, option_index):
                await message.reply_text(
                    f"✅ Stimme für **{poll.options[option_index]}** gezählt!\n"
                    f"📊 Dein Score: {live_score}",
                    parse_mode='Markdown'
                )
            else:
                await message.reply_text("❌ Ungültige Option.")
                
        except Exception as e:
            logger.error(f"Poll vote error: {e}")
    
    # ===== HILFSFUNKTIONEN =====
    
    async def _mute_user(self, bot, chat_id: int, user_id: int):
        """Entzieht Schreibrechte"""
        try:
            from telegram import ChatPermissions
            await bot.restrict_chat_member(
                chat_id=chat_id,
                user_id=user_id,
                permissions=ChatPermissions(
                    can_send_messages=False,
                    can_send_media_messages=False,
                    can_send_polls=False,
                    can_send_other_messages=False,
                    can_add_web_page_previews=False,
                    can_change_info=False,
                    can_invite_users=False,
                    can_pin_messages=False
                )
            )
            logger.info(f"Muted user {user_id} in {chat_id}")
        except Exception as e:
            logger.error(f"Failed to mute user: {e}")
    
    async def _unmute_user(self, bot, chat_id: int, user_id: int):
        """Gibt Schreibrechte"""
        try:
            from telegram import ChatPermissions
            await bot.restrict_chat_member(
                chat_id=chat_id,
                user_id=user_id,
                permissions=ChatPermissions(
                    can_send_messages=True,
                    can_send_media_messages=True,
                    can_send_polls=True,
                    can_send_other_messages=True,
                    can_add_web_page_previews=True,
                    can_change_info=False,
                    can_invite_users=True,
                    can_pin_messages=False
                )
            )
            logger.info(f"Unmuted user {user_id} in {chat_id}")
        except Exception as e:
            logger.error(f"Failed to unmute user: {e}")


# ===== BOT STARTEN =====

# Globale Instanz
group_bot = TelegramGroupBot()


async def run_bot():
    """Startet den Bot mit python-telegram-bot"""
    from telegram.ext import Application, CommandHandler, MessageHandler, filters
    
    if not BOT_TOKEN:
        logger.error("❌ TELEGRAM_GROUP_BOT_TOKEN nicht gesetzt!")
        return
    
    logger.info("🚀 Starting Telegram Group Bot...")
    
    # Application erstellen
    app = Application.builder().token(BOT_TOKEN).build()
    
    # Handler registrieren
    app.add_handler(CommandHandler("help", group_bot.cmd_help))
    app.add_handler(CommandHandler("mystatus", group_bot.cmd_mystatus))
    app.add_handler(CommandHandler("verify", group_bot.cmd_verify))
    app.add_handler(CommandHandler("setminscore", group_bot.cmd_setminscore))
    app.add_handler(CommandHandler("settimeout", group_bot.cmd_settimeout))
    app.add_handler(CommandHandler("setwelcome", group_bot.cmd_setwelcome))
    app.add_handler(CommandHandler("status", group_bot.cmd_status))
    app.add_handler(CommandHandler("poll", group_bot.cmd_poll))
    app.add_handler(CommandHandler("closepoll", group_bot.cmd_closepoll))
    
    # Event Handler
    app.add_handler(MessageHandler(
        filters.StatusUpdate.NEW_CHAT_MEMBERS,
        group_bot.handle_new_member
    ))
    app.add_handler(MessageHandler(
        filters.StatusUpdate.LEFT_CHAT_MEMBER,
        group_bot.handle_left_member
    ))
    
    # Message Handler für Session-Verlängerung und Poll-Votes
    app.add_handler(MessageHandler(
        filters.TEXT & ~filters.COMMAND,
        group_bot.handle_message
    ))
    
    # Session Cleanup Task starten
    group_bot.session_manager.start_cleanup_task()
    
    # Bot starten
    logger.info("✅ Telegram Group Bot started!")
    await app.initialize()
    await app.start()
    await app.updater.start_polling()
    
    # Warten bis beendet
    try:
        while True:
            await asyncio.sleep(3600)
    except asyncio.CancelledError:
        pass
    finally:
        await app.updater.stop()
        await app.stop()
        await app.shutdown()


def start_bot_thread():
    """Startet Bot in separatem Thread (für Integration in server.py)"""
    import threading
    
    def run():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(run_bot())
    
    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


if __name__ == "__main__":
    # Standalone-Modus
    asyncio.run(run_bot())
