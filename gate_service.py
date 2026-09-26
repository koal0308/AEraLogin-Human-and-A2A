"""
🚀 Dynamic Gate Service
=======================

Zentrale Service-Schicht für NFT-gated Communities.
Ersetzt hardcodierte Bot-Tokens durch dynamische DB-basierte Konfiguration.

Features:
- Jeder Owner kann eigenen Bot konfigurieren
- Automatische Bot-Verifizierung
- Fallback auf statische Links wenn kein Bot
- Bot-Instance Caching für Performance
- Sichere Token-Verschlüsselung

Author: VEra-Resonance
Created: 2026-01-03
"""

import os
import sqlite3
import aiohttp
import logging
from datetime import datetime, timezone
from typing import Optional, Tuple, Dict, Any
from dotenv import load_dotenv

load_dotenv()

# Logger
logger = logging.getLogger("GateService")
logger.setLevel(logging.INFO)

# Import encryption
from gate_encryption import gate_encryption

# API Base URLs
TELEGRAM_API_BASE = "https://api.telegram.org/bot"
DISCORD_API_BASE = "https://discord.com/api/v10"


# ============================================================================
# Dynamic Bot Classes
# ============================================================================

class DynamicTelegramBot:
    """
    Dynamische Telegram Bot Instanz für einen spezifischen Owner.
    Nutzt Owner's Bot-Token statt hardcodiertem .env Token.
    """
    
    def __init__(self, bot_token: str, group_id: str, owner_wallet: str = ""):
        self.bot_token = bot_token
        self.group_id = group_id
        self.owner_wallet = owner_wallet
        self._bot_info = None
    
    @property
    def api_url(self) -> str:
        return f"{TELEGRAM_API_BASE}{self.bot_token}"
    
    @property
    def is_configured(self) -> bool:
        return bool(self.bot_token and self.group_id)
    
    async def _api_request(self, method: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        """Telegram API Request"""
        url = f"{self.api_url}/{method}"
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=params or {}) as response:
                    result = await response.json()
                    
                    if not result.get("ok"):
                        error_desc = result.get("description", "Unknown error")
                        return {"ok": False, "error": error_desc}
                    
                    return result
                    
        except aiohttp.ClientError as e:
            return {"ok": False, "error": f"Connection error: {str(e)}"}
        except Exception as e:
            return {"ok": False, "error": str(e)}
    
    async def get_bot_info(self) -> Dict[str, Any]:
        """Holt Bot-Informationen (getMe)"""
        if self._bot_info:
            return {"ok": True, "result": self._bot_info}
        
        result = await self._api_request("getMe")
        
        if result.get("ok"):
            self._bot_info = result.get("result", {})
        
        return result
    
    async def verify_permissions(self) -> Dict[str, Any]:
        """Prüft ob Bot Admin-Rechte in der Gruppe hat"""
        if not self.group_id:
            return {"ok": False, "error": "No group ID configured"}
        
        bot_info = await self.get_bot_info()
        if not bot_info.get("ok"):
            return bot_info
        
        bot_id = self._bot_info.get("id")
        
        result = await self._api_request("getChatMember", {
            "chat_id": self.group_id,
            "user_id": bot_id
        })
        
        if not result.get("ok"):
            return result
        
        member = result.get("result", {})
        status = member.get("status", "")
        
        if status in ["creator", "administrator"]:
            can_invite = member.get("can_invite_users", False)
            return {
                "ok": True,
                "status": status,
                "can_invite": can_invite,
                "bot_username": self._bot_info.get("username"),
                "message": "✅ Bot has invite permissions" if can_invite else "❌ Bot lacks invite permissions"
            }
        else:
            return {
                "ok": False,
                "status": status,
                "can_invite": False,
                "error": f"Bot is not admin (status: {status})"
            }
    
    async def create_one_time_invite(
        self,
        name: Optional[str] = None,
        expire_seconds: int = 300
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Erstellt einen EINMAL-LINK (member_limit=1)
        """
        if not self.bot_token:
            return False, {"error": "Bot token not configured"}
        
        if not self.group_id:
            return False, {"error": "Group ID not configured"}
        
        expire_date = int(datetime.now(timezone.utc).timestamp()) + expire_seconds
        
        params = {
            "chat_id": self.group_id,
            "member_limit": 1,
            "expire_date": expire_date,
            "creates_join_request": False
        }
        
        if name:
            params["name"] = name[:32]
        
        result = await self._api_request("createChatInviteLink", params)
        
        if result.get("ok"):
            invite_data = result.get("result", {})
            return True, {
                "invite_link": invite_data.get("invite_link", ""),
                "name": invite_data.get("name"),
                "expire_date": invite_data.get("expire_date"),
                "member_limit": invite_data.get("member_limit"),
                "is_one_time": True
            }
        else:
            return False, {"error": result.get("error", "Unknown error")}


class DynamicDiscordBot:
    """
    Dynamische Discord Bot Instanz für einen spezifischen Owner.
    """
    
    def __init__(self, bot_token: str, guild_id: str, channel_id: str = "", owner_wallet: str = ""):
        self.bot_token = bot_token
        self.guild_id = guild_id
        self.channel_id = channel_id
        self.owner_wallet = owner_wallet
        self._bot_info = None
    
    @property
    def headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bot {self.bot_token}",
            "Content-Type": "application/json"
        }
    
    @property
    def is_configured(self) -> bool:
        return bool(self.bot_token and self.guild_id)
    
    async def _api_request(
        self, 
        method: str, 
        endpoint: str, 
        json_data: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """Discord API Request"""
        url = f"{DISCORD_API_BASE}{endpoint}"
        
        try:
            async with aiohttp.ClientSession() as session:
                if method == "GET":
                    async with session.get(url, headers=self.headers) as response:
                        if response.status == 200:
                            return {"ok": True, "result": await response.json()}
                        else:
                            return {"ok": False, "error": f"HTTP {response.status}"}
                elif method == "POST":
                    async with session.post(url, headers=self.headers, json=json_data or {}) as response:
                        if response.status in [200, 201]:
                            return {"ok": True, "result": await response.json()}
                        else:
                            error_text = await response.text()
                            return {"ok": False, "error": f"HTTP {response.status}: {error_text}"}
        except Exception as e:
            return {"ok": False, "error": str(e)}
    
    async def get_bot_info(self) -> Dict[str, Any]:
        """Holt Bot-Informationen"""
        if self._bot_info:
            return {"ok": True, "result": self._bot_info}
        
        result = await self._api_request("GET", "/users/@me")
        
        if result.get("ok"):
            self._bot_info = result.get("result", {})
        
        return result
    
    async def verify_permissions(self) -> Dict[str, Any]:
        """Prüft ob Bot die nötigen Rechte im Server hat"""
        if not self.guild_id:
            return {"ok": False, "error": "No guild ID configured"}
        
        bot_info = await self.get_bot_info()
        if not bot_info.get("ok"):
            return bot_info
        
        # Check guild access
        result = await self._api_request("GET", f"/guilds/{self.guild_id}")
        
        if not result.get("ok"):
            return {"ok": False, "error": "Cannot access guild - check bot permissions"}
        
        guild = result.get("result", {})
        
        return {
            "ok": True,
            "guild_name": guild.get("name"),
            "bot_username": self._bot_info.get("username"),
            "can_invite": True,  # If we can access guild, we likely have invite perms
            "message": "✅ Bot has access to server"
        }
    
    async def create_one_time_invite(
        self,
        name: Optional[str] = None,
        expire_seconds: int = 300
    ) -> Tuple[bool, Dict[str, Any]]:
        """Erstellt einen Einmal-Invite für Discord"""
        if not self.bot_token:
            return False, {"error": "Bot token not configured"}
        
        if not self.guild_id:
            return False, {"error": "Guild ID not configured"}
        
        # Get channels to find a suitable one for invite
        target_channel = self.channel_id
        
        if not target_channel:
            # Get first text channel
            channels_result = await self._api_request("GET", f"/guilds/{self.guild_id}/channels")
            if channels_result.get("ok"):
                channels = channels_result.get("result", [])
                for channel in channels:
                    if channel.get("type") == 0:  # Text channel
                        target_channel = channel.get("id")
                        break
        
        if not target_channel:
            return False, {"error": "No suitable channel found"}
        
        # Create invite
        result = await self._api_request("POST", f"/channels/{target_channel}/invites", {
            "max_age": expire_seconds,
            "max_uses": 1,
            "unique": True
        })
        
        if result.get("ok"):
            invite_data = result.get("result", {})
            invite_code = invite_data.get("code", "")
            return True, {
                "invite_link": f"https://discord.gg/{invite_code}",
                "code": invite_code,
                "max_uses": invite_data.get("max_uses"),
                "max_age": invite_data.get("max_age"),
                "is_one_time": True
            }
        else:
            return False, {"error": result.get("error", "Unknown error")}


# ============================================================================
# Main Gate Service
# ============================================================================

class GateService:
    """
    Zentrale Service-Schicht für alle Gate-Operationen.
    
    Responsibilities:
    - Gate-Konfiguration aus DB laden
    - Bot-Tokens sicher entschlüsseln
    - Dynamische Bot-Instanzen erstellen
    - Caching für Performance
    - Fallback auf statische Links
    """
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._bot_cache: Dict[str, Any] = {}  # Cache für Bot-Instanzen
        
        # Fallback: Default Bots aus .env (für unser eigenes Gate)
        self._default_telegram_token = os.getenv("TELEGRAM_BOT_TOKEN", "")
        self._default_telegram_group = os.getenv("TELEGRAM_GROUP_ID", "")
        self._default_discord_token = os.getenv("DISCORD_BOT_TOKEN", "")
        self._default_discord_guild = os.getenv("DISCORD_GUILD_ID", "")
    
    def _get_db_connection(self):
        """SQLite Connection mit Row Factory"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    async def get_gate_config(
        self, 
        owner_wallet: str, 
        platform: str, 
        group_id: Optional[str] = None
    ) -> Optional[Dict]:
        """
        Holt Gate-Konfiguration aus der Datenbank.
        
        MULTI-GATE SUPPORT: Wenn group_id angegeben, wird das spezifische Gate geholt.
        Ohne group_id wird das erste aktive Gate für die Plattform zurückgegeben.
        
        Args:
            owner_wallet: Wallet-Adresse des Owners
            platform: 'telegram' oder 'discord'
            group_id: Optional - spezifische Group ID
            
        Returns:
            Config-Dict oder None
        """
        try:
            conn = self._get_db_connection()
            cursor = conn.cursor()
            
            if group_id:
                # Specific gate by group_id
                cursor.execute("""
                    SELECT * FROM owner_gate_configs 
                    WHERE owner_wallet = ? AND platform = ? AND group_id = ? AND is_active = 1
                """, (owner_wallet.lower(), platform.lower(), group_id))
            else:
                # First active gate for platform (backward compatibility)
                cursor.execute("""
                    SELECT * FROM owner_gate_configs 
                    WHERE owner_wallet = ? AND platform = ? AND is_active = 1
                    ORDER BY created_at ASC
                    LIMIT 1
                """, (owner_wallet.lower(), platform.lower()))
            
            result = cursor.fetchone()
            conn.close()
            
            return dict(result) if result else None
            
        except Exception as e:
            logger.error(f"Error getting gate config: {e}")
            return None
    
    async def get_all_gates_for_owner(
        self, 
        owner_wallet: str, 
        platform: Optional[str] = None
    ) -> list:
        """
        Holt ALLE Gate-Konfigurationen für einen Owner.
        
        Args:
            owner_wallet: Wallet-Adresse des Owners
            platform: Optional - filter by platform
            
        Returns:
            Liste von Config-Dicts
        """
        try:
            conn = self._get_db_connection()
            cursor = conn.cursor()
            
            if platform:
                cursor.execute("""
                    SELECT * FROM owner_gate_configs 
                    WHERE owner_wallet = ? AND platform = ? AND is_active = 1
                    ORDER BY group_name
                """, (owner_wallet.lower(), platform.lower()))
            else:
                cursor.execute("""
                    SELECT * FROM owner_gate_configs 
                    WHERE owner_wallet = ? AND is_active = 1
                    ORDER BY platform, group_name
                """, (owner_wallet.lower(),))
            
            results = cursor.fetchall()
            conn.close()
            
            return [dict(row) for row in results]
            
        except Exception as e:
            logger.error(f"Error getting all gates: {e}")
            return []
    
    async def save_gate_config(
        self,
        owner_wallet: str,
        platform: str,
        bot_token: str,
        group_id: str,
        channel_id: str = "",
        group_name: str = "",
        static_invite_link: str = "",
        min_score: int = 50
    ) -> Dict[str, Any]:
        """
        Speichert Gate-Konfiguration in der Datenbank.
        Bot-Token wird verschlüsselt gespeichert!
        
        MULTI-GATE SUPPORT: UNIQUE(owner_wallet, platform, group_id)
        Ein Owner kann mehrere Gates pro Plattform haben!
        
        Args:
            owner_wallet: Wallet-Adresse des Owners
            platform: 'telegram' oder 'discord'
            bot_token: Bot-Token (wird verschlüsselt)
            group_id: Telegram Group ID oder Discord Guild ID
            channel_id: Discord Channel ID (optional)
            group_name: Name der Gruppe (optional)
            static_invite_link: Fallback-Link (empfohlen)
            min_score: Minimum Resonance Score (50-200, default 50)
        
        Returns:
            {"success": bool, "error": str or None}
        """
        try:
            # Validate token format
            if bot_token:
                validation = gate_encryption.verify_token_format(bot_token, platform)
                if not validation["valid"]:
                    return {"success": False, "error": validation["error"]}
            
            # Validate min_score
            if not isinstance(min_score, int) or min_score < 50 or min_score > 200:
                min_score = 50
            
            # Encrypt token
            encrypted_token = None
            if bot_token and gate_encryption.is_configured:
                encrypted_token = gate_encryption.encrypt_token(bot_token)
                if not encrypted_token:
                    return {"success": False, "error": "Failed to encrypt token"}
            elif bot_token and not gate_encryption.is_configured:
                return {"success": False, "error": "Encryption not configured (GATE_ENCRYPTION_KEY missing)"}
            
            conn = self._get_db_connection()
            cursor = conn.cursor()
            
            now = datetime.now(timezone.utc).isoformat()
            
            # MULTI-GATE: UNIQUE constraint ist jetzt (owner_wallet, platform, group_id)
            # WICHTIG: COALESCE um existierenden bot_token zu behalten wenn neuer leer ist
            # SECURITY: bot_verified wird immer auf 0 gesetzt wenn neuer Token → User MUSS verify drücken!
            cursor.execute("""
                INSERT INTO owner_gate_configs 
                (owner_wallet, platform, bot_token_encrypted, group_id, channel_id, 
                 group_name, static_invite_link, min_score, created_at, updated_at, is_active, bot_verified)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0)
                ON CONFLICT(owner_wallet, platform, group_id) DO UPDATE SET
                    bot_token_encrypted = COALESCE(excluded.bot_token_encrypted, owner_gate_configs.bot_token_encrypted),
                    channel_id = COALESCE(excluded.channel_id, owner_gate_configs.channel_id),
                    group_name = COALESCE(excluded.group_name, owner_gate_configs.group_name),
                    static_invite_link = COALESCE(excluded.static_invite_link, owner_gate_configs.static_invite_link),
                    min_score = COALESCE(excluded.min_score, owner_gate_configs.min_score),
                    updated_at = excluded.updated_at,
                    is_active = 1,
                    bot_verified = CASE 
                        WHEN excluded.bot_token_encrypted IS NOT NULL 
                             AND excluded.bot_token_encrypted != owner_gate_configs.bot_token_encrypted 
                        THEN 0 
                        ELSE owner_gate_configs.bot_verified 
                    END,
                    verified_at = CASE 
                        WHEN excluded.bot_token_encrypted IS NOT NULL 
                             AND excluded.bot_token_encrypted != owner_gate_configs.bot_token_encrypted 
                        THEN NULL 
                        ELSE owner_gate_configs.verified_at 
                    END
            """, (
                owner_wallet.lower(), 
                platform.lower(), 
                encrypted_token,
                group_id,
                channel_id,
                group_name,
                static_invite_link,
                min_score,
                now,
                now
            ))
            
            conn.commit()
            conn.close()
            
            # Clear cache for this owner+group
            cache_key = f"{owner_wallet.lower()}:{platform.lower()}:{group_id}"
            if cache_key in self._bot_cache:
                del self._bot_cache[cache_key]
            
            if bot_token:
                logger.info(f"⚠️ Gate config SAVED (NOT VERIFIED YET) for {owner_wallet[:10]}... ({platform}, group={group_id[:15]}, min_score={min_score})")
                logger.info(f"   ⏳ User MUST click '✅ Verify Bot Permissions' to complete setup!")
            else:
                logger.info(f"✓ Gate config saved (static link only) for {owner_wallet[:10]}... ({platform}, group={group_id[:15]}, min_score={min_score})")
            
            return {"success": True, "error": None}
            
        except Exception as e:
            logger.error(f"Error saving gate config: {e}")
            return {"success": False, "error": str(e)}
    
    async def get_bot_instance(
        self, 
        owner_wallet: str, 
        platform: str,
        group_id: Optional[str] = None
    ) -> Optional[Any]:
        """
        Erstellt oder holt gecachte Bot-Instanz für einen Owner.
        
        MULTI-GATE SUPPORT: group_id identifiziert das spezifische Gate.
        
        Args:
            owner_wallet: Wallet-Adresse des Owners
            platform: 'telegram' oder 'discord'
            group_id: Optional - spezifische Group ID
            
        Returns:
            DynamicTelegramBot, DynamicDiscordBot, oder None
        """
        # Cache key includes group_id for multi-gate support
        if group_id:
            cache_key = f"{owner_wallet.lower()}:{platform.lower()}:{group_id}"
        else:
            cache_key = f"{owner_wallet.lower()}:{platform.lower()}"
        
        # Check cache first
        if cache_key in self._bot_cache:
            return self._bot_cache[cache_key]
        
        # Get config from DB
        config = await self.get_gate_config(owner_wallet, platform, group_id)
        
        if not config:
            return None
        
        encrypted_token = config.get("bot_token_encrypted")
        if not encrypted_token:
            return None
        
        # Decrypt token
        bot_token = gate_encryption.decrypt_token(encrypted_token)
        if not bot_token:
            logger.error(f"Failed to decrypt token for {owner_wallet[:10]}...")
            return None
        
        # Create bot instance
        if platform.lower() == "telegram":
            bot = DynamicTelegramBot(
                bot_token=bot_token,
                group_id=config.get("group_id", ""),
                owner_wallet=owner_wallet
            )
        elif platform.lower() == "discord":
            bot = DynamicDiscordBot(
                bot_token=bot_token,
                guild_id=config.get("group_id", ""),
                channel_id=config.get("channel_id", ""),
                owner_wallet=owner_wallet
            )
        else:
            return None
        
        # Cache the instance (with group_id in key)
        self._bot_cache[cache_key] = bot
        
        return bot
    
    async def verify_bot(
        self, 
        owner_wallet: str, 
        platform: str,
        group_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Verifiziert dass der Bot korrekt konfiguriert ist.
        
        MULTI-GATE SUPPORT: group_id identifiziert das spezifische Gate.
        
        Returns:
            {"success": bool, "bot_username": str, "can_invite": bool, "error": str}
        """
        bot = await self.get_bot_instance(owner_wallet, platform, group_id)
        
        if not bot:
            return {
                "success": False,
                "error": "No bot configured for this gate"
            }
        
        # Verify permissions
        result = await bot.verify_permissions()
        
        if result.get("ok") and result.get("can_invite"):
            # Update DB with verified status
            try:
                conn = self._get_db_connection()
                cursor = conn.cursor()
                
                if group_id:
                    cursor.execute("""
                        UPDATE owner_gate_configs 
                        SET bot_verified = 1, 
                            bot_username = ?,
                            verified_at = ?,
                            health_status = 'healthy'
                        WHERE owner_wallet = ? AND platform = ? AND group_id = ?
                    """, (
                        result.get("bot_username"),
                        datetime.now(timezone.utc).isoformat(),
                        owner_wallet.lower(),
                        platform.lower(),
                        group_id
                    ))
                else:
                    cursor.execute("""
                        UPDATE owner_gate_configs 
                        SET bot_verified = 1, 
                            bot_username = ?,
                            verified_at = ?,
                            health_status = 'healthy'
                        WHERE owner_wallet = ? AND platform = ?
                    """, (
                        result.get("bot_username"),
                        datetime.now(timezone.utc).isoformat(),
                        owner_wallet.lower(),
                        platform.lower()
                    ))
                conn.commit()
                conn.close()
            except Exception as e:
                logger.error(f"Failed to update verification status: {e}")
            
            return {
                "success": True,
                "bot_username": result.get("bot_username"),
                "can_invite": True,
                "message": result.get("message", "Bot verified successfully")
            }
        else:
            return {
                "success": False,
                "error": result.get("error", "Verification failed"),
                "can_invite": result.get("can_invite", False)
            }
    
    async def create_one_time_invite(
        self,
        owner_wallet: str,
        platform: str,
        user_address: str,
        group_id: Optional[str] = None,
        expire_seconds: int = 300
    ) -> Tuple[bool, str, str]:
        """
        Erstellt einen Einmal-Link für das Gate eines Owners.
        
        MULTI-GATE SUPPORT: group_id identifiziert das spezifische Gate.
        
        Args:
            owner_wallet: Wallet des Gate-Owners
            platform: 'telegram' oder 'discord'
            user_address: Wallet des Users der beitreten will
            group_id: Optional - spezifische Group ID
            expire_seconds: Gültigkeit des Links
            
        Returns:
            (success: bool, invite_link: str, method: str)
            method: 'bot_one_time' | 'static_fallback' | 'default_bot'
        """
        # 1. Try owner's configured bot
        bot = await self.get_bot_instance(owner_wallet, platform, group_id)
        
        if bot and bot.is_configured:
            name = f"AEra-{user_address[:8]}"
            success, result = await bot.create_one_time_invite(
                name=name,
                expire_seconds=expire_seconds
            )
            
            if success:
                logger.info(f"✅ One-time link created via owner bot ({owner_wallet[:10]}...)")
                return True, result.get("invite_link", ""), "bot_one_time"
            else:
                logger.warning(f"Owner bot failed: {result.get('error')}")
        
        # 2. Try static fallback link from owner's config (with group_id for multi-gate)
        config = await self.get_gate_config(owner_wallet, platform, group_id)
        if config and config.get("static_invite_link"):
            logger.info(f"Using static fallback link for {owner_wallet[:10]}... (group={group_id or 'default'})")
            return True, config["static_invite_link"], "static_fallback"
        
        # 3. Try default bot (our hardcoded bot from .env)
        if platform.lower() == "telegram" and self._default_telegram_token:
            default_bot = DynamicTelegramBot(
                bot_token=self._default_telegram_token,
                group_id=self._default_telegram_group,
                owner_wallet="default"
            )
            name = f"AEra-{user_address[:8]}"
            success, result = await default_bot.create_one_time_invite(
                name=name,
                expire_seconds=expire_seconds
            )
            if success:
                logger.info("✅ Using default AEra bot")
                return True, result.get("invite_link", ""), "default_bot"
        
        elif platform.lower() == "discord" and self._default_discord_token:
            default_bot = DynamicDiscordBot(
                bot_token=self._default_discord_token,
                guild_id=self._default_discord_guild,
                owner_wallet="default"
            )
            name = f"AEra-{user_address[:8]}"
            success, result = await default_bot.create_one_time_invite(
                name=name,
                expire_seconds=expire_seconds
            )
            if success:
                logger.info("✅ Using default AEra bot")
                return True, result.get("invite_link", ""), "default_bot"
        
        # 4. No method available
        return False, "", "no_config"
    
    async def get_gate_status(
        self, 
        owner_wallet: str, 
        platform: str,
        group_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Gibt den Status eines Gates zurück.
        
        MULTI-GATE SUPPORT: group_id identifiziert das spezifische Gate.
        
        Returns:
            {
                "configured": bool,
                "bot_verified": bool,
                "has_static_fallback": bool,
                "security_level": "high" | "medium" | "low",
                "bot_username": str or None,
                "min_score": int
            }
        """
        config = await self.get_gate_config(owner_wallet, platform, group_id)
        
        if not config:
            return {
                "configured": False,
                "bot_verified": False,
                "has_static_fallback": False,
                "security_level": "none",
                "bot_username": None,
                "min_score": 50
            }
        
        has_bot = bool(config.get("bot_token_encrypted"))
        bot_verified = bool(config.get("bot_verified"))
        has_static = bool(config.get("static_invite_link"))
        
        # Determine security level
        if has_bot and bot_verified:
            security_level = "high"  # One-time links
        elif has_static:
            security_level = "low"   # Static links can be shared
        else:
            security_level = "none"
        
        return {
            "configured": True,
            "bot_verified": bot_verified,
            "has_static_fallback": has_static,
            "security_level": security_level,
            "bot_username": config.get("bot_username"),
            "group_name": config.get("group_name"),
            "group_id": config.get("group_id"),
            "min_score": config.get("min_score", 50),
            "created_at": config.get("created_at")
        }


# ============================================================================
# Singleton Instance
# ============================================================================

# Will be initialized when server.py imports this module
gate_service: Optional[GateService] = None


def init_gate_service(db_path: str) -> GateService:
    """Initialisiert den GateService mit DB-Pfad"""
    global gate_service
    gate_service = GateService(db_path)
    logger.info(f"✓ GateService initialized with DB: {db_path}")
    return gate_service


def get_gate_service() -> Optional[GateService]:
    """Gibt die GateService-Instanz zurück"""
    return gate_service
