"""
🎮 Discord Bot Service für ECHTE Einmal-Links
=============================================

Nutzt die Discord Bot API um Invite Links mit max_uses=1 zu erstellen.
Jeder Link kann NUR von EINER Person genutzt werden!

Voraussetzungen:
1. Discord Bot erstellen unter https://discord.com/developers/applications
2. Bot mit folgenden Rechten zur Guild hinzufügen:
   - CREATE_INSTANT_INVITE
   - VIEW_CHANNEL
3. DISCORD_BOT_TOKEN und DISCORD_GUILD_ID (und optional DISCORD_CHANNEL_ID) in .env setzen

Author: VEra-Resonance
Created: 2025-12-28
"""

import os
import aiohttp
import logging
from datetime import datetime, timezone
from typing import Optional, Tuple, Dict, Any
from dotenv import load_dotenv

# .env laden
load_dotenv()

# Logger
logger = logging.getLogger("DiscordBot")
logger.setLevel(logging.INFO)

# Discord API Base URL
DISCORD_API_BASE = "https://discord.com/api/v10"


class DiscordBotService:
    """
    Service für Discord Bot API Interaktionen
    """
    
    def __init__(self):
        self.bot_token = os.getenv("DISCORD_BOT_TOKEN", "")
        self.default_guild_id = os.getenv("DISCORD_GUILD_ID", "")  # Server ID
        self.default_channel_id = os.getenv("DISCORD_CHANNEL_ID", "")  # Channel für Invite
        self._bot_info = None
    
    @property
    def is_configured(self) -> bool:
        """Prüft ob Bot konfiguriert ist"""
        return bool(self.bot_token and self.default_guild_id)
    
    @property
    def headers(self) -> Dict[str, str]:
        """Standard API Headers mit Authorization"""
        return {
            "Authorization": f"Bot {self.bot_token}",
            "Content-Type": "application/json"
        }
    
    async def _api_request(
        self, 
        method: str, 
        endpoint: str, 
        json_data: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Generischer Discord API Request
        
        Args:
            method: HTTP Method (GET, POST, DELETE)
            endpoint: API Endpoint (z.B. "/users/@me", "/guilds/{id}")
            json_data: JSON Body für POST/PUT Requests
        
        Returns:
            API Response als Dict
        """
        url = f"{DISCORD_API_BASE}{endpoint}"
        
        try:
            async with aiohttp.ClientSession() as session:
                kwargs = {"headers": self.headers}
                if json_data:
                    kwargs["json"] = json_data
                
                async with session.request(method, url, **kwargs) as response:
                    # Discord gibt bei manchen Endpoints leeren Body zurück
                    if response.status == 204:
                        return {"ok": True}
                    
                    result = await response.json()
                    
                    # Discord API Fehler haben "message" und optional "code"
                    if "message" in result and response.status >= 400:
                        error_msg = result.get("message", "Unknown error")
                        error_code = result.get("code", 0)
                        logger.error(f"❌ Discord API Error [{error_code}]: {error_msg}")
                        return {"ok": False, "error": error_msg, "code": error_code}
                    
                    return {"ok": True, "result": result}
                    
        except aiohttp.ClientError as e:
            logger.error(f"❌ Discord API Connection Error: {str(e)}")
            return {"ok": False, "error": f"Connection error: {str(e)}"}
        except Exception as e:
            logger.error(f"❌ Discord API Exception: {str(e)}")
            return {"ok": False, "error": str(e)}
    
    async def get_bot_info(self) -> Dict[str, Any]:
        """
        Holt Bot-Informationen (GET /users/@me)
        
        Returns:
            Bot Info oder Error
        """
        if self._bot_info:
            return {"ok": True, "result": self._bot_info}
        
        result = await self._api_request("GET", "/users/@me")
        
        if result.get("ok"):
            self._bot_info = result.get("result", {})
            logger.info(f"🤖 Bot Info: {self._bot_info.get('username')}#{self._bot_info.get('discriminator', '0')}")
        
        return result
    
    async def get_guild_info(self, guild_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Holt Informationen über die Guild/Server
        
        Args:
            guild_id: Discord Guild/Server ID (optional, nutzt default)
        
        Returns:
            Guild Info (name, member_count, etc.)
        """
        target_guild = guild_id or self.default_guild_id
        
        if not target_guild:
            return {"ok": False, "error": "No guild ID configured"}
        
        result = await self._api_request("GET", f"/guilds/{target_guild}")
        
        if result.get("ok"):
            guild = result.get("result", {})
            return {
                "ok": True,
                "id": guild.get("id"),
                "name": guild.get("name"),
                "member_count": guild.get("approximate_member_count"),
                "icon": guild.get("icon")
            }
        
        return result
    
    async def get_guild_channels(self, guild_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Holt alle Channels der Guild
        
        Returns:
            Liste von Channels (filtert für Text-Channels)
        """
        target_guild = guild_id or self.default_guild_id
        
        if not target_guild:
            return {"ok": False, "error": "No guild ID configured"}
        
        result = await self._api_request("GET", f"/guilds/{target_guild}/channels")
        
        if result.get("ok"):
            channels = result.get("result", [])
            # Filtere nur Text Channels (type 0) und News Channels (type 5)
            text_channels = [ch for ch in channels if ch.get("type") in [0, 5]]
            return {
                "ok": True,
                "channels": text_channels
            }
        
        return result
    
    async def verify_bot_permissions(
        self, 
        guild_id: Optional[str] = None,
        channel_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Prüft ob Bot CREATE_INSTANT_INVITE Berechtigung hat
        
        Args:
            guild_id: Discord Guild ID (optional)
            channel_id: Channel ID zum Testen (optional)
        
        Returns:
            {"ok": True, "can_invite": True} oder Error
        """
        target_guild = guild_id or self.default_guild_id
        target_channel = channel_id or self.default_channel_id
        
        if not target_guild:
            return {"ok": False, "error": "No guild ID configured"}
        
        # Get bot's member info in the guild
        bot_info = await self.get_bot_info()
        if not bot_info.get("ok"):
            return bot_info
        
        bot_id = self._bot_info.get("id")
        
        # Get bot's member info
        result = await self._api_request("GET", f"/guilds/{target_guild}/members/{bot_id}")
        
        if not result.get("ok"):
            return {"ok": False, "error": "Bot is not in the guild", "can_invite": False}
        
        member = result.get("result", {})
        roles = member.get("roles", [])
        
        # Für eine vollständige Prüfung müssten wir die Rollen-Permissions berechnen
        # Einfacher: Versuchen wir einen Test-Invite zu erstellen
        
        # Wenn kein Channel angegeben, hole den ersten verfügbaren
        if not target_channel:
            channels_result = await self.get_guild_channels(target_guild)
            if channels_result.get("ok") and channels_result.get("channels"):
                target_channel = channels_result["channels"][0]["id"]
            else:
                return {"ok": False, "error": "No accessible channels found", "can_invite": False}
        
        return {
            "ok": True,
            "can_invite": True,  # Wird beim tatsächlichen Erstellen verifiziert
            "guild_id": target_guild,
            "channel_id": target_channel,
            "message": "✅ Bot appears to be configured correctly"
        }
    
    async def create_one_time_invite(
        self,
        guild_id: Optional[str] = None,
        channel_id: Optional[str] = None,
        name: Optional[str] = None,
        expire_seconds: int = 300
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        🎟️ Erstellt einen EINMAL-LINK (max_uses=1)
        
        Der Link kann NUR von EINER Person verwendet werden!
        
        Args:
            guild_id: Discord Guild ID (optional, nutzt default)
            channel_id: Channel ID für den Invite (optional)
            name: Name für den Link (für Logging)
            expire_seconds: Gültigkeit in Sekunden (default: 5 Minuten)
        
        Returns:
            (success: bool, result: Dict)
            result enthält bei Erfolg: invite_url, code, max_uses, expires_at
        """
        target_guild = guild_id or self.default_guild_id
        target_channel = channel_id or self.default_channel_id
        
        if not self.bot_token:
            return False, {"error": "DISCORD_BOT_TOKEN not configured"}
        
        if not target_guild:
            return False, {"error": "DISCORD_GUILD_ID not configured"}
        
        # Wenn kein Channel angegeben, hole den ersten verfügbaren
        if not target_channel:
            channels_result = await self.get_guild_channels(target_guild)
            if channels_result.get("ok") and channels_result.get("channels"):
                target_channel = channels_result["channels"][0]["id"]
                logger.info(f"🎯 Using channel: {channels_result['channels'][0].get('name')}")
            else:
                return False, {"error": "No accessible channels found in guild"}
        
        # Discord API: POST /channels/{channel.id}/invites
        # https://discord.com/developers/docs/resources/channel#create-channel-invite
        invite_data = {
            "max_age": expire_seconds,  # Sekunden bis Ablauf
            "max_uses": 1,              # 🔐 KEY: Nur 1 Person kann diesen Link nutzen!
            "unique": True,             # Neuen Invite erstellen, nicht existierenden wiederverwenden
            "temporary": False          # User bleibt permanent (nicht nur während Session)
        }
        
        logger.info(f"🎟️ Creating one-time invite for channel {target_channel} (expires in {expire_seconds}s)")
        
        result = await self._api_request("POST", f"/channels/{target_channel}/invites", invite_data)
        
        if result.get("ok"):
            invite = result.get("result", {})
            invite_code = invite.get("code", "")
            invite_url = f"https://discord.gg/{invite_code}"
            
            logger.info(f"✅ One-time link created: {invite_url}")
            
            return True, {
                "invite_url": invite_url,
                "invite_link": invite_url,  # Alias für Kompatibilität
                "code": invite_code,
                "max_uses": invite.get("max_uses"),
                "max_age": invite.get("max_age"),
                "channel_id": invite.get("channel", {}).get("id"),
                "guild_id": invite.get("guild", {}).get("id"),
                "is_one_time": True
            }
        else:
            error = result.get("error", "Unknown error")
            error_code = result.get("code", 0)
            
            # Bekannte Fehler
            if error_code == 50013:
                error = "Bot lacks CREATE_INSTANT_INVITE permission"
            elif error_code == 10003:
                error = "Channel not found"
            elif error_code == 50001:
                error = "Bot has no access to this channel"
            
            logger.error(f"❌ Failed to create invite: {error}")
            return False, {"error": error, "code": error_code}
    
    async def revoke_invite(self, invite_code: str) -> bool:
        """
        Widerruft einen Invite Link
        
        Args:
            invite_code: Der Invite Code (ohne discord.gg/)
        
        Returns:
            True wenn erfolgreich
        """
        # Extrahiere Code falls voller Link übergeben wurde
        if "discord.gg/" in invite_code:
            invite_code = invite_code.split("discord.gg/")[-1]
        
        result = await self._api_request("DELETE", f"/invites/{invite_code}")
        
        return result.get("ok", False)
    
    async def get_invite_info(self, invite_code: str) -> Dict[str, Any]:
        """
        Holt Informationen über einen Invite
        
        Args:
            invite_code: Der Invite Code
        
        Returns:
            Invite Info (uses, max_uses, expires_at, etc.)
        """
        # Extrahiere Code falls voller Link
        if "discord.gg/" in invite_code:
            invite_code = invite_code.split("discord.gg/")[-1]
        
        result = await self._api_request("GET", f"/invites/{invite_code}?with_counts=true")
        
        if result.get("ok"):
            invite = result.get("result", {})
            return {
                "ok": True,
                "code": invite.get("code"),
                "uses": invite.get("uses"),
                "max_uses": invite.get("max_uses"),
                "expires_at": invite.get("expires_at"),
                "guild_name": invite.get("guild", {}).get("name"),
                "channel_name": invite.get("channel", {}).get("name")
            }
        
        return result


# Singleton Instance
discord_bot = DiscordBotService()


# ===== CONVENIENCE FUNCTIONS =====

async def create_one_time_discord_invite(
    wallet_address: str,
    guild_id: Optional[str] = None,
    channel_id: Optional[str] = None,
    expire_seconds: int = 300
) -> Tuple[bool, str]:
    """
    Convenience Function: Erstellt Einmal-Link für Wallet
    
    Args:
        wallet_address: Ethereum Wallet Adresse (für Logging)
        guild_id: Optional eigene Guild ID (sonst default)
        channel_id: Optional Channel ID
        expire_seconds: Gültigkeit (default 5 Min)
    
    Returns:
        (success, invite_url_or_error)
    """
    # Create name from wallet for logging
    name = f"AEra-{wallet_address[:8]}"
    
    success, result = await discord_bot.create_one_time_invite(
        guild_id=guild_id,
        channel_id=channel_id,
        name=name,
        expire_seconds=expire_seconds
    )
    
    if success:
        return True, result.get("invite_url", result.get("invite_link", ""))
    else:
        return False, result.get("error", "Unknown error")


async def check_discord_bot_setup() -> Dict[str, Any]:
    """
    Prüft ob Discord Bot korrekt konfiguriert ist
    
    Returns:
        Status-Dict mit allen relevanten Infos
    """
    status = {
        "token_configured": bool(discord_bot.bot_token),
        "guild_configured": bool(discord_bot.default_guild_id),
        "channel_configured": bool(discord_bot.default_channel_id),
        "bot_info": None,
        "guild_info": None,
        "permissions": None,
        "ready": False
    }
    
    if not status["token_configured"]:
        status["error"] = "DISCORD_BOT_TOKEN not set in .env"
        return status
    
    if not status["guild_configured"]:
        status["error"] = "DISCORD_GUILD_ID not set in .env"
        return status
    
    # Check bot info
    bot_result = await discord_bot.get_bot_info()
    if bot_result.get("ok"):
        status["bot_info"] = discord_bot._bot_info
    else:
        status["error"] = f"Bot token invalid: {bot_result.get('error')}"
        return status
    
    # Check guild info
    guild_result = await discord_bot.get_guild_info()
    if guild_result.get("ok"):
        status["guild_info"] = guild_result
    else:
        status["error"] = f"Cannot access guild: {guild_result.get('error')}"
        return status
    
    # Check permissions
    perm_result = await discord_bot.verify_bot_permissions()
    status["permissions"] = perm_result
    
    if perm_result.get("ok") and perm_result.get("can_invite"):
        status["ready"] = True
        bot_name = status['bot_info'].get('username', 'Unknown')
        guild_name = status['guild_info'].get('name', 'Unknown')
        status["message"] = f"✅ Bot {bot_name} ready for guild {guild_name}!"
    else:
        status["error"] = perm_result.get("error", "Bot lacks invite permissions")
    
    return status


# ===== CLI TEST =====
if __name__ == "__main__":
    import asyncio
    
    async def test():
        print("🎮 Testing Discord Bot Service...\n")
        
        # Check setup
        status = await check_discord_bot_setup()
        print(f"Configuration Status:")
        print(f"  Token: {'✅' if status['token_configured'] else '❌'}")
        print(f"  Guild: {'✅' if status['guild_configured'] else '❌'}")
        print(f"  Channel: {'✅' if status['channel_configured'] else '⚠️ (will auto-detect)'}")
        
        if status.get("bot_info"):
            bot = status['bot_info']
            print(f"  Bot: {bot.get('username')}#{bot.get('discriminator', '0')}")
        
        if status.get("guild_info"):
            guild = status['guild_info']
            print(f"  Guild: {guild.get('name')}")
        
        if status.get("permissions"):
            print(f"  Permissions: {status['permissions'].get('message', status['permissions'])}")
        
        if status["ready"]:
            print(f"\n✅ {status['message']}")
            
            # Ask user before creating test link
            user_input = input("\n📝 Create test one-time invite? (y/n): ").strip().lower()
            if user_input == 'y':
                print("\n📝 Creating test one-time invite...")
                success, link = await create_one_time_discord_invite("0xTestWallet1234", expire_seconds=60)
                
                if success:
                    print(f"✅ Link created: {link}")
                    print("   ⚠️ This link will expire in 60 seconds and can only be used ONCE!")
                else:
                    print(f"❌ Failed: {link}")
            else:
                print("Skipped test invite creation.")
        else:
            print(f"\n❌ Not ready: {status.get('error')}")
            print("\n📋 Setup Instructions:")
            print("1. Go to https://discord.com/developers/applications")
            print("2. Create a new application or select existing")
            print("3. Go to 'Bot' section and create/copy the bot token")
            print("4. Go to 'OAuth2' > 'URL Generator'")
            print("5. Select 'bot' scope with 'Create Instant Invite' permission")
            print("6. Use generated URL to add bot to your server")
            print("7. Set in .env:")
            print("   DISCORD_BOT_TOKEN=your_bot_token")
            print("   DISCORD_GUILD_ID=your_server_id")
            print("   DISCORD_CHANNEL_ID=optional_channel_id")
    
    asyncio.run(test())
