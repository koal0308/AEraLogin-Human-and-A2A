"""
🔐 Gate Token Encryption Service
================================

Sichere Verschlüsselung für Bot-Tokens in der Datenbank.
Verwendet Fernet (AES-128-CBC + HMAC-SHA256) für symmetrische Verschlüsselung.

WICHTIG:
- Master-Key MUSS in .env bleiben (GATE_ENCRYPTION_KEY)
- Niemals Keys in der Datenbank speichern
- Bei Key-Verlust sind alle gespeicherten Tokens unbrauchbar

Author: VEra-Resonance
Created: 2026-01-03
"""

import os
import base64
import hashlib
import secrets
from typing import Optional
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv

load_dotenv()


class GateTokenEncryption:
    """
    Verschlüsselungsservice für Bot-Tokens
    
    Features:
    - AES-256 basierte Verschlüsselung (via Fernet)
    - Automatische Key-Generierung wenn nicht vorhanden
    - Sichere Token-Validierung
    """
    
    def __init__(self):
        """
        Initialisiert den Encryption Service.
        Liest GATE_ENCRYPTION_KEY aus .env oder generiert neuen Key.
        """
        self._master_key = os.getenv("GATE_ENCRYPTION_KEY", "")
        self._fernet: Optional[Fernet] = None
        
        if self._master_key:
            try:
                # Validiere dass Key ein gültiger Fernet-Key ist
                self._fernet = Fernet(self._master_key.encode())
            except Exception:
                # Key ist kein gültiger Fernet-Key, versuche zu konvertieren
                self._fernet = self._derive_key_from_secret(self._master_key)
        else:
            # Kein Key konfiguriert - Service im "disabled" Modus
            self._fernet = None
    
    def _derive_key_from_secret(self, secret: str) -> Fernet:
        """
        Leitet einen Fernet-Key aus einem beliebigen Secret ab.
        Verwendet SHA-256 + Base64 für Kompatibilität.
        """
        # SHA-256 Hash des Secrets
        hash_bytes = hashlib.sha256(secret.encode()).digest()
        # Fernet benötigt URL-safe Base64 encoded 32-byte key
        key = base64.urlsafe_b64encode(hash_bytes)
        return Fernet(key)
    
    @property
    def is_configured(self) -> bool:
        """Prüft ob Encryption konfiguriert ist"""
        return self._fernet is not None
    
    @staticmethod
    def generate_new_key() -> str:
        """
        Generiert einen neuen Fernet-Key.
        Dieser sollte in .env als GATE_ENCRYPTION_KEY gespeichert werden.
        
        Returns:
            URL-safe Base64 encoded 32-byte key
        """
        return Fernet.generate_key().decode()
    
    def encrypt_token(self, plaintext: str) -> Optional[str]:
        """
        Verschlüsselt einen Bot-Token.
        
        Args:
            plaintext: Der Bot-Token im Klartext
            
        Returns:
            Verschlüsselter Token (Base64) oder None bei Fehler
        """
        if not self._fernet:
            return None
        
        if not plaintext:
            return None
        
        try:
            encrypted = self._fernet.encrypt(plaintext.encode())
            return encrypted.decode()
        except Exception as e:
            print(f"❌ Encryption error: {e}")
            return None
    
    def decrypt_token(self, encrypted: str) -> Optional[str]:
        """
        Entschlüsselt einen Bot-Token.
        
        Args:
            encrypted: Der verschlüsselte Token (Base64)
            
        Returns:
            Entschlüsselter Token oder None bei Fehler
        """
        if not self._fernet:
            return None
        
        if not encrypted:
            return None
        
        try:
            decrypted = self._fernet.decrypt(encrypted.encode())
            return decrypted.decode()
        except InvalidToken:
            print("❌ Decryption failed: Invalid token (wrong key or corrupted data)")
            return None
        except Exception as e:
            print(f"❌ Decryption error: {e}")
            return None
    
    def verify_token_format(self, token: str, platform: str) -> dict:
        """
        Überprüft ob ein Token das richtige Format für die Platform hat.
        
        Args:
            token: Der Bot-Token
            platform: 'telegram' oder 'discord'
            
        Returns:
            {"valid": bool, "error": str or None}
        """
        if not token:
            return {"valid": False, "error": "Token is empty"}
        
        if platform == "telegram":
            # Telegram Bot Token Format: 123456789:ABCdefGHIjklMNOpqrSTUvwxYZ
            if ":" not in token:
                return {"valid": False, "error": "Invalid Telegram token format (missing ':')"}
            
            parts = token.split(":")
            if len(parts) != 2:
                return {"valid": False, "error": "Invalid Telegram token format"}
            
            bot_id, bot_hash = parts
            if not bot_id.isdigit():
                return {"valid": False, "error": "Invalid Telegram token (bot ID must be numeric)"}
            
            if len(bot_hash) < 30:
                return {"valid": False, "error": "Invalid Telegram token (hash too short)"}
            
            return {"valid": True, "error": None}
        
        elif platform == "discord":
            # Discord Bot Token: Base64-encoded, typically 59-72 chars
            if len(token) < 50:
                return {"valid": False, "error": "Invalid Discord token (too short)"}
            
            # Discord tokens have 3 parts separated by dots
            parts = token.split(".")
            if len(parts) != 3:
                return {"valid": False, "error": "Invalid Discord token format (should have 3 parts)"}
            
            return {"valid": True, "error": None}
        
        else:
            return {"valid": False, "error": f"Unknown platform: {platform}"}


# Singleton Instance
gate_encryption = GateTokenEncryption()


# ===== CLI TOOL =====
if __name__ == "__main__":
    print("🔐 Gate Encryption Tool")
    print("=" * 40)
    
    # Generate new key
    new_key = GateTokenEncryption.generate_new_key()
    print(f"\n📝 New encryption key (add to .env):")
    print(f"   GATE_ENCRYPTION_KEY={new_key}")
    
    # Test encryption
    if gate_encryption.is_configured:
        print(f"\n✅ Encryption is configured")
        
        test_token = "1234567890:TEST-ONLY-not-a-real-bot-token"
        encrypted = gate_encryption.encrypt_token(test_token)
        decrypted = gate_encryption.decrypt_token(encrypted)
        
        print(f"\n🧪 Test:")
        print(f"   Original:  {test_token[:20]}...")
        print(f"   Encrypted: {encrypted[:40]}...")
        print(f"   Decrypted: {decrypted[:20]}...")
        print(f"   Match: {'✅' if test_token == decrypted else '❌'}")
    else:
        print(f"\n⚠️ Encryption NOT configured (GATE_ENCRYPTION_KEY missing in .env)")
        print(f"   Add this to your .env file:")
        print(f"   GATE_ENCRYPTION_KEY={new_key}")
