#!/usr/bin/env python3
"""
EINFACHSTER WEG: Telegram Group ID finden
Zeigt alle Updates an, die dein Bot empfängt
"""

import os
import sys
from dotenv import load_dotenv

load_dotenv()

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")

if not BOT_TOKEN:
    print("\n❌ TELEGRAM_BOT_TOKEN nicht in .env gefunden!")
    BOT_TOKEN = input("📱 Bitte gib deinen Bot Token ein: ").strip()

if not BOT_TOKEN:
    print("❌ Kein Bot Token!")
    sys.exit(1)

print("\n" + "="*70)
print("🔍 TELEGRAM GROUP ID FINDER")
print("="*70)
print("\n📋 SCHRITT-FÜR-SCHRITT ANLEITUNG:")
print("   1. Füge deinen Bot zur Telegram-Gruppe hinzu")
print("   2. Mache ihn zum ADMIN (wichtig!)")
print("   3. Sende EINE NACHRICHT in der Gruppe")
print("   4. Die Group ID erscheint hier sofort!")
print("\n⏳ Warte auf Updates...\n")
print("="*70 + "\n")

import requests

# Hole die letzten Updates vom Bot
url = f"https://api.telegram.org/bot{BOT_TOKEN}/getUpdates"

try:
    response = requests.get(url, timeout=10)
    data = response.json()
    
    if not data.get("ok"):
        print(f"❌ Fehler: {data.get('description')}")
        print("💡 Tipp: Prüfe ob der Bot Token korrekt ist")
        sys.exit(1)
    
    updates = data.get("result", [])
    
    if not updates:
        print("⚠️  Keine Updates gefunden!")
        print("\n💡 LÖSUNG:")
        print("   1. Gehe zu deiner Telegram-Gruppe")
        print("   2. Sende JETZT eine Nachricht (z.B. 'test')")
        print("   3. Führe dieses Script ERNEUT aus")
        sys.exit(0)
    
    print(f"✅ {len(updates)} Update(s) gefunden!\n")
    
    groups_found = {}
    
    for update in updates:
        # Check message
        if "message" in update:
            msg = update["message"]
            chat = msg.get("chat", {})
            chat_type = chat.get("type")
            
            if chat_type in ["group", "supergroup"]:
                chat_id = chat.get("id")
                chat_title = chat.get("title", "Unbekannt")
                
                if chat_id not in groups_found:
                    groups_found[chat_id] = chat_title
        
        # Check my_chat_member (bot was added)
        if "my_chat_member" in update:
            member = update["my_chat_member"]
            chat = member.get("chat", {})
            chat_type = chat.get("type")
            
            if chat_type in ["group", "supergroup"]:
                chat_id = chat.get("id")
                chat_title = chat.get("title", "Unbekannt")
                
                if chat_id not in groups_found:
                    groups_found[chat_id] = chat_title
    
    if not groups_found:
        print("⚠️  Keine Gruppen in den Updates gefunden!")
        print("\n💡 LÖSUNG:")
        print("   1. Stelle sicher, dass der Bot in der Gruppe ist")
        print("   2. Sende eine Nachricht in der Gruppe")
        print("   3. Führe dieses Script erneut aus")
        sys.exit(0)
    
    print("🎉 GRUPPEN GEFUNDEN!\n")
    print("="*70)
    
    for group_id, group_name in groups_found.items():
        print(f"\n✅ Gruppe: {group_name}")
        print(f"🆔 GROUP ID: {group_id}")
        print(f"\n📋 Kopiere diese ID für deine Konfiguration:")
        print(f"   group_id = \"{group_id}\"")
        print("-"*70)
    
    print("\n✅ FERTIG! Verwende die Group ID oben in deiner Gate-Konfiguration.")
    print("="*70)

except requests.exceptions.Timeout:
    print("❌ Timeout beim Verbinden zur Telegram API")
    print("💡 Prüfe deine Internetverbindung")
except requests.exceptions.RequestException as e:
    print(f"❌ Netzwerkfehler: {e}")
except Exception as e:
    print(f"❌ Unerwarteter Fehler: {e}")
    import traceback
    traceback.print_exc()
