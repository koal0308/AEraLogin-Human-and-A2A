#!/usr/bin/env python3
"""
Telegram Group ID Finder
Zeigt die Group ID an, wenn du deinen Bot zur Gruppe hinzufügst und eine Nachricht sendest.
"""

import os
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import Application, MessageHandler, filters, ContextTypes

load_dotenv()

# Dein Bot Token (oder lass es leer und gib es beim Start ein)
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")

async def get_chat_info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Diese Funktion wird aufgerufen, wenn eine Nachricht in einer Gruppe gesendet wird.
    Sie zeigt die Group ID an.
    """
    chat = update.effective_chat
    user = update.effective_user
    
    print("\n" + "="*60)
    print("📊 TELEGRAM GRUPPE GEFUNDEN!")
    print("="*60)
    print(f"📝 Gruppen Name: {chat.title}")
    print(f"🆔 GROUP ID: {chat.id}")
    print(f"👤 Nachricht von: {user.first_name} (@{user.username})")
    print(f"🔗 Chat Type: {chat.type}")
    print("="*60)
    print(f"\n✅ Verwende diese Group ID in deiner Konfiguration:")
    print(f"   GROUP_ID = {chat.id}")
    print("="*60 + "\n")
    
    # Sende Bestätigung in die Gruppe
    await update.message.reply_text(
        f"✅ Group ID gefunden!\n\n"
        f"🆔 ID: `{chat.id}`\n"
        f"📝 Name: {chat.title}\n\n"
        f"Kopiere die ID oben (ohne Backticks) und verwende sie in deiner Gate-Konfiguration.",
        parse_mode="Markdown"
    )

def main():
    """Starte den Bot und warte auf Nachrichten"""
    
    # Bot Token abrufen
    token = BOT_TOKEN
    if not token:
        print("\n⚠️  TELEGRAM_BOT_TOKEN nicht in .env gefunden!")
        token = input("📱 Bitte gib deinen Bot Token ein: ").strip()
    
    if not token:
        print("❌ Kein Bot Token angegeben!")
        return
    
    print("\n🤖 Starte Telegram Group ID Finder...")
    print("="*60)
    print("📋 ANLEITUNG:")
    print("   1. Füge deinen Bot zur Telegram-Gruppe hinzu")
    print("   2. Sende EINE BELIEBIGE NACHRICHT in der Gruppe")
    print("   3. Die Group ID wird hier angezeigt")
    print("   4. Drücke CTRL+C zum Beenden")
    print("="*60 + "\n")
    
    # Bot-Application erstellen
    app = Application.builder().token(token).build()
    
    # Handler für ALLE Nachrichten in Gruppen
    app.add_handler(MessageHandler(
        filters.ChatType.GROUPS | filters.ChatType.SUPERGROUP,
        get_chat_info
    ))
    
    # Bot starten
    print("✅ Bot läuft und wartet auf Nachrichten...\n")
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Bot gestoppt!")
    except Exception as e:
        print(f"\n❌ Fehler: {e}")
