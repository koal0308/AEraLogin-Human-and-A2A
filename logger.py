# VEra-Resonance Logger Module
# © 2025 Karlheinz Beismann — VEra-Resonance Project
# Licensed under the Apache License, Version 2.0

import logging
import json
from datetime import datetime
from pathlib import Path

# Logs Verzeichnis erstellen
LOG_DIR = Path(__file__).parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

# Hauptlog Datei
MAIN_LOG_FILE = LOG_DIR / "aera.log"
JSON_LOG_FILE = LOG_DIR / "aera.json"
ERROR_LOG_FILE = LOG_DIR / "errors.log"
ACTIVITY_LOG_FILE = LOG_DIR / "activity.log"

class JSONFormatter(logging.Formatter):
    """JSON-Format für strukturierte Logs"""
    def format(self, record):
        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        return json.dumps(log_data, ensure_ascii=False)

def setup_logger(name):
    """Erstelle einen vollständig konfigurierten Logger"""
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    
    # Verhindere doppelte Handler
    if logger.handlers:
        return logger
    
    # ==== MAIN LOG (alles) ====
    main_handler = logging.FileHandler(MAIN_LOG_FILE, encoding='utf-8')
    main_handler.setLevel(logging.DEBUG)
    main_formatter = logging.Formatter(
        '[%(asctime)s] [%(levelname)-8s] [%(name)s:%(funcName)s:%(lineno)d] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    main_handler.setFormatter(main_formatter)
    
    # ==== JSON LOG (strukturiert für Analyse) ====
    json_handler = logging.FileHandler(JSON_LOG_FILE, encoding='utf-8')
    json_handler.setLevel(logging.DEBUG)
    json_handler.setFormatter(JSONFormatter())
    
    # ==== ERROR LOG (nur Fehler) ====
    error_handler = logging.FileHandler(ERROR_LOG_FILE, encoding='utf-8')
    error_handler.setLevel(logging.ERROR)
    error_formatter = logging.Formatter(
        '[%(asctime)s] [ERROR] [%(name)s] %(message)s\n%(exc_info)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    error_handler.setFormatter(error_formatter)
    
    # ==== ACTIVITY LOG (nur wichtige Events) ====
    activity_handler = logging.FileHandler(ACTIVITY_LOG_FILE, encoding='utf-8')
    activity_handler.setLevel(logging.INFO)
    activity_formatter = logging.Formatter(
        '[%(asctime)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    activity_handler.setFormatter(activity_formatter)
    
    # ==== CONSOLE (wichtige Messages) ====
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter(
        '[%(asctime)s] [%(levelname)-8s] %(message)s',
        datefmt='%H:%M:%S'
    )
    console_handler.setFormatter(console_formatter)
    
    logger.addHandler(main_handler)
    logger.addHandler(json_handler)
    logger.addHandler(error_handler)
    logger.addHandler(activity_handler)
    logger.addHandler(console_handler)
    
    return logger

# ===== STANDARD LOGGER =====
logger = setup_logger("AEra")

# ===== SPEZIAL-LOGGER =====
auth_logger = setup_logger("AEra.Auth")        # Authentifizierung
blockchain_logger = setup_logger("AEra.Web3")  # Web3/Blockchain
db_logger = setup_logger("AEra.Database")      # Datenbank
api_logger = setup_logger("AEra.API")          # API Requests
wallet_logger = setup_logger("AEra.Wallet")    # Wallet Operationen
airdrop_logger = setup_logger("AEra.Airdrop")  # Airdrop Worker

def log_activity(level, category, message, **extra_data):
    """
    Protokolliere eine Aktivität mit Kategorie
    
    Beispiel:
        log_activity("INFO", "AUTH", "User registered", address="0x...", score=50)
    """
    full_message = f"[{category}] {message}"
    if extra_data:
        full_message += " | " + " | ".join(f"{k}={v}" for k, v in extra_data.items())
    
    if level.upper() == "DEBUG":
        logger.debug(full_message)
    elif level.upper() == "INFO":
        logger.info(full_message)
    elif level.upper() == "WARNING":
        logger.warning(full_message)
    elif level.upper() == "ERROR":
        logger.error(full_message)
    elif level.upper() == "CRITICAL":
        logger.critical(full_message)

if __name__ == "__main__":
    # Test Logging
    logger.debug("Debug Message Test")
    logger.info("Info Message Test")
    logger.warning("Warning Message Test")
    logger.error("Error Message Test")
    
    log_activity("INFO", "TEST", "Test Activity", user="test_user", score=50)
    log_activity("ERROR", "TEST", "Test Error", error="Sample error")
    
    print(f"\n✅ Logs erstellt in: {LOG_DIR}")
    print(f"   📄 Main Log: {MAIN_LOG_FILE}")
    print(f"   📊 JSON Log: {JSON_LOG_FILE}")
    print(f"   ❌ Error Log: {ERROR_LOG_FILE}")
    print(f"   📝 Activity Log: {ACTIVITY_LOG_FILE}")
