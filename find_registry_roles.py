"""
🔍 Registry Contract - Role Finder
Analysiert den Contract Source Code von BaseScan und findet alle Role-Definitionen
"""

import re

# Source Code von BaseScan (File 1 - AEraResonanceRegistry.sol)
# Wir holen den Source Code direkt via API

import requests
import json

# BaseScan API - Contract Source Code abrufen
CONTRACT_ADDRESS = "0xE2d5B85E4A9B0820c59658607C03bC90ba63b7b9"
API_KEY = "YourApiKey"  # Nicht benötigt für Sourcify-verifizierte Contracts

print("=" * 80)
print("🔍 REGISTRY CONTRACT - ROLE ANALYSE")
print("=" * 80)
print(f"\n📍 Contract: {CONTRACT_ADDRESS}")
print(f"🌐 Network: BASE Mainnet (Chain ID 8453)")

# Sourcify API nutzen (alternative zu BaseScan API)
sourcify_url = f"https://repo.sourcify.dev/contracts/full_match/8453/{CONTRACT_ADDRESS}/sources/"

print(f"\n⏳ Hole Contract Source Code von Sourcify...")

try:
    # Liste der verfügbaren Dateien
    files_url = sourcify_url.replace("/sources/", "/")
    response = requests.get(f"https://repo.sourcify.dev/contracts/full_match/8453/{CONTRACT_ADDRESS}/")
    
    if response.status_code == 200:
        print(f"✅ Sourcify gefunden!")
        
        # Hauptdatei suchen
        main_contract_url = f"https://repo.sourcify.dev/contracts/full_match/8453/{CONTRACT_ADDRESS}/sources/contracts/AEraResonanceRegistry.sol"
        
        response = requests.get(main_contract_url)
        if response.status_code == 200:
            source_code = response.text
            print(f"✅ Source Code geladen ({len(source_code)} Zeichen)")
            
            print("\n" + "=" * 80)
            print("📝 ROLE DEFINITIONEN IM CONTRACT:")
            print("=" * 80)
            
            # Suche nach Role-Konstanten
            role_pattern = r'bytes32\s+public\s+constant\s+(\w+ROLE)\s*=\s*keccak256\("([^"]+)"\);'
            roles = re.findall(role_pattern, source_code)
            
            if roles:
                print(f"\n✅ Gefunden: {len(roles)} Role-Definitionen\n")
                for role_name, role_string in roles:
                    print(f"  • {role_name}")
                    print(f"    └─ keccak256(\"{role_string}\")")
                    print()
            else:
                print("\n❌ Keine Role-Konstanten gefunden!")
            
            # Suche nach recordInteraction Funktion
            print("\n" + "=" * 80)
            print("🔍 RECORD INTERACTION FUNKTION:")
            print("=" * 80)
            
            # Finde die Funktion und ihren Modifier
            func_pattern = r'function\s+recordInteraction\s*\([^)]+\)\s+([^{]+)\s*\{'
            func_match = re.search(func_pattern, source_code, re.MULTILINE | re.DOTALL)
            
            if func_match:
                modifiers = func_match.group(1)
                print(f"\nModifiers: {modifiers.strip()}")
                
                # Suche nach onlyRole Modifier
                role_modifier = re.search(r'onlyRole\((\w+)\)', modifiers)
                if role_modifier:
                    required_role = role_modifier.group(1)
                    print(f"\n✅ BENÖTIGTE ROLE: {required_role}")
                else:
                    print(f"\n❌ Kein onlyRole Modifier gefunden!")
            else:
                print("\n❌ recordInteraction Funktion nicht gefunden!")
                
            # Zeige relevanten Code-Ausschnitt
            print("\n" + "=" * 80)
            print("📄 RELEVANTER CODE:")
            print("=" * 80)
            
            # Zeige die ersten 100 Zeilen des Contracts
            lines = source_code.split('\n')
            for i, line in enumerate(lines[:100], 1):
                if 'ROLE' in line or 'recordInteraction' in line:
                    print(f"{i:3d} | {line}")
            
        else:
            print(f"❌ Hauptdatei nicht gefunden: {response.status_code}")
    else:
        print(f"❌ Sourcify nicht erreichbar: {response.status_code}")
        print("\n💡 ALTERNATIVE: Contract manuell auf BaseScan prüfen:")
        print(f"   https://basescan.org/address/{CONTRACT_ADDRESS}#code")
        
except Exception as e:
    print(f"❌ Fehler: {e}")
    print("\n💡 Fallback - Typische Role-Namen testen:")
    
    role_candidates = [
        "RECORDER_ROLE",
        "INTERACTION_RECORDER_ROLE", 
        "WRITER_ROLE",
        "OPERATOR_ROLE",
        "BACKEND_ROLE",
        "UPDATER_ROLE",
        "DEFAULT_ADMIN_ROLE"
    ]
    
    print("\n🎯 Diese Roles sollten geprüft werden:\n")
    for role in role_candidates:
        print(f"  • {role}")

print("\n" + "=" * 80)

