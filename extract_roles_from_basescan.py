"""
🔍 Extrahiere Roles aus BaseScan HTML
"""

import re
import subprocess

CONTRACT_ADDRESS = "0xE2d5B85E4A9B0820c59658607C03bC90ba63b7b9"

print("=" * 80)
print("🔍 REGISTRY CONTRACT - ROLE ANALYSE (BaseScan HTML)")
print("=" * 80)

# Hole HTML von BaseScan Code Tab
url = f"https://basescan.org/address/{CONTRACT_ADDRESS}#code"
print(f"\n⏳ Lade Contract-Seite von BaseScan...")

try:
    result = subprocess.run(
        ['curl', '-s', url],
        capture_output=True,
        text=True,
        timeout=30
    )
    
    html = result.stdout
    print(f"✅ HTML geladen ({len(html)} Zeichen)")
    
    # Suche nach Solidity Source Code im HTML
    # BaseScan hat den Source Code in einem <pre> Tag oder als JS Variable
    
    # Methode 1: Suche nach "bytes32 public constant" im HTML
    role_pattern = r'bytes32\s+public\s+constant\s+(\w+)\s*=\s*keccak256\([\'"]([^\'"]+)[\'"]\);'
    roles = re.findall(role_pattern, html)
    
    if roles:
        print(f"\n✅ Gefunden: {len(roles)} Role-Definitionen im HTML\n")
        print("=" * 80)
        print("📝 ROLE DEFINITIONEN:")
        print("=" * 80 + "\n")
        
        for role_name, role_string in roles:
            print(f"  🔑 {role_name}")
            print(f"     └─ keccak256(\"{role_string}\")")
            print()
    else:
        print("\n⚠️  Keine Roles im HTML gefunden - versuche alternative Patterns...")
        
        # Alternative Pattern ohne Anführungszeichen
        alt_pattern = r'bytes32\s+(?:public\s+)?constant\s+(\w+ROLE)'
        alt_roles = re.findall(alt_pattern, html)
        
        if alt_roles:
            print(f"\n✅ Gefunden: {len(alt_roles)} Role-Namen\n")
            for role in set(alt_roles):
                print(f"  • {role}")
        else:
            print("\n❌ Keine Roles gefunden!")
    
    # Suche nach recordInteraction Funktion und Modifier
    print("\n" + "=" * 80)
    print("🔍 RECORD INTERACTION FUNKTION:")
    print("=" * 80)
    
    # Suche nach der Funktion im HTML
    func_patterns = [
        r'function\s+recordInteraction\s*\([^)]+\)\s+([^{]+)\s*\{',
        r'recordInteraction[^{]*onlyRole\(([^\)]+)\)',
    ]
    
    found_modifier = False
    for pattern in func_patterns:
        matches = re.findall(pattern, html, re.MULTILINE | re.DOTALL)
        if matches:
            print(f"\n✅ Gefunden: {matches[0]}")
            found_modifier = True
            break
    
    if not found_modifier:
        print("\n⚠️  Modifier nicht im HTML gefunden")
    
    # Fallback: Zeige alle ROLE-bezogenen Zeilen
    print("\n" + "=" * 80)
    print("📄 ALLE ROLE-ERWÄHNUNGEN IM HTML:")
    print("=" * 80 + "\n")
    
    role_lines = [line for line in html.split('\n') if 'ROLE' in line and 'bytes32' in line]
    for line in role_lines[:10]:  # Erste 10 Zeilen
        clean_line = re.sub(r'<[^>]+>', '', line)  # Remove HTML tags
        clean_line = clean_line.strip()
        if len(clean_line) > 20 and len(clean_line) < 200:
            print(f"  {clean_line[:150]}")
    
except subprocess.TimeoutExpired:
    print("❌ Timeout beim Laden der Seite")
except Exception as e:
    print(f"❌ Fehler: {e}")

print("\n" + "=" * 80)
print("💡 NÄCHSTER SCHRITT:")
print("=" * 80)
print("""
Wenn keine Roles gefunden wurden, müssen wir:
1. Contract Source direkt auf BaseScan lesen (manuell)
2. Oder alle gängigen Role-Namen durchprobieren
""")
print("=" * 80)

