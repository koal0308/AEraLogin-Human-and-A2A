from web3 import Web3
import sys
import os

rpc_url = os.getenv("BASE_RPC_URL", "https://mainnet.base.org")
wallet = os.getenv("TEST_WALLET", "0xed1a95ab5b794Dc20964693FBCc60A3DFb5A22C5")

print(f"🔄 Verbinde zu BASE Mainnet...")
w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={'timeout': 10}))

try:
    connected = w3.is_connected()
    print(f"🌐 Verbindung: {'✅ Erfolgreich' if connected else '❌ Fehlgeschlagen'}")
    
    if not connected:
        sys.exit(1)
    
    balance_wei = w3.eth.get_balance(wallet)
    balance_eth = float(w3.from_wei(balance_wei, 'ether'))
    
    print(f"\n💰 WALLET BALANCE:")
    print(f"   Adresse: {wallet}")
    print(f"   Balance: {balance_eth:.6f} ETH")
    print(f"   Balance: {balance_wei} Wei")
    
    if balance_eth > 0:
        print(f"\n✅ WALLET IST GEFUNDET!")
        print(f"🎨 NFT-Minting ist jetzt möglich!")
    else:
        print(f"\n❌ WALLET IST LEER")
        print(f"⚠️  Bitte Funds hinzufügen!")
        
except Exception as e:
    print(f"\n❌ FEHLER: {e}")
    sys.exit(1)
