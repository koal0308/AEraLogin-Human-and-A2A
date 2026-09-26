import asyncio
from web3_service import Web3Service

async def test():
    service = Web3Service()
    
    print("🔍 Testing Web3Service.get_blockchain_score()")
    print("=" * 70)
    
    # Test-Adresse
    address = "0x9de3772a1b2e958561d8371ee34364dcd90967ba"
    
    print(f"Address: {address}")
    print(f"Contract initialized: {service.resonance_score is not None}")
    
    if service.resonance_score:
        print(f"Contract address: {service.resonance_score.address}")
    
    score = await service.get_blockchain_score(address)
    print(f"\nBlockchain Score: {score}")
    print(f"Expected: 55")
    print(f"Match: {'✅' if score == 55 else '❌'}")

asyncio.run(test())
