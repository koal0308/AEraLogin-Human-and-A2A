"""
VEra-Resonance — Alchemy Paymaster Service
© 2025 Karlheinz Beismann — VEra-Resonance Project
Licensed under the Apache License, Version 2.0

Enables gasless transactions through Alchemy's Paymaster (ERC-4337 Account Abstraction).
This allows users to interact with blockchain without needing ETH for gas fees.

Architecture:
1. User signs UserOperation (not regular transaction)
2. Backend bundles with Paymaster signature
3. Bundler submits to EntryPoint contract
4. Gas fees sponsored by Paymaster Policy
"""

import os
import requests
from typing import Dict, Any, Optional, Tuple
from web3 import Web3
from eth_account import Account
from dotenv import load_dotenv
from logger import setup_logger

# Load environment variables
load_dotenv()

logger = setup_logger(__name__)


class PaymasterService:
    """Service for Alchemy Paymaster gasless transactions"""
    
    def __init__(self):
        """Initialize Paymaster service with Alchemy configuration"""
        # Load from environment
        self.policy_id = os.getenv("Policy_ID")
        self.policy_api_key = os.getenv("Policy_API_key")
        self.rpc_url = os.getenv("BASE_ALCHEMY_API_URL") or os.getenv("BASE_RPC_URL", "https://mainnet.base.org")
        self.chain_id = int(os.getenv("BASE_NETWORK_CHAIN_ID", "8453"))
        
        # Alchemy Bundler & Paymaster URLs for BASE Mainnet
        # Format: https://base-mainnet.g.alchemy.com/v2/<API_KEY>
        alchemy_api_key = self._extract_alchemy_key(self.rpc_url)
        
        if not alchemy_api_key:
            logger.warning("⚠️ Could not extract Alchemy API key from RPC URL")
            logger.warning("⚠️ Paymaster requires Alchemy RPC endpoint")
            self.enabled = False
            return
        
        self.bundler_url = f"https://base-mainnet.g.alchemy.com/v2/{alchemy_api_key}"
        self.paymaster_url = self.bundler_url  # Same endpoint for Paymaster
        
        if not self.policy_id or not self.policy_api_key:
            logger.warning("⚠️ Paymaster Policy ID or API Key not configured")
            logger.warning("⚠️ Set Policy_ID and Policy_API_key in .env for gasless transactions")
            self.enabled = False
        else:
            self.enabled = True
            logger.info(f"✅ Paymaster Service initialized")
            logger.info(f"   Policy ID: {self.policy_id}")
            logger.info(f"   Chain: BASE Mainnet (8453)")
            logger.info(f"   Status: {'Enabled' if self.enabled else 'Disabled'}")
    
    def _extract_alchemy_key(self, url: str) -> Optional[str]:
        """Extract Alchemy API key from RPC URL"""
        try:
            # Format: https://base-mainnet.g.alchemy.com/v2/KEY
            if "alchemy.com" in url:
                parts = url.split("/v2/")
                if len(parts) == 2:
                    return parts[1].split("?")[0]  # Remove query params if any
            return None
        except Exception as e:
            logger.error(f"Error extracting Alchemy key: {e}")
            return None
    
    async def sponsor_user_operation(
        self,
        user_operation: Dict[str, Any]
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Request Paymaster sponsorship for a UserOperation
        
        Args:
            user_operation: ERC-4337 UserOperation dict
            
        Returns:
            (success, response_data)
            - If success: response contains paymasterAndData field
            - If failure: response contains error message
        """
        if not self.enabled:
            return False, {"error": "Paymaster not configured"}
        
        try:
            # Alchemy Paymaster RPC Request
            # Method: alchemy_requestPaymasterAndData
            payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "alchemy_requestPaymasterAndData",
                "params": [
                    {
                        **user_operation,
                        "policyId": self.policy_id,
                    }
                ]
            }
            
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.policy_api_key}"
            }
            
            logger.info(f"🔄 Requesting Paymaster sponsorship...")
            logger.debug(f"   UserOp sender: {user_operation.get('sender', 'N/A')}")
            logger.debug(f"   Policy ID: {self.policy_id}")
            
            response = requests.post(
                self.paymaster_url,
                json=payload,
                headers=headers,
                timeout=10
            )
            
            if response.status_code != 200:
                logger.error(f"❌ Paymaster request failed: HTTP {response.status_code}")
                return False, {"error": f"HTTP {response.status_code}: {response.text}"}
            
            data = response.json()
            
            if "error" in data:
                error_msg = data["error"].get("message", str(data["error"]))
                logger.error(f"❌ Paymaster error: {error_msg}")
                return False, {"error": error_msg}
            
            if "result" not in data:
                logger.error(f"❌ Unexpected Paymaster response: {data}")
                return False, {"error": "Invalid response from Paymaster"}
            
            # Extract Paymaster signature data
            result = data["result"]
            paymaster_and_data = result.get("paymasterAndData")
            
            if not paymaster_and_data:
                logger.error(f"❌ No paymasterAndData in response")
                return False, {"error": "Missing paymasterAndData"}
            
            logger.info(f"✅ Paymaster sponsorship approved!")
            logger.debug(f"   PaymasterAndData: {paymaster_and_data[:20]}...")
            
            return True, {
                "paymasterAndData": paymaster_and_data,
                "sponsored": True
            }
            
        except requests.exceptions.Timeout:
            logger.error(f"❌ Paymaster request timeout")
            return False, {"error": "Request timeout"}
        except Exception as e:
            logger.error(f"❌ Paymaster service error: {e}")
            return False, {"error": str(e)}
    
    async def send_sponsored_transaction(
        self,
        contract_address: str,
        function_call: str,
        user_address: str,
        value: int = 0
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Build and send a gasless transaction using Paymaster
        
        Args:
            contract_address: Target smart contract
            function_call: Encoded function call data
            user_address: User's wallet address (sender)
            value: ETH value to send (usually 0)
            
        Returns:
            (success, tx_data) with UserOp hash and status
        """
        if not self.enabled:
            return False, {"error": "Paymaster not enabled"}
        
        try:
            logger.info(f"🔄 Building gasless transaction...")
            logger.info(f"   Contract: {contract_address}")
            logger.info(f"   User: {user_address}")
            
            # Step 1: Build UserOperation
            # This is simplified - in production you'd use a Smart Account factory
            user_op = {
                "sender": user_address,
                "nonce": "0x0",  # Would fetch from EntryPoint
                "initCode": "0x",  # Empty if account exists
                "callData": function_call,
                "callGasLimit": "0x55730",  # ~350k gas
                "verificationGasLimit": "0x55730",
                "preVerificationGas": "0xc350",  # ~50k gas
                "maxFeePerGas": "0x59682f00",  # 1.5 gwei
                "maxPriorityFeePerGas": "0x59682f00",
                "paymasterAndData": "0x",  # Will be filled by Paymaster
                "signature": "0x"  # Will be filled by user
            }
            
            # Step 2: Request Paymaster sponsorship
            success, sponsor_data = await self.sponsor_user_operation(user_op)
            
            if not success:
                return False, sponsor_data
            
            # Step 3: Update UserOp with Paymaster data
            user_op["paymasterAndData"] = sponsor_data["paymasterAndData"]
            
            logger.info(f"✅ Gasless transaction prepared")
            logger.info(f"   Gas sponsored by Paymaster")
            logger.info(f"   User signature required to complete")
            
            return True, {
                "userOp": user_op,
                "sponsored": True,
                "requires_signature": True,
                "message": "User must sign UserOperation to complete transaction"
            }
            
        except Exception as e:
            logger.error(f"❌ Error building sponsored transaction: {e}")
            return False, {"error": str(e)}
    
    def is_enabled(self) -> bool:
        """Check if Paymaster is configured and enabled"""
        return self.enabled
    
    def get_policy_limits(self) -> Dict[str, Any]:
        """Get current Paymaster policy configuration"""
        if not self.enabled:
            return {"enabled": False}
        
        return {
            "enabled": True,
            "policy_id": self.policy_id,
            "chain_id": self.chain_id,
            "chain_name": "BASE Mainnet",
            "note": "Check Alchemy Dashboard for usage limits and spend"
        }


# Global instance
paymaster_service = PaymasterService()


# Example usage function
async def example_mint_nft_gasless(user_address: str):
    """Example: Mint NFT without user paying gas"""
    from web3_service import web3_service
    
    # Get contract and encode function call
    mint_function = web3_service.identity_nft.functions.mintIdentity(user_address)
    call_data = mint_function._encode_transaction_data()
    
    # Build gasless transaction
    success, result = await paymaster_service.send_sponsored_transaction(
        contract_address=web3_service.identity_nft_address,
        function_call=call_data,
        user_address=user_address
    )
    
    if success:
        logger.info("✅ Gasless NFT mint prepared!")
        logger.info(f"   User must sign: {result['requires_signature']}")
        return result
    else:
        logger.error(f"❌ Gasless mint failed: {result.get('error')}")
        return None


if __name__ == "__main__":
    # Test Paymaster configuration
    print("\n" + "="*60)
    print("Alchemy Paymaster Service - Configuration Test")
    print("="*60 + "\n")
    
    service = PaymasterService()
    
    if service.is_enabled():
        print("✅ Paymaster is ENABLED\n")
        limits = service.get_policy_limits()
        print(f"Policy ID: {limits['policy_id']}")
        print(f"Chain: {limits['chain_name']} ({limits['chain_id']})")
        print(f"\n{limits['note']}")
    else:
        print("❌ Paymaster is DISABLED\n")
        print("To enable:")
        print("1. Add Policy_ID to .env")
        print("2. Add Policy_API_key to .env")
        print("3. Ensure BASE_ALCHEMY_API_URL uses Alchemy")
    
    print("\n" + "="*60 + "\n")
