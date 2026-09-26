#!/bin/bash
echo "🧪 Testing OAuth Smart Wallet Support"
echo "======================================"
echo ""
echo "📱 Demo App URL: https://aera-miniapp-demo.vercel.app/app"
echo ""
echo "🔍 Watching OAuth logs (Press Ctrl+C to stop)..."
echo ""
tail -f /var/log/aeralogin/server.log | grep --line-buffered --color=always -E "OAUTH|EIP-1271|Smart|signature"
