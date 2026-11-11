#!/usr/bin/env bash
# start_5gc.sh — Starts free5GC WebConsole & services for the 5G NOC ReAct Agent

set -e

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Checking free5GC Services ==="

# Check MongoDB
if ! nc -z 127.0.0.1 27017 2>/dev/null; then
    echo "[!] MongoDB is not running on port 27017."
    echo "    Start it with: sudo systemctl start mongodb"
else
    echo "[✓] MongoDB is running on port 27017."
fi

# Check WebConsole
if ! nc -z 127.0.0.1 5000 2>/dev/null; then
    echo "[*] Starting free5GC WebConsole backend on port 5000..."
    cd "${BASE_DIR}/free5gc/webconsole"
    if [ ! -f "bin/webconsole" ]; then
        echo "[*] Building webconsole binary..."
        go build -o bin/webconsole server.go
    fi
    nohup ./bin/webconsole -c ../config/webuicfg.yaml > /tmp/webconsole.log 2>&1 &
    sleep 2
    echo "[✓] free5GC WebConsole started (PID $!)."
else
    echo "[✓] free5GC WebConsole is already running on port 5000."
fi

echo "=== All services ready for ReAct Agent ==="
