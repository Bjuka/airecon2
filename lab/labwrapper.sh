#!/bin/bash
# keep the lab container alive; tools are invoked via docker exec
echo "[airecon2-lab] ready - tools: aircrack-ng nmap sqlmap hydra tshark wifite ..."
exec tail -f /dev/null
