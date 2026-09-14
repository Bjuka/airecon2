@echo off
title airecon2 lab
cd /d D:\projects\airecon2\lab
echo Starting pentest lab container (first build takes a few minutes)...
docker compose up -d --build
docker ps --filter name=airecon2-lab
echo.
echo Lab ready. Enter it with:  docker exec -it airecon2-lab bash
echo Attach USB wifi (admin prompt): usbipd wsl attach --busid ^<BUSID^>
pause
