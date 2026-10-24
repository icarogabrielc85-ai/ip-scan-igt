@echo off
chcp 65001 >nul
title IP Scan IGT - Instalador de Dependências Windows
cd /d "%~dp0"

echo ======================================================================
echo          IP SCAN IGT - INSTALADOR & VERIFICADOR WINDOWS
echo ======================================================================
echo.

python --version >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERRO] O Python nao esta instalado ou nao esta no PATH do Windows!
    echo.
    echo Baixe e instale o Python oficial marcando [X] Add python.exe to PATH:
    echo https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)

echo [*] Python detectado com sucesso.
echo [*] Instalando/atualizando dependencias Python (PyQt5, psutil)...
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

echo.
echo [*] Verificando reprodutores de video e utilitarios recomendados...
where ffplay >nul 2>nul
if %ERRORLEVEL% neq 0 (
    where vlc >nul 2>nul
    if %ERRORLEVEL% neq 0 (
        echo [!] Nem VLC nem FFplay foram detectados no PATH.
        echo [*] Deseja que o Windows instale o VLC Media Player via winget?
        choice /C SN /M "Instalar VLC agora (Recomendado para cameras RTSP)?"
        if errorlevel 1 if not errorlevel 2 (
            winget install VideoLAN.VLC
        )
    )
)

echo.
echo ======================================================================
echo [OK] Verificacao concluida! O sistema esta pronto para o IP Scan IGT.
echo ======================================================================
echo.
pause
