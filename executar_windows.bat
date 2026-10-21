@echo off
chcp 65001 >nul
title IP Scan IGT

where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo ======================================================================
    echo [ERRO] Python nao foi encontrado no sistema!
    echo ======================================================================
    echo Por favor, instale o Python marcando a opcao "Add Python to PATH":
    echo https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)

python -c "import PyQt5" >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [*] PyQt5 nao foi detectado.
    echo [*] Instalando PyQt5 automaticamente via pip...
    python -m pip install --upgrade pip
    python -m pip install PyQt5>=5.15.9
    if %ERRORLEVEL% neq 0 (
        echo [ERRO] Falha ao instalar o PyQt5.
        pause
        exit /b 1
    )
    echo [OK] PyQt5 instalado com sucesso!
)

echo [*] Iniciando IP Scan IGT...
start "" pythonw main.py 2>nul || python main.py
