@echo off
chcp 65001 >nul
title Compilador IP Scan IGT para Windows
cd /d "%~dp0"

echo ======================================================================
echo           IP SCAN IGT - COMPILADOR AUTOMATICO PARA WINDOWS
echo ======================================================================
echo.

python --version >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo ======================================================================
    echo [ERRO] O Python nao esta instalado ou nao esta no PATH do Windows!
    echo ======================================================================
    echo.
    echo 1. Baixe o instalador oficial do Python (versao 3.10 ou mais recente):
    echo    https://www.python.org/downloads/
    echo.
    echo 2. IMPORTANTE: Na primeira tela do instalador, marque a caixa:
    echo    "[X] Add python.exe to PATH"
    echo.
    echo Depois de instalar, feche este terminal e tente novamente.
    echo.
    pause
    exit /b 1
)

echo [*] Python detectado com sucesso.
echo [*] Verificando se PyQt5 e PyInstaller estao instalados no sistema...

python -c "import PyQt5.QtCore, PyQt5.QtWidgets, PyInstaller" >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo.
    echo [*] PyQt5 ou PyInstaller ausentes.
    echo [*] Instalando dependencias automaticamente via pip...
    echo [*] Aguarde alguns instantes...
    echo.
    python -m pip install --upgrade pip
    python -m pip install -r requirements.txt
    if %ERRORLEVEL% neq 0 (
        echo.
        echo ======================================================================
        echo [ERRO] Falha ao instalar dependencias do requirements.txt!
        echo ======================================================================
        echo Verifique sua conexao com a internet ou execute este arquivo como Administrador.
        echo.
        pause
        exit /b 1
    )
    echo.
    echo [OK] Dependencias instaladas com sucesso!
) else (
    echo [OK] PyQt5 e PyInstaller ja estao instalados e prontos!
)

echo.
echo [*] Iniciando empacotamento do executavel IPScanIGT.exe...
python -m PyInstaller --clean ipscan_windows.spec
if %ERRORLEVEL% neq 0 (
    echo.
    echo ======================================================================
    echo [ERRO] Ocorreu uma falha durante o processo do PyInstaller!
    echo ======================================================================
    echo.
    pause
    exit /b 1
)

echo.
if exist "dist\IPScanIGT.exe" (
    echo ======================================================================
    echo [SUCESSO] Compilacao concluida com exito!
    echo Executavel gerado em: dist\IPScanIGT.exe
    echo ======================================================================
    echo.
    echo Abrindo a pasta dist...
    explorer dist
) else (
    echo [AVISO] O processo finalizou mas dist\IPScanIGT.exe nao foi localizado.
)

echo.
pause
