@echo off
chcp 65001 >nul
title Compilador IP Scan IGT para Windows
echo ======================================================================
echo           IP SCAN IGT - COMPILADOR AUTOMATICO PARA WINDOWS
echo ======================================================================
echo.

where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERRO] Python nao foi encontrado no sistema!
    echo Por favor, instale o Python 3.10 ou superior marcando a opcao "Add Python to PATH".
    echo Download oficial: https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)

echo [*] Python detectado com sucesso.
echo [*] Instalando/atualizando dependencias necessarias (PyQt5 e PyInstaller)...
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
if %ERRORLEVEL% neq 0 (
    echo.
    echo [ERRO] Falha ao instalar dependencias do requirements.txt.
    echo Verifique sua conexao com a internet ou permissoes do Python.
    echo.
    pause
    exit /b 1
)

echo.
echo [*] Iniciando empacotamento do executavel IPScanIGT.exe...
python -m PyInstaller --clean ipscan_windows.spec
if %ERRORLEVEL% neq 0 (
    echo.
    echo [ERRO] Ocorreu uma falha durante o processo do PyInstaller!
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
