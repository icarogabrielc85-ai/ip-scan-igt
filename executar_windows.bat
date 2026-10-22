@echo off
chcp 65001 >nul
title IP Scan IGT - Inicializador Windows
cd /d "%~dp0"

echo ======================================================================
echo                      IP SCAN IGT (WINDOWS)
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
echo [*] Verificando biblioteca visual PyQt5...

python -c "import PyQt5.QtCore, PyQt5.QtWidgets" >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo.
    echo [*] PyQt5 ausente ou incompleto no seu Windows.
    echo [*] Baixando e instalando PyQt5 automaticamente via pip...
    echo [*] Isso pode levar cerca de 1 a 2 minutos. Aguarde...
    echo.
    python -m pip install --upgrade pip
    python -m pip install PyQt5>=5.15.9
    if %ERRORLEVEL% neq 0 (
        echo.
        echo ======================================================================
        echo [ERRO] Falha ao instalar o PyQt5 via pip!
        echo ======================================================================
        echo Verifique sua conexao com a internet ou tente rodar no Prompt de Comando:
        echo pip install PyQt5
        echo.
        pause
        exit /b 1
    )
    echo.
    echo [OK] PyQt5 instalado com sucesso!
    echo.
) else (
    echo [OK] PyQt5 ja esta instalado e pronto para uso!
)

echo.
echo [*] Iniciando IP Scan IGT...
echo.

python main.py
if %ERRORLEVEL% neq 0 (
    echo.
    echo ======================================================================
    echo [ERRO] O programa finalizou com erro!
    echo Veja a mensagem acima para identificar o problema.
    echo ======================================================================
    echo.
    pause
)
