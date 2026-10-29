@echo off
chcp 65001 > nul
title Portal de Resultados e Indicadores · SUBINOVA

echo =====================================================================
echo   INICIANDO PORTAL DE RESULTADOS · SUBINOVA / SEDE-MG
echo =====================================================================
echo.
echo   [1/2] Abrindo navegador em http://localhost:8080 ...
start http://localhost:8080
echo.
echo   [2/2] Iniciando servidor local com suporte a streaming de vídeo...
echo   Senha de acesso configurada: @3293
echo.
echo   Para encerrar a execução, feche esta janela ou pressione Ctrl+C.
echo =====================================================================
echo.

python "%~dp0server.py"

pause
