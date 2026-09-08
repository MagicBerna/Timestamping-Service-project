#!/usr/bin/env bash
# build.sh — Configurazione e compilazione automatizzata del progetto TSS
# Progetto Foundations of Cybersecurity (FoC) 2025-26

set -euo pipefail

BUILD_DIR="build"
JOBS=$(nproc 2>/dev/null || echo 4)

echo "=============================================="
echo " TSS Build Automation — FoC Project 2025-26"
echo "=============================================="
echo "[*] Core CPU rilevati per la compilazione: $JOBS"
echo ""

# 1. Configurazione CMake
echo "[1/2] Configurazione progetto con CMake..."
cmake -B "$BUILD_DIR" \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
      .

echo ""
# 2. Compilazione parallela dei target
echo "[2/2] Compilazione di tutti i target in parallelo ($JOBS job)..."
cmake --build "$BUILD_DIR" --parallel "$JOBS"

echo ""
echo "=============================================="
echo " Build completata con successo!"
echo "=============================================="
echo ""
echo "Eseguibili generati in $BUILD_DIR/:"
if [ -f "$BUILD_DIR/tss_server" ]; then
    echo "  [OK] $BUILD_DIR/tss_server   (Timestamping Server)"
fi
if [ -f "$BUILD_DIR/tss_client" ]; then
    echo "  [OK] $BUILD_DIR/tss_client   (Client Interattivo)"
fi
if [ -f "$BUILD_DIR/tss_verify" ]; then
    echo "  [OK] $BUILD_DIR/tss_verify   (Verificatore Offline dei Token)"
fi
if [ -f "$BUILD_DIR/test_common" ]; then
    echo "  [OK] $BUILD_DIR/test_common  (Unit Test Modulo Comune)"
fi

echo ""
echo "Guida rapida per l'esecuzione:"
echo "  1. Genera certificati e utenti (se non gia' presenti):"
echo "     ./keygen.sh"
echo ""
echo "  2. Avvia il server in un terminale:"
echo "     ./$BUILD_DIR/tss_server"
echo ""
echo "  3. In un altro terminale, avvia il client (es. alice):"
echo "     ./$BUILD_DIR/tss_client --user alice --pass alice_password"
echo ""
echo "  4. Verifica offline un token ricevuto:"
echo "     ./$BUILD_DIR/tss_verify --token token_<hash>.json"
echo ""
