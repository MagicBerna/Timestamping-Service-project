#!/bin/bash
# Script per la generazione delle chiavi crittografiche e del database utenti.
# Progetto Foundations of Cybersecurity (FoC)

set -e

CERTS_DIR="certs"
mkdir -p "$CERTS_DIR"

echo "=============================================="
echo " TSS Key Generation — FoC Project 2025-26"
echo "=============================================="

# 1. Chiavi di connessione per TLS (privKc / pubKc)
echo ""
echo "[1/4] Generating connection private key (P-256)..."
openssl ecparam -name prime256v1 -genkey -noout -out "$CERTS_DIR/server_conn.key"
chmod 600 "$CERTS_DIR/server_conn.key"
echo "      -> $CERTS_DIR/server_conn.key"

echo "[2/4] Generating self-signed TLS certificate (pubKc, 1 year)..."
openssl req -new -x509 \
    -key "$CERTS_DIR/server_conn.key" \
    -out "$CERTS_DIR/server_conn.crt" \
    -days 365 \
    -subj "/CN=localhost/O=FoC-TSA/C=IT/ST=Italy/L=University" \
    -extensions v3_ca \
    -addext "subjectAltName=IP:127.0.0.1,DNS:localhost"
echo "      -> $CERTS_DIR/server_conn.crt"

# 2. Chiavi per la firma dei timestamp (privKts / pubKts)
echo ""
echo "[3/4] Generating timestamping private key (P-384)..."
openssl ecparam -name secp384r1 -genkey -noout -out "$CERTS_DIR/server_ts.key"
chmod 600 "$CERTS_DIR/server_ts.key"
echo "      -> $CERTS_DIR/server_ts.key"

echo "[4/4] Extracting timestamping public key (pubKts)..."
openssl ec -in "$CERTS_DIR/server_ts.key" -pubout -out "$CERTS_DIR/server_ts.pub"
echo "      -> $CERTS_DIR/server_ts.pub"

# 3. Creazione database utenti iniziale
echo ""
echo "[+] Generating users.json with demo credentials..."

gen_user() {
    user="$1"
    pass="$2"
    nc="$3"
    nr="$4"

    salt=$(openssl rand -hex 16)
    hash=$(printf '%s%s' "$pass" "$salt" | openssl dgst -sha256 -hex | awk '{print $2}')

    cat << EOF
    "$user": {
      "salt": "$salt",
      "password_hash": "$hash",
      "nc": $nc,
      "nr": $nr
    }
EOF
}

ALICE=$(gen_user "alice" "alice_password" 0 100)
BOB=$(gen_user "bob" "bob_password" 0 50)
CHARLIE=$(gen_user "charlie" "charlie_password" 10 0)

cat > users.json << JSON
{
  "users": {
    $ALICE,
    $BOB,
    $CHARLIE
  }
}
JSON
echo "      -> users.json"

# Riepilogo finale
echo ""
echo "=============================================="
echo " Setup completato con successo!"
echo "=============================================="
echo ""
echo "File generati in $CERTS_DIR/:"
ls -lh "$CERTS_DIR/"
echo ""
echo "Credenziali demo create in users.json:"
echo "  - alice   / alice_password   (nc: 0,  nr: 100) -> Test operazioni standard"
echo "  - bob     / bob_password     (nc: 0,  nr: 50)  -> Test client concorrente"
echo "  - charlie / charlie_password (nc: 10, nr: 0)   -> Test saldo esaurito (fallimento)"
echo ""
echo "Comandi utili per ispezionare i certificati:"
echo "  openssl x509 -in $CERTS_DIR/server_conn.crt -text -noout"
echo "  openssl ec -in $CERTS_DIR/server_ts.key -text -noout"
echo ""
