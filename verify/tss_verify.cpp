#include "common.hpp"

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstring>
#include <ctime>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

using namespace std;
using json = nlohmann::json;

struct TokenBundle {
    string hash_hex;
    uint64_t time_val;
    string signature_hex;
};

// Lettura e parsing del token JSON
TokenBundle load_token_file(const string& path) {
    ifstream file(path);
    if (!file.is_open()) {
        throw runtime_error("Impossibile aprire il file del token: " + path);
    }

    json j;
    file >> j;

    if (!j.contains("hash") || !j.contains("time") || !j.contains("signature")) {
        throw runtime_error("Formato token non valido (campi mancanti)");
    }

    TokenBundle bundle;
    bundle.hash_hex = j["hash"].get<string>();
    bundle.time_val = j["time"].get<uint64_t>();
    bundle.signature_hex = j["signature"].get<string>();

    return bundle;
}

// Verifica della firma ECDSA con chiave pubblica pubKts
bool verify_timestamp_bundle(const TokenBundle& tok, const string& pubkts_path) {
    // Caricamento della chiave pubblica
    FILE* kf = fopen(pubkts_path.c_str(), "r");
    if (!kf) {
        throw runtime_error("Impossibile aprire la chiave pubblica: " + pubkts_path);
    }

    EVP_PKEY* pubkey = PEM_read_PUBKEY(kf, nullptr, nullptr, nullptr);
    fclose(kf);

    if (!pubkey) {
        throw runtime_error("Errore nel parsing della chiave pubblica");
    }

    // Decodifica esadecimale della firma
    vector<uint8_t> sig_bytes = tss::hex_to_bytes(tok.signature_hex);

    // Ricostruzione del payload (hash || time a 40 byte)
    vector<uint8_t> payload = tss::build_timestamp_payload(tok.hash_hex, tok.time_val);

    // Verifica con SHA-384
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pubkey);
        throw runtime_error("Errore allocazione contesto digest");
    }

    bool is_valid = false;
    if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha384(), nullptr, pubkey) == 1 &&
        EVP_DigestVerifyUpdate(ctx, payload.data(), payload.size()) == 1) {
        int rc = EVP_DigestVerifyFinal(ctx, sig_bytes.data(), sig_bytes.size());
        if (rc == 1) {
            is_valid = true;
        }
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pubkey);

    return is_valid;
}

// Funzione per stampare le informazioni del token
void print_token_info(const TokenBundle& tok, const string& file_checked = "") {
    cout << "--- Informazioni Token Timestamp ---" << endl;
    cout << "Hash documento : " << tok.hash_hex << endl;
    cout << "Data UTC       : " << tss::format_epoch_time(tok.time_val) << endl;
    cout << "Unix Epoch     : " << tok.time_val << endl;
    cout << "Firma (hex)    : " << tok.signature_hex.substr(0, 32) << "..." << endl;
    if (!file_checked.empty()) {
        cout << "File verificato: " << file_checked << endl;
    }
    cout << "------------------------------------" << endl;
}

// Funzione di appoggio che mostra a video qual ora l'utente si dimentichi di eseguire tss_verify senza il token
void usage(const char* prog_name) {
    cout << "Uso: " << prog_name << " [OPZIONI]\n\n"
         << "Opzioni:\n"
         << "  --token <file.json>    File contenente il token di timestamp\n"
         << "  --file <doc>           (Opzionale) File del documento da verificare\n"
         << "  --pubkts <pubkey.pub>  Chiave pubblica del server (default: certs/server_ts.pub)\n"
         << "  --hash <hex>           Hash SHA-256 da verificare manualmente\n"
         << "  --time <epoch>         Timestamp Unix\n"
         << "  --sig <hex>            Firma esadecimale\n"
         << "  --help                 Mostra questo messaggio\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    string token_file;
    string doc_file;
    string pubkts_path = tss::SERVER_TS_PUB;
    string hash_hex;
    string sig_hex;
    uint64_t time_val = 0;
    bool manual_args = false;

    for (int i = 1; i < argc; ++i) {
        string arg = argv[i];
        if (arg == "--token" && i + 1 < argc) {
            token_file = argv[++i];
        } else if (arg == "--file" && i + 1 < argc) {
            doc_file = argv[++i];
        } else if (arg == "--pubkts" && i + 1 < argc) {
            pubkts_path = argv[++i];
        } else if (arg == "--hash" && i + 1 < argc) {
            hash_hex = argv[++i];
            manual_args = true;
        } else if (arg == "--time" && i + 1 < argc) {
            time_val = stoull(argv[++i]);
            manual_args = true;
        } else if (arg == "--sig" && i + 1 < argc) {
            sig_hex = argv[++i];
            manual_args = true;
        } else if (arg == "--help" || arg == "-h") {
            usage(argv[0]);
            return 0;
        } else {
            cerr << "Opzione non valida: " << arg << endl;
            usage(argv[0]);
            return 1;
        }
    }

    TokenBundle token;
    try {
        if (!token_file.empty()) {
            token = load_token_file(token_file);
        } else if (manual_args) {
            if (hash_hex.empty() || sig_hex.empty() || time_val == 0) {
                cerr << "Errore: specificare tutti i parametri (--hash, --time, --sig)" << endl;
                return 1;
            }
            token.hash_hex = hash_hex;
            token.time_val = time_val;
            token.signature_hex = sig_hex;
        } else {
            usage(argv[0]);
            return 1;
        }
    } catch (const exception& e) {
        cerr << "Errore lettura token: " << e.what() << endl;
        return 1;
    }

    // Controllo opzionale dell'hash del file locale
    if (!doc_file.empty()) {
        try {
            string file_hash = tss::sha256_file(doc_file);
            if (file_hash != token.hash_hex) {
                cout << "[ERRORE] L'hash del file non corrisponde a quello del token!" << endl;
                cout << "  Hash file : " << file_hash << endl;
                cout << "  Hash token: " << token.hash_hex << endl;
                return 2;
            }
        } catch (const exception& e) {
            cerr << "Errore calcolo hash file: " << e.what() << endl;
            return 1;
        }
    }

    print_token_info(token, doc_file);

    try {
        bool ok = verify_timestamp_bundle(token, pubkts_path);
        if (ok) {
            cout << "[OK] Firma valida: il timestamp e' autentico e integro." << endl;
            return 0;
        } else {
            cout << "[ERRORE] Firma NON valida: token manomesso o chiave errata." << endl;
            return 2;
        }
    } catch (const exception& e) {
        cerr << "Errore durante la verifica: " << e.what() << endl;
        return 1;
    }
}
