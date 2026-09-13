/**
 * tss_client.cpp — Timestamping Service (TSS) Client
 * Progetto: Foundations of Cybersecurity (FoC)
 *
 * Funzionalita':
 * - Connessione su canale sicuro TLS 1.3 con verifica del certificato del server (pubKc)
 * - Autenticazione crittografica con username e password all'interno del canale TLS
 * - Scambio di nonce (nonce_c, nonce_s) per protezione anti-replay a livello di sessione
 * - Contatore di sequenza applicativo (seq) per validare la monotonicita' dei comandi
 * - Shell interattiva (REPL): timestamp <file|hex>, balance, verify <token.json>, help, quit
 * - Hashing locale dei file in streaming (Data Minimization Principle)
 * - Persistenza dei token di timestamp ricevuti su file JSON
 * - Modulo di verifica crittografica offline integrato (P-384 / SHA-384)
 */

#include "common.hpp"

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <ctime>
#include <csignal>
#include <stdexcept>
#include <sys/stat.h>

// POSIX Networking
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

// OpenSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/rand.h>

using namespace std;
using json = nlohmann::json;

// --- Utility: Verifica esistenza file su disco ---
static bool file_exists(const string& path) {
    struct stat buffer;
    return (stat(path.c_str(), &buffer) == 0);
}

// --- Salvataggio del Token di Timestamp su File JSON ---
static string save_timestamp_token(const json& resp) {
    if (!resp.contains("hash") || !resp.contains("time") || !resp.contains("signature")) {
        cerr << "[ERRORE] Struttura token non valida, impossibile salvare su file." << endl;
        return "";
    }

    string hash_str = resp["hash"].get<string>();
    string prefix = hash_str.substr(0, (hash_str.length() >= 16 ? 16 : hash_str.length()));
    string filename = "token_" + prefix + ".json";

    json token_json = {
        {"hash", resp["hash"].get<string>()},
        {"time", resp["time"].get<uint64_t>()},
        {"signature", resp["signature"].get<string>()}
    };

    ofstream f(filename);
    if (!f.is_open()) {
        cerr << "[ERRORE] Impossibile creare il file del token: " << filename << endl;
        return "";
    }

    f << token_json.dump(2) << endl;
    cout << "[+] Token salvato con successo su: " << filename << endl;
    return filename;
}

// --- Menu di Aiuto ---
static void print_help() {
    cout << "\n"
         << "+-------------------------------------------------------------------------+\n"
         << "| Comandi Disponibili nel Client TSS                                      |\n"
         << "+-------------------------------------------------------------------------+\n"
         << "| timestamp <file | hex>  : Richiede un timestamp per un file locale     |\n"
         << "|                           o per una stringa hash SHA-256 esadecimale    |\n"
         << "| balance                 : Interroga il saldo crediti (nc consumati, nr) |\n"
         << "| verify <token.json>     : Verifica offline la firma del token ricevuto  |\n"
         << "| help                    : Mostra questa guida ai comandi                |\n"
         << "| quit / exit             : Disconnette la sessione e chiude il client    |\n"
         << "+-------------------------------------------------------------------------+\n\n";
}

// --- Verifica Crittografica Offline del Token (P-384 / SHA-384) ---
static bool verify_token_file(const string& token_path, const string& pubkts_path) {
    ifstream tf(token_path);
    if (!tf.is_open()) {
        cerr << "[-] Impossibile aprire il file token: " << token_path << endl;
        return false;
    }

    json token;
    try {
        tf >> token;
    } catch (const exception& e) {
        cerr << "[-] Errore nel parsing JSON del token: " << e.what() << endl;
        return false;
    }

    if (!token.contains("hash") || !token.contains("time") || !token.contains("signature")) {
        cerr << "[-] Token non valido: campi richiesti mancanti ('hash', 'time', 'signature')" << endl;
        return false;
    }

    string hash_hex = token["hash"].get<string>();
    uint64_t time_val = token["time"].get<uint64_t>();
    string sig_hex = token["signature"].get<string>();

    // Caricamento chiave pubblica di timestamping (pubKts)
    FILE* kf = fopen(pubkts_path.c_str(), "r");
    if (!kf) {
        cerr << "[-] Impossibile aprire la chiave pubblica pubKts: " << pubkts_path << endl;
        return false;
    }

    EVP_PKEY* pubkey = PEM_read_PUBKEY(kf, nullptr, nullptr, nullptr);
    fclose(kf);

    if (!pubkey) {
        cerr << "[-] Errore nel caricamento della chiave pubblica OpenSSL." << endl;
        tss::print_openssl_errors("verify_token_file (PEM_read_PUBKEY)");
        return false;
    }

    // Decodifica byte della firma esadecimale DER
    vector<uint8_t> sig_bytes;
    try {
        sig_bytes = tss::hex_to_bytes(sig_hex);
    } catch (const exception& e) {
        cerr << "[-] Errore decodifica esadecimale della firma: " << e.what() << endl;
        EVP_PKEY_free(pubkey);
        return false;
    }

    // Ricostruzione deterministica del payload canonico (hash a 32 byte || time a 8 byte Big-Endian)
    vector<uint8_t> payload;
    try {
        payload = tss::build_timestamp_payload(hash_hex, time_val);
    } catch (const exception& e) {
        cerr << "[-] Errore costruzione payload per la verifica: " << e.what() << endl;
        EVP_PKEY_free(pubkey);
        return false;
    }

    // Verifica con algoritmo ECDSA / SHA-384
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pubkey);
        cerr << "[-] Errore allocazione contesto EVP_MD_CTX." << endl;
        return false;
    }

    bool is_valid = false;
    if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha384(), nullptr, pubkey) == 1 &&
        EVP_DigestVerifyUpdate(ctx, payload.data(), payload.size()) == 1) {
        int rc = EVP_DigestVerifyFinal(ctx, sig_bytes.data(), sig_bytes.size());
        if (rc == 1) {
            is_valid = true;
        } else if (rc < 0) {
            tss::print_openssl_errors("EVP_DigestVerifyFinal");
        }
    } else {
        tss::print_openssl_errors("EVP_DigestVerifyInit/Update");
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pubkey);
    return is_valid;
}

// --- Guida utilizzo CLI ---
static void usage(const char* prog_name) {
    cout << "Uso: " << prog_name << " [OPZIONI]\n\n"
         << "Opzioni:\n"
         << "  --host <host>          Indirizzo IP o hostname del server TSS (default: " << tss::SERVER_HOST << ")\n"
         << "  --port <porta>         Porta TCP del server (default: " << tss::SERVER_PORT << ")\n"
         << "  --crt <cert.crt>       Certificato TLS del server per pinning (default: " << tss::SERVER_CONN_CRT << ")\n"
         << "  --pubkts <pubkey.pub>  Chiave pubblica TSA per verifica token (default: " << tss::SERVER_TS_PUB << ")\n"
         << "  --user <username>      Nome utente per autenticazione (opzionale)\n"
         << "  --pass <password>      Password per autenticazione (opzionale)\n"
         << "  --help, -h             Mostra questo messaggio di aiuto\n";
}

int main(int argc, char* argv[]) {
    // Ignora SIGPIPE per evitare terminazione anomala del client su disconnessioni di rete
    signal(SIGPIPE, SIG_IGN);

    string server_host = tss::SERVER_HOST;
    int server_port = tss::SERVER_PORT;
    string conn_crt = tss::SERVER_CONN_CRT;
    string pubkts_path = tss::SERVER_TS_PUB;
    string cli_user;
    string cli_pass;

    // Parsing argomenti CLI
    for (int i = 1; i < argc; ++i) {
        string arg = argv[i];
        if (arg == "--host" && i + 1 < argc) {
            server_host = argv[++i];
        } else if (arg == "--port" && i + 1 < argc) {
            server_port = stoi(argv[++i]);
        } else if (arg == "--crt" && i + 1 < argc) {
            conn_crt = argv[++i];
        } else if (arg == "--pubkts" && i + 1 < argc) {
            pubkts_path = argv[++i];
        } else if (arg == "--user" && i + 1 < argc) {
            cli_user = argv[++i];
        } else if (arg == "--pass" && i + 1 < argc) {
            cli_pass = argv[++i];
        } else if (arg == "--help" || arg == "-h") {
            usage(argv[0]);
            return 0;
        } else {
            cerr << "Opzione non riconosciuta: " << arg << endl;
            usage(argv[0]);
            return 1;
        }
    }

    cout << "==================================================" << endl;
    cout << " TSS Client (Timestamping Service)" << endl;
    cout << "==================================================" << endl;
    cout << "Parametri di connessione:" << endl;
    cout << "  - Server Destinazione : " << server_host << ":" << server_port << endl;
    cout << "  - Certificato Pinning : " << conn_crt << endl;
    cout << "  - Chiave Pubblica TSA : " << pubkts_path << endl;
    cout << "--------------------------------------------------" << endl;

    // Verifica presenza del certificato per il pinning
    if (!file_exists(conn_crt)) {
        cerr << "[ERRORE] File certificato server non trovato: " << conn_crt << endl;
        cerr << "Suggerimento: Esegui ./keygen.sh prima di avviare il client." << endl;
        return 1;
    }

    // -------------------------------------------------------------
    // Setup TLS 1.3 Client e Connessione TCP
    // -------------------------------------------------------------
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ssl_ctx = SSL_CTX_new(method);
    if (!ssl_ctx) {
        cerr << "[ERRORE] Creazione contesto SSL client fallita." << endl;
        tss::print_openssl_errors("SSL_CTX_new");
        return 1;
    }

    // Forzatura TLS 1.3 come protocollo minimo
    if (SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION) != 1) {
        cerr << "[ERRORE] Impossibile impostare TLS 1.3 come versione minima." << endl;
        tss::print_openssl_errors("SSL_CTX_set_min_proto_version");
        SSL_CTX_free(ssl_ctx);
        return 1;
    }

    // Caricamento del certificato del server come CA fidata (Certificate Pinning)
    if (SSL_CTX_load_verify_locations(ssl_ctx, conn_crt.c_str(), nullptr) != 1) {
        cerr << "[ERRORE] Impossibile caricare il certificato server per il pinning: " << conn_crt << endl;
        tss::print_openssl_errors("SSL_CTX_load_verify_locations");
        SSL_CTX_free(ssl_ctx);
        return 1;
    }

    // Attivazione verifica obbligatoria del certificato del server
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_verify_depth(ssl_ctx, 1);

    // Risoluzione DNS e connessione socket TCP
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    string port_str = to_string(server_port);

    if (getaddrinfo(server_host.c_str(), port_str.c_str(), &hints, &res) != 0) {
        cerr << "[ERRORE] Risoluzione indirizzo fallita per: " << server_host << endl;
        SSL_CTX_free(ssl_ctx);
        return 1;
    }

    int sock_fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock_fd < 0) {
        perror("[ERRORE] Creazione socket fallita");
        freeaddrinfo(res);
        SSL_CTX_free(ssl_ctx);
        return 1;
    }

    if (connect(sock_fd, res->ai_addr, res->ai_addrlen) < 0) {
        perror("[ERRORE] Connessione TCP al server fallita");
        freeaddrinfo(res);
        close(sock_fd);
        SSL_CTX_free(ssl_ctx);
        return 1;
    }
    freeaddrinfo(res);

    // Associazione SSL al socket
    SSL* ssl = SSL_new(ssl_ctx);
    if (!ssl) {
        cerr << "[ERRORE] Creazione sessione SSL fallita." << endl;
        close(sock_fd);
        SSL_CTX_free(ssl_ctx);
        return 1;
    }
    SSL_set_fd(ssl, sock_fd);

    // Impostazione SNI (Server Name Indication)
    SSL_set_tlsext_host_name(ssl, server_host.c_str());

    // Handshake TLS lato client
    if (SSL_connect(ssl) != 1) {
        cerr << "[ERRORE] Handshake TLS con il server fallito." << endl;
        tss::print_openssl_errors("SSL_connect");
        SSL_free(ssl);
        close(sock_fd);
        SSL_CTX_free(ssl_ctx);
        return 1;
    }

    // Verifica del certificato del server (pubKc)
    X509* peer_cert = SSL_get_peer_certificate(ssl);
    if (!peer_cert) {
        cerr << "[ERRORE] Il server non ha fornito alcun certificato X.509." << endl;
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sock_fd);
        SSL_CTX_free(ssl_ctx);
        return 1;
    }

    long verify_res = SSL_get_verify_result(ssl);
    if (verify_res != X509_V_OK) {
        cerr << "[ERRORE] Verifica del certificato fallita: " 
             << X509_verify_cert_error_string(verify_res) << endl;
        X509_free(peer_cert);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sock_fd);
        SSL_CTX_free(ssl_ctx);
        return 1;
    }

    char cert_subject[512] = {};
    X509_NAME_oneline(X509_get_subject_name(peer_cert), cert_subject, sizeof(cert_subject) - 1);
    X509_free(peer_cert);

    cout << "[OK] Canale TLS 1.3 stabilito con successo!" << endl;
    cout << "     Server Cert : " << cert_subject << endl;
    cout << "     TLS Versione: " << SSL_get_version(ssl) << " | Cipher: " << SSL_get_cipher(ssl) << endl;
    cout << "--------------------------------------------------" << endl;

    // -------------------------------------------------------------
    // Autenticazione Utente (LOGIN)
    // -------------------------------------------------------------
    string username = cli_user;
    string password = cli_pass;

    if (username.empty()) {
        cout << "Inserisci Username: " << flush;
        if (!getline(cin, username) || username.empty()) {
            cerr << "[ERRORE] Username non valido o vuoto." << endl;
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(sock_fd);
            SSL_CTX_free(ssl_ctx);
            return 1;
        }
    }

    if (password.empty()) {
        cout << "Inserisci Password: " << flush;
        if (!getline(cin, password) || password.empty()) {
            cerr << "[ERRORE] Password non valida o vuota." << endl;
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(sock_fd);
            SSL_CTX_free(ssl_ctx);
            return 1;
        }
    }

    json login_req = {
        {"cmd", "LOGIN"},
        {"username", username},
        {"password", password}
    };

    if (!tss::send_json_message(ssl, login_req)) {
        cerr << "[ERRORE] Invio richiesta LOGIN fallito." << endl;
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sock_fd);
        SSL_CTX_free(ssl_ctx);
        return 1;
    }

    json login_resp;
    if (!tss::recv_json_message(ssl, login_resp)) {
        cerr << "[ERRORE] Ricezione risposta LOGIN fallita o connessione interrotta." << endl;
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sock_fd);
        SSL_CTX_free(ssl_ctx);
        return 1;
    }

    if (login_resp.value("status", "") != "OK") {
        cerr << "[ERRORE] Autenticazione fallita: " 
             << login_resp.value("message", "Nessun messaggio di errore specificato") << endl;
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sock_fd);
        SSL_CTX_free(ssl_ctx);
        return 1;
    }

    string nonce_s = login_resp.value("nonce_s", "");
    cout << "[OK] Autenticazione completata con successo per l'utente '" << username << "'!" << endl;
    cout << "     Nonce Server : " << nonce_s << endl;

    print_help();

    // -------------------------------------------------------------
    // Loop Interattivo (REPL)
    // -------------------------------------------------------------
    uint64_t seq = 1;
    string line;

    while (true) {
        cout << "tss[" << username << "]> " << flush;
        if (!getline(cin, line)) {
            // Raggiunta fine dell'input (EOF o CTRL+D)
            cout << "\n[INFO] Ricevuto EOF. Chiusura sessione..." << endl;
            break;
        }

        if (line.empty()) continue;

        istringstream iss(line);
        string cmd_word;
        iss >> cmd_word;

        // --- Comando: timestamp <file|hex> ---
        if (cmd_word == "timestamp") {
            string target;
            if (!(iss >> target)) {
                cout << "Uso: timestamp <percorso_file | stringa_hash_hex>" << endl;
                continue;
            }

            string hash_hex;
            if (file_exists(target)) {
                try {
                    hash_hex = tss::sha256_file(target);
                    cout << "[*] File: " << target << "\n    SHA-256: " << hash_hex << endl;
                } catch (const exception& e) {
                    cerr << "[ERRORE] Calcolo hash del file fallito: " << e.what() << endl;
                    continue;
                }
            } else {
                // Tratta il target come hash esadecimale diretto
                hash_hex = target;
                if (hash_hex.length() != 64) {
                    cerr << "[ATTENZIONE] L'argomento fornito non e' un file esistente ne' un hash SHA-256 valido a 64 caratteri." << endl;
                }
            }

            uint64_t cur_seq = seq++;
            json req = {
                {"cmd", "TIMESTAMP"},
                {"hash", hash_hex},
                {"nonce_s", nonce_s},
                {"seq", cur_seq}
            };

            if (!tss::send_json_message(ssl, req)) {
                cerr << "[ERRORE] Invio richiesta TIMESTAMP fallito." << endl;
                break;
            }

            json resp;
            if (!tss::recv_json_message(ssl, resp)) {
                cerr << "[ERRORE] Ricezione risposta TIMESTAMP fallita." << endl;
                break;
            }

            // Validazione anti-replay e session binding della risposta del server
            if (resp.value("nonce_s", "") != nonce_s || resp.value("seq", 0ULL) != cur_seq) {
                cerr << "[ERRORE] Validazione risposta fallita: session nonce_s o seq non corrispondono!" << endl;
                cerr << "         Atteso: nonce_s=" << nonce_s.substr(0, 8) << "..., seq=" << cur_seq << endl;
                cerr << "         Ricevuto: nonce_s=" << resp.value("nonce_s", "").substr(0, 8) << "..., seq=" << resp.value("seq", 0ULL) << endl;
                break;
            }

            if (resp.value("status", "") == "OK") {
                uint64_t ts = resp["time"].get<uint64_t>();
                string sig = resp["signature"].get<string>();

                cout << "+-------------------------------------------------------------------------+\n"
                     << "| Token di Timestamp Rilasciato dalla TSA                                 |\n"
                     << "+-------------------------------------------------------------------------+\n"
                     << "| Hash SHA-256 : " << resp["hash"].get<string>() << "\n"
                     << "| Data / Ora   : " << tss::format_epoch_time(ts) << " (" << ts << ")\n"
                     << "| Firma ECDSA  : " << sig.substr(0, 32) << "...\n"
                     << "+-------------------------------------------------------------------------+\n";

                string saved_file = save_timestamp_token(resp);
                if (!saved_file.empty()) {
                    cout << "[*] Puoi verificare questo token digitando: verify " << saved_file << endl;
                }
            } else {
                cout << "[-] Richiesta TIMESTAMP RESPINTA dal server: " 
                     << resp.value("message", "Errore sconosciuto") << endl;
            }
        }
        // --- Comando: balance ---
        else if (cmd_word == "balance") {
            uint64_t cur_seq = seq++;
            json req = {
                {"cmd", "BALANCE"},
                {"nonce_s", nonce_s},
                {"seq", cur_seq}
            };

            if (!tss::send_json_message(ssl, req)) {
                cerr << "[ERRORE] Invio richiesta BALANCE fallito." << endl;
                break;
            }

            json resp;
            if (!tss::recv_json_message(ssl, resp)) {
                cerr << "[ERRORE] Ricezione risposta BALANCE fallita." << endl;
                break;
            }

            // Validazione anti-replay e session binding della risposta del server
            if (resp.value("nonce_s", "") != nonce_s || resp.value("seq", 0ULL) != cur_seq) {
                cerr << "[ERRORE] Validazione risposta fallita: session nonce_s o seq non corrispondono!" << endl;
                cerr << "         Atteso: nonce_s=" << nonce_s.substr(0, 8) << "..., seq=" << cur_seq << endl;
                cerr << "         Ricevuto: nonce_s=" << resp.value("nonce_s", "").substr(0, 8) << "..., seq=" << resp.value("seq", 0ULL) << endl;
                break;
            }

            if (resp.value("status", "") == "OK") {
                uint64_t nc = resp["nc"].get<uint64_t>();
                uint64_t nr = resp["nr"].get<uint64_t>();

                cout << "+---------------------------------------------------+\n"
                     << "| Saldo Crediti Utente: " << setw(27) << left << username << " |\n"
                     << "+---------------------------------------------------+\n"
                     << "| Timestamp Consumati (nc) : " << setw(22) << right << nc << " |\n"
                     << "| Timestamp Rimanenti (nr) : " << setw(22) << right << nr << " |\n"
                     << "+---------------------------------------------------+\n";
            } else {
                cout << "[-] Richiesta BALANCE fallita: " 
                     << resp.value("message", "Errore sconosciuto") << endl;
            }
        }
        // --- Comando: verify <token.json> ---
        else if (cmd_word == "verify") {
            string token_file;
            if (!(iss >> token_file)) {
                cout << "Uso: verify <file_token.json>" << endl;
                continue;
            }

            cout << "[*] Verifica crittografica del token: " << token_file << endl;
            bool is_valid = verify_token_file(token_file, pubkts_path);
            if (is_valid) {
                cout << "[OK] Token VALIDO — La firma crittografica corrisponde alla chiave pubKts." << endl;
            } else {
                cout << "[ERRORE] Token NON VALIDO — Verifica della firma fallita o token alterato!" << endl;
            }
        }
        // --- Comando: help ---
        else if (cmd_word == "help") {
            print_help();
        }
        // --- Comando: quit / exit ---
        else if (cmd_word == "quit" || cmd_word == "exit") {
            uint64_t cur_seq = seq++;
            json req = {
                {"cmd", "QUIT"},
                {"nonce_s", nonce_s},
                {"seq", cur_seq}
            };
            tss::send_json_message(ssl, req);
            json resp;
            if (tss::recv_json_message(ssl, resp)) {
                if (resp.value("nonce_s", "") != nonce_s || resp.value("seq", 0ULL) != cur_seq) {
                    cerr << "[ATTENZIONE] Risposta QUIT con nonce_s o seq non corrispondenti." << endl;
                }
            }
            break;
        }
        // --- Comando Sconosciuto ---
        else {
            cout << "[-] Comando non riconosciuto: '" << cmd_word << "'. Digita 'help' per la lista dei comandi." << endl;
        }
    }

    // -------------------------------------------------------------
    // FASE 5.4: Chiusura Sessione e Rilascio Risorse
    // -------------------------------------------------------------
    cout << "[INFO] Chiusura canale sicuro TLS e disconnessione..." << endl;
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);
    close(sock_fd);

    cout << "[OK] Disconnesso dal server. Arrivederci!" << endl;
    return 0;
}
