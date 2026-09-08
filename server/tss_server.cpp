/**
 * tss_server.cpp — Timestamping Service (TSS) Server
 * Progetto: Foundations of Cybersecurity (FoC)
 * 
 * Server di marcatura temporale:
 * - Canale sicuro su TLS 1.3 con Perfect Forward Secrecy (ECDHE) e crittografia AEAD
 * - Architettura multi-client concorrente (std::thread)
 * - Gestione thread-safe del database utenti (users.json)
 * - Autenticazione crittografica con password hash + salt (SHA-256)
 * - Caricamento e gestione della chiave privata di timestamping P-384 (privKts)
 * - Arresto controllato e rilascio risorse su ricezione segnali (SIGINT, SIGTERM)
 */

#include "common.hpp"

#include <iostream>
#include <fstream>
#include <string>
#include <unordered_map>
#include <mutex>
#include <thread>
#include <atomic>
#include <vector>
#include <cstring>
#include <csignal>
#include <stdexcept>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

using namespace std;
using json = nlohmann::json;

// --- Struttura Dati Utente ---
struct UserRecord {
    string salt;           // Salt a 16 byte (32 caratteri hex)
    string password_hash;  // SHA-256(password + salt) in hex
    uint64_t nc = 0;       // Numero di timestamp consumati
    uint64_t nr = 0;       // Numero di timestamp rimanenti (quota)
};

// --- Stato Globale del Server ---
static unordered_map<string, UserRecord> g_users;
static mutex                             g_users_mtx;
static EVP_PKEY*                         g_ts_key = nullptr; // privKts (P-384)
static string                            g_users_file = tss::USERS_DB;

static atomic<bool>                      g_running{true};
static int                               g_server_fd = -1;

// --- Gestione Segnali di Terminazione ---
void signal_handler(int signum) {
    (void)signum;
    cout << "\n[INFO] Ricevuto segnale di arresto. Chiusura del server in corso..." << endl;
    g_running = false;
    if (g_server_fd >= 0) {
        shutdown(g_server_fd, SHUT_RDWR);
        close(g_server_fd);
        g_server_fd = -1;
    }
}

// --- Utility: Verifica esistenza file su disco ---
bool file_exists(const string& path) {
    struct stat buffer;
    return (stat(path.c_str(), &buffer) == 0);
}

// --- Caricamento Utenti da users.json ---
bool load_users(const string& path) {
    ifstream f(path);
    if (!f.is_open()) {
        cerr << "[ERRORE] Impossibile aprire il file utenti: " << path << endl;
        return false;
    }

    try {
        json j;
        f >> j;

        if (!j.contains("users") || !j["users"].is_object()) {
            cerr << "[ERRORE] Formato users.json non valido (manca oggetto 'users')" << endl;
            return false;
        }

        lock_guard<mutex> lock(g_users_mtx);
        g_users.clear();

        for (auto& [username, data] : j["users"].items()) {
            UserRecord rec;
            rec.salt = data.value("salt", "");
            rec.password_hash = data.value("password_hash", "");
            rec.nc = data.value("nc", static_cast<uint64_t>(0));
            rec.nr = data.value("nr", static_cast<uint64_t>(0));

            if (rec.salt.empty() || rec.password_hash.empty()) {
                cerr << "[ATTENZIONE] Record incompleto per l'utente: " << username << endl;
                continue;
            }

            g_users[username] = rec;
        }

        cout << "[OK] Caricati " << g_users.size() << " utenti dal database (" << path << ")" << endl;
        return true;
    } catch (const exception& e) {
        cerr << "[ERRORE] Parsing JSON fallito per " << path << ": " << e.what() << endl;
        return false;
    }
}

// --- Salvataggio Utenti su users.json (Internal, Mutex già acquisito) ---
bool save_users_locked(const string& path) {
    json j;
    j["users"] = json::object();

    for (const auto& [username, rec] : g_users) {
        j["users"][username] = {
            {"salt", rec.salt},
            {"password_hash", rec.password_hash},
            {"nc", rec.nc},
            {"nr", rec.nr}
        };
    }

    ofstream f(path);
    if (!f.is_open()) {
        cerr << "[ERRORE] Impossibile salvare il database utenti su: " << path << endl;
        return false;
    }

    f << j.dump(2) << endl;
    return true;
}

// --- Salvataggio Utenti su users.json (Thread-Safe) ---
bool save_users(const string& path) {
    lock_guard<mutex> lock(g_users_mtx);
    return save_users_locked(path);
}

// --- Firma Digitale del Payload Timestamp (privKts - P-384 con SHA-384) ---
string sign_timestamp_payload(EVP_PKEY* pkey, const vector<uint8_t>& payload) {
    if (!pkey) {
        throw runtime_error("Chiave privata privKts non inizializzata");
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw runtime_error("Errore allocazione EVP_MD_CTX");
    }

    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha384(), nullptr, pkey) <= 0) {
        EVP_MD_CTX_free(ctx);
        tss::print_openssl_errors("EVP_DigestSignInit");
        throw runtime_error("Errore inizializzazione DigestSign");
    }

    if (EVP_DigestSignUpdate(ctx, payload.data(), payload.size()) <= 0) {
        EVP_MD_CTX_free(ctx);
        tss::print_openssl_errors("EVP_DigestSignUpdate");
        throw runtime_error("Errore aggiornamento digest payload");
    }

    size_t sig_len = 0;
    if (EVP_DigestSignFinal(ctx, nullptr, &sig_len) <= 0) {
        EVP_MD_CTX_free(ctx);
        tss::print_openssl_errors("EVP_DigestSignFinal (size)");
        throw runtime_error("Errore determinazione lunghezza firma");
    }

    vector<uint8_t> sig(sig_len);
    if (EVP_DigestSignFinal(ctx, sig.data(), &sig_len) <= 0) {
        EVP_MD_CTX_free(ctx);
        tss::print_openssl_errors("EVP_DigestSignFinal");
        throw runtime_error("Errore generazione finale della firma");
    }

    EVP_MD_CTX_free(ctx);
    sig.resize(sig_len);
    return tss::bytes_to_hex(sig);
}

// --- Verifica Credenziali Utente (Password + Salt) ---
bool verify_user_credentials(const string& username, const string& password) {
    lock_guard<mutex> lock(g_users_mtx);

    auto it = g_users.find(username);
    if (it == g_users.end()) {
        return false; // Utente non trovato
    }

    const UserRecord& rec = it->second;
    // Calcolo: SHA-256(password + salt)
    string computed_hash = tss::sha256_string(password + rec.salt);

    return (computed_hash == rec.password_hash);
}

// --- Caricamento Chiave Privata di Timestamping (privKts - P-384) ---
EVP_PKEY* load_private_key(const string& key_path) {
    FILE* kf = fopen(key_path.c_str(), "r");
    if (!kf) {
        cerr << "[ERRORE] Impossibile aprire il file della chiave privata: " << key_path << endl;
        return nullptr;
    }

    EVP_PKEY* pkey = PEM_read_PrivateKey(kf, nullptr, nullptr, nullptr);
    fclose(kf);

    if (!pkey) {
        cerr << "[ERRORE] Errore nel parsing OpenSSL della chiave privata: " << key_path << endl;
        tss::print_openssl_errors("load_private_key");
        return nullptr;
    }

    cout << "[OK] Chiave privata di timestamping caricata con successo: " << key_path << endl;
    return pkey;
}

// --- Inizializzazione Contesto TLS 1.3 Server ---
SSL_CTX* create_server_ssl_context(const string& cert_file, const string& key_file) {
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        cerr << "[ERRORE] Creazione contesto SSL fallita." << endl;
        tss::print_openssl_errors("SSL_CTX_new");
        return nullptr;
    }

    // Forza esclusivamente TLS 1.3 come versione minima e massima
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1) {
        cerr << "[ERRORE] Impossibile impostare TLS 1.3 come versione minima." << endl;
        tss::print_openssl_errors("SSL_CTX_set_min_proto_version");
        SSL_CTX_free(ctx);
        return nullptr;
    }

    // Carica il certificato X.509 del server (pubKc)
    if (SSL_CTX_use_certificate_file(ctx, cert_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
        cerr << "[ERRORE] Caricamento certificato TLS fallito: " << cert_file << endl;
        tss::print_openssl_errors("SSL_CTX_use_certificate_file");
        SSL_CTX_free(ctx);
        return nullptr;
    }

    // Carica la chiave privata di connessione del server (privKc)
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
        cerr << "[ERRORE] Caricamento chiave privata TLS fallita: " << key_file << endl;
        tss::print_openssl_errors("SSL_CTX_use_PrivateKey_file");
        SSL_CTX_free(ctx);
        return nullptr;
    }

    // Verifica che la chiave privata corrisponda al certificato pubblico caricato
    if (SSL_CTX_check_private_key(ctx) <= 0) {
        cerr << "[ERRORE] La chiave privata non corrisponde al certificato TLS." << endl;
        tss::print_openssl_errors("SSL_CTX_check_private_key");
        SSL_CTX_free(ctx);
        return nullptr;
    }

    cout << "[OK] Contesto TLS 1.3 inizializzato con successo (Certificato: " << cert_file << ")" << endl;
    return ctx;
}

// --- Creazione Socket Server POSIX ---
int create_server_socket(int port) {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("[ERRORE] Impossibile creare il socket");
        return -1;
    }

    // Permette il riutilizzo immediato dell'indirizzo e porta (evita TIME_WAIT)
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("[ATTENZIONE] setsockopt(SO_REUSEADDR) fallito");
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(static_cast<uint16_t>(port));

    if (bind(server_fd, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) < 0) {
        perror("[ERRORE] Bind fallito");
        close(server_fd);
        return -1;
    }

    if (listen(server_fd, SOMAXCONN) < 0) {
        perror("[ERRORE] Listen fallito");
        close(server_fd);
        return -1;
    }

    cout << "[OK] Socket in ascolto su porta " << port << "..." << endl;
    return server_fd;
}

// --- Gestione Connessione Singolo Client (Worker Thread) ---
void handle_client(SSL* ssl, int client_fd, string client_ip, int client_port) {
    string client_id = client_ip + ":" + to_string(client_port);
    cout << "[+] Nuova connessione TCP da " << client_id << endl;

    // Esecuzione handshake TLS lato server
    if (SSL_accept(ssl) <= 0) {
        cerr << "[-] Handshake TLS fallito con " << client_id << endl;
        tss::print_openssl_errors("SSL_accept");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
        return;
    }

    cout << "[OK] Handshake TLS completato con " << client_id << endl;
    cout << "     Versione: " << SSL_get_version(ssl) 
         << " | Cipher: " << SSL_get_cipher(ssl) << endl;

    // Stato di Sessione del Client
    bool is_authenticated = false;
    string authenticated_user;
    string client_nonce;
    string server_nonce;
    uint64_t expected_seq = 1;

    // Loop di elaborazione messaggi su canale sicuro
    while (g_running) {
        if (!is_authenticated) {
            cout << "[*] In attesa di autenticazione (LOGIN) da " << client_id << "..." << endl;
        } else {
            cout << "[*] In attesa di richieste da '" << authenticated_user << "' (" << client_id << ")..." << endl;
        }

        json req;
        if (!tss::recv_json_message(ssl, req)) {
            // Connessione terminata dal client o errore di rete/framing
            break;
        }

        if (!req.is_object() || !req.contains("cmd") || !req["cmd"].is_string()) {
            json err_resp = {
                {"status", "ERROR"},
                {"message", "Formato messaggio non valido (campo 'cmd' mancante o non valido)"}
            };
            tss::send_json_message(ssl, err_resp);
            continue;
        }

        string cmd = req["cmd"].get<string>();

        // 1. Comando di Autenticazione: LOGIN
        if (cmd == "LOGIN") {
            if (is_authenticated) {
                json resp = {
                    {"status", "ERROR"},
                    {"message", "Utente gia' autenticato per questa sessione"}
                };
                tss::send_json_message(ssl, resp);
                continue;
            }

            if (!req.contains("username") || !req.contains("password") || !req.contains("nonce_c") ||
                !req["username"].is_string() || !req["password"].is_string() || !req["nonce_c"].is_string()) {
                json resp = {
                    {"status", "ERROR"},
                    {"message", "Parametri LOGIN mancanti o non validi (richiesti: username, password, nonce_c)"}
                };
                tss::send_json_message(ssl, resp);
                continue;
            }

            string username = req["username"].get<string>();
            string password = req["password"].get<string>();
            string nonce_c = req["nonce_c"].get<string>();

            if (username.empty() || password.empty() || nonce_c.empty()) {
                json resp = {
                    {"status", "ERROR"},
                    {"message", "Credenziali o nonce_c non possono essere vuoti"}
                };
                tss::send_json_message(ssl, resp);
                continue;
            }

            // Verifica delle credenziali nel database thread-safe
            bool auth_ok = verify_user_credentials(username, password);
            if (!auth_ok) {
                cout << "[-] Autenticazione FALLITA per l'utente '" << username << "' da " << client_id << endl;
                json resp = {
                    {"status", "ERROR"},
                    {"message", "Autenticazione fallita: username o password non validi"}
                };
                tss::send_json_message(ssl, resp);
                // Terminazione della connessione su credenziali errate
                break;
            }

            // Autenticazione riuscita: generazione nonce server e inizializzazione sessione
            string nonce_s = tss::generate_nonce_hex(16);
            is_authenticated = true;
            authenticated_user = username;
            client_nonce = nonce_c;
            server_nonce = nonce_s;
            expected_seq = 1;

            cout << "[+] Autenticazione RIUSCITA per '" << username << "' da " << client_id 
                 << " (Nonce_C: " << client_nonce.substr(0, 8) << "... | Nonce_S: " << server_nonce.substr(0, 8) << "...)" << endl;

            json resp = {
                {"status", "OK"},
                {"nonce_s", nonce_s}
            };
            if (!tss::send_json_message(ssl, resp)) {
                cerr << "[-] Errore invio risposta LOGIN a " << client_id << endl;
                break;
            }
            continue;
        }

        // 2. Controllo Autenticazione per comandi successivi
        if (!is_authenticated) {
            json resp = {
                {"status", "ERROR"},
                {"message", "Accesso negato: autenticazione (LOGIN) richiesta prima di procedere"}
            };
            tss::send_json_message(ssl, resp);
            continue;
        }

        // 3. Verifica Anti-Replay: Controllo Monotonicita' del Sequence Number
        if (!req.contains("seq") || !req["seq"].is_number_unsigned()) {
            json resp = {
                {"status", "ERROR"},
                {"message", "Controllo anti-replay fallito: campo 'seq' (uint) mancante"}
            };
            tss::send_json_message(ssl, resp);
            continue;
        }

        uint64_t seq = req["seq"].get<uint64_t>();
        if (seq != expected_seq) {
            cerr << "[!] Violazione anti-replay da " << client_id << " (utente: " << authenticated_user << "):"
                 << " seq ricevuto=" << seq << ", atteso=" << expected_seq << endl;

            json resp = {
                {"status", "ERROR"},
                {"message", "Controllo anti-replay fallito: numero di sequenza errato"},
                {"expected_seq", expected_seq},
                {"received_seq", seq}
            };
            tss::send_json_message(ssl, resp);
            break; // Termina la sessione per prevenire replay attack
        }
        expected_seq++;

        // 4. Dispatch comandi di sessione
        if (cmd == "BALANCE") {
            uint64_t nc = 0, nr = 0;
            {
                lock_guard<mutex> lock(g_users_mtx);
                auto it = g_users.find(authenticated_user);
                if (it != g_users.end()) {
                    nc = it->second.nc;
                    nr = it->second.nr;
                }
            }

            cout << "[+] Interrogazione BALANCE per '" << authenticated_user 
                 << "': nc=" << nc << ", nr=" << nr << " (seq=" << seq << ")" << endl;

            json resp = {
                {"status", "OK"},
                {"nc", nc},
                {"nr", nr}
            };
            if (!tss::send_json_message(ssl, resp)) {
                cerr << "[-] Errore invio risposta BALANCE a " << client_id << endl;
                break;
            }
            continue;
        } 
        else if (cmd == "TIMESTAMP") {
            if (!req.contains("hash") || !req["hash"].is_string()) {
                json resp = {
                    {"status", "ERROR"},
                    {"message", "Parametro 'hash' (stringa SHA-256 esadecimale) mancante o non valido"}
                };
                tss::send_json_message(ssl, resp);
                continue;
            }

            string doc_hash = req["hash"].get<string>();

            // Validazione sintattica dell'hash (deve essere 64 caratteri hex = 32 byte)
            if (doc_hash.length() != 64) {
                json resp = {
                    {"status", "ERROR"},
                    {"message", "Formato hash non valido (deve essere una stringa esadecimale SHA-256 di 64 caratteri)"}
                };
                tss::send_json_message(ssl, resp);
                continue;
            }

            bool valid_hex = true;
            for (char c : doc_hash) {
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                    valid_hex = false;
                    break;
                }
            }
            if (!valid_hex) {
                json resp = {
                    {"status", "ERROR"},
                    {"message", "L'hash contiene caratteri esadecimali non validi"}
                };
                tss::send_json_message(ssl, resp);
                continue;
            }

            // Verifica disponibilità quota e aggiornamento saldo
            bool quota_available = false;
            uint64_t updated_nc = 0;
            uint64_t updated_nr = 0;

            {
                lock_guard<mutex> lock(g_users_mtx);
                auto it = g_users.find(authenticated_user);
                if (it != g_users.end()) {
                    if (it->second.nr > 0) {
                        it->second.nc += 1;
                        it->second.nr -= 1;
                        updated_nc = it->second.nc;
                        updated_nr = it->second.nr;
                        quota_available = true;

                        // Persistenza atomica dello stato aggiornato su disco
                        save_users_locked(g_users_file);
                    }
                }
            }

            if (!quota_available) {
                cout << "[-] Richiesta TIMESTAMP respinta per '" << authenticated_user 
                     << "': saldo esaurito (nr = 0)" << endl;
                json resp = {
                    {"status", "ERROR"},
                    {"message", "Timestamp balance exhausted"}
                };
                tss::send_json_message(ssl, resp);
                continue;
            }

            // Acquisizione timestamp autorevole UTC (Unix Epoch)
            uint64_t ts_epoch = tss::get_current_epoch_time();

            // Costruzione payload canonico binario a 40 byte (32 byte hash + 8 byte big-endian time)
            vector<uint8_t> payload;
            try {
                payload = tss::build_timestamp_payload(doc_hash, ts_epoch);
            } catch (const exception& e) {
                cerr << "[ERRORE] Costruzione payload fallita: " << e.what() << endl;
                json resp = {
                    {"status", "ERROR"},
                    {"message", "Errore interno nella costruzione del payload"}
                };
                tss::send_json_message(ssl, resp);
                continue;
            }

            // Firma crittografica del payload con privKts (P-384 / SHA-384)
            string sig_hex;
            try {
                sig_hex = sign_timestamp_payload(g_ts_key, payload);
            } catch (const exception& e) {
                cerr << "[ERRORE] Firma digitale fallita: " << e.what() << endl;
                json resp = {
                    {"status", "ERROR"},
                    {"message", "Errore crittografico interno durante la firma del timestamp"}
                };
                tss::send_json_message(ssl, resp);
                continue;
            }

            cout << "[+] TIMESTAMP emesso per '" << authenticated_user << "' | Data: " 
                 << tss::format_epoch_time(ts_epoch) 
                 << " | Saldo rimanente: " << updated_nr 
                 << " (nc=" << updated_nc << ")" << endl;

            // Invio del token di timestamp firmato
            json resp = {
                {"status", "OK"},
                {"hash", doc_hash},
                {"time", ts_epoch},
                {"signature", sig_hex}
            };
            if (!tss::send_json_message(ssl, resp)) {
                cerr << "[-] Errore invio risposta TIMESTAMP a " << client_id << endl;
                break;
            }
            continue;
        }
        else if (cmd == "QUIT" || cmd == "LOGOUT") {
            json resp = {
                {"status", "OK"},
                {"message", "Disconnessione completata con successo"}
            };
            tss::send_json_message(ssl, resp);
            break;
        }
        else {
            json resp = {
                {"status", "ERROR"},
                {"message", "Comando sconosciuto o non supportato: " + cmd}
            };
            tss::send_json_message(ssl, resp);
        }
    }

    cout << "[-] Connessione chiusa con " << client_id;
    if (!authenticated_user.empty()) {
        cout << " (utente: " << authenticated_user << ")";
    }
    cout << endl;

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_fd);
}

// --- Guida utilizzo CLI ---
void usage(const char* prog_name) {
    cout << "Uso: " << prog_name << " [OPZIONI]\n\n"
         << "Opzioni:\n"
         << "  --port <porta>       Porta TCP di ascolto (default: " << tss::SERVER_PORT << ")\n"
         << "  --crt <cert.crt>     Certificato TLS di connessione (default: " << tss::SERVER_CONN_CRT << ")\n"
         << "  --key <key.key>      Chiave privata TLS di connessione (default: " << tss::SERVER_CONN_KEY << ")\n"
         << "  --tskey <key.key>    Chiave privata per firma timestamp (default: " << tss::SERVER_TS_KEY << ")\n"
         << "  --users <file.json>  File database utenti (default: " << tss::USERS_DB << ")\n"
         << "  --help, -h           Mostra questo messaggio di aiuto\n";
}

int main(int argc, char* argv[]) {
    int port = tss::SERVER_PORT;
    string conn_crt = tss::SERVER_CONN_CRT;
    string conn_key = tss::SERVER_CONN_KEY;
    string ts_key_path = tss::SERVER_TS_KEY;
    string users_path = tss::USERS_DB;

    // Registrazione gestori segnali per shutdown pulito
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    // Ignora SIGPIPE per evitare che la disconnessione o chiusura socket di un client termini il server
    signal(SIGPIPE, SIG_IGN);

    // Parsing argomenti CLI
    for (int i = 1; i < argc; ++i) {
        string arg = argv[i];
        if (arg == "--port" && i + 1 < argc) {
            port = stoi(argv[++i]);
        } else if (arg == "--crt" && i + 1 < argc) {
            conn_crt = argv[++i];
        } else if (arg == "--key" && i + 1 < argc) {
            conn_key = argv[++i];
        } else if (arg == "--tskey" && i + 1 < argc) {
            ts_key_path = argv[++i];
        } else if (arg == "--users" && i + 1 < argc) {
            users_path = argv[++i];
        } else if (arg == "--help" || arg == "-h") {
            usage(argv[0]);
            return 0;
        } else {
            cerr << "Opzione non riconosciuta: " << arg << endl;
            usage(argv[0]);
            return 1;
        }
    }

    g_users_file = users_path;

    cout << "==================================================" << endl;
    cout << " TSS Server (Timestamping Service)" << endl;
    cout << "==================================================" << endl;
    cout << "Configurazione rilevata:" << endl;
    cout << "  - Porta di ascolto   : " << port << endl;
    cout << "  - Certificato TLS    : " << conn_crt << endl;
    cout << "  - Chiave TLS         : " << conn_key << endl;
    cout << "  - Chiave Timestamping: " << ts_key_path << endl;
    cout << "  - Database Utenti    : " << users_path << endl;
    cout << "--------------------------------------------------" << endl;

    // 1. Verifica file certificati TLS
    if (!file_exists(conn_crt)) {
        cerr << "[ERRORE] Certificato TLS non trovato: " << conn_crt << endl;
        cerr << "Suggerimento: Esegui ./keygen.sh prima di avviare il server." << endl;
        return 1;
    }
    if (!file_exists(conn_key)) {
        cerr << "[ERRORE] Chiave privata TLS non trovata: " << conn_key << endl;
        cerr << "Suggerimento: Esegui ./keygen.sh prima di avviare il server." << endl;
        return 1;
    }

    // 2. Caricamento chiave privata di timestamping (privKts)
    g_ts_key = load_private_key(ts_key_path);
    if (!g_ts_key) {
        return 1;
    }

    // 3. Caricamento database utenti
    if (!load_users(g_users_file)) {
        EVP_PKEY_free(g_ts_key);
        return 1;
    }

    // 4. Inizializzazione contesto TLS 1.3
    SSL_CTX* ssl_ctx = create_server_ssl_context(conn_crt, conn_key);
    if (!ssl_ctx) {
        EVP_PKEY_free(g_ts_key);
        return 1;
    }

    // 5. Creazione socket server TCP
    g_server_fd = create_server_socket(port);
    if (g_server_fd < 0) {
        SSL_CTX_free(ssl_ctx);
        EVP_PKEY_free(g_ts_key);
        return 1;
    }

    cout << "--------------------------------------------------" << endl;
    cout << "[READY] Server TSS attivo e in attesa di connessioni TLS 1.3..." << endl;
    cout << "Premi CTRL+C per arrestare il server." << endl;
    cout << "--------------------------------------------------" << endl;

    // 6. Ciclo principale di accettazione connessioni (Multi-Client)
    while (g_running) {
        sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);

        int client_fd = accept(g_server_fd, reinterpret_cast<sockaddr*>(&client_addr), &client_len);
        if (client_fd < 0) {
            if (!g_running) break; // Uscita pulita se il server è stato interrotto
            perror("[ATTENZIONE] accept() fallito");
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        int client_port = ntohs(client_addr.sin_port);

        SSL* ssl = SSL_new(ssl_ctx);
        if (!ssl) {
            cerr << "[ERRORE] Creazione struttura SSL fallita per client " << client_ip << endl;
            close(client_fd);
            continue;
        }

        SSL_set_fd(ssl, client_fd);

        // Spawn di un thread dedicato per gestire la connessione del client in parallelo
        thread client_thread(handle_client, ssl, client_fd, string(client_ip), client_port);
        client_thread.detach();
    }

    // Pulizia e rilascio risorse di sistema
    cout << "[INFO] Arresto del server e rilascio risorse in corso..." << endl;
    if (g_server_fd >= 0) {
        close(g_server_fd);
        g_server_fd = -1;
    }
    if (ssl_ctx) {
        SSL_CTX_free(ssl_ctx);
    }
    if (g_ts_key) {
        EVP_PKEY_free(g_ts_key);
        g_ts_key = nullptr;
    }

    cout << "[OK] Server arrestato correttamente." << endl;
    return 0;
}
