#pragma once

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <chrono>
#include <cstring>
#include <cstdint>
#include <stdexcept>
#include <endian.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <nlohmann/json.hpp>

namespace tss {

// Costanti di configurazione e percorsi
constexpr uint32_t MAX_PAYLOAD_SIZE = 64 * 1024; // 64 KB limite anti-DoS
constexpr const char* SERVER_HOST = "127.0.0.1";
constexpr int SERVER_PORT = 8443;

constexpr const char* SERVER_CONN_CRT = "certs/server_conn.crt";
constexpr const char* SERVER_CONN_KEY = "certs/server_conn.key";
constexpr const char* SERVER_TS_KEY   = "certs/server_ts.key";
constexpr const char* SERVER_TS_PUB   = "certs/server_ts.pub";
 const char* USERS_DB        = "users.json";

// --- Conversioni Hex / Byte ---
inline std::string bytes_to_hex(const uint8_t* data, size_t len) {
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        ss << std::setw(2) << static_cast<int>(data[i]);
    }
    return ss.str();
}

inline std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
    return bytes_to_hex(bytes.data(), bytes.size());
}

inline std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    if (hex.length() % 2 != 0) {
        throw std::invalid_argument("Lunghezza esadecimale non valida (deve essere pari)");
    }
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.length() / 2);

    for (size_t i = 0; i < hex.length(); i += 2) {
        auto nibble = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
            if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
            if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
            throw std::invalid_argument("Carattere hex non valido");
        };
        bytes.push_back(static_cast<uint8_t>((nibble(hex[i]) << 4) | nibble(hex[i + 1])));
    }
    return bytes;
}

// --- Generazione Nonce Crittografico (CSPRNG) ---
inline std::string generate_nonce_hex(size_t bytes_len = 16) {
    std::vector<uint8_t> buf(bytes_len);
    if (RAND_bytes(buf.data(), static_cast<int>(bytes_len)) != 1) {
        throw std::runtime_error("Errore generazione nonce con RAND_bytes");
    }
    return bytes_to_hex(buf);
}

// --- Funzioni di Hashing SHA-256 (OpenSSL EVP) ---
inline std::vector<uint8_t> sha256_bytes(const uint8_t* data, size_t len) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Errore allocazione EVP_MD_CTX");
    }

    std::vector<uint8_t> hash(static_cast<size_t>(EVP_MD_size(EVP_sha256())));
    unsigned int hash_len = 0;

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, data, len) != 1 ||
        EVP_DigestFinal_ex(ctx, hash.data(), &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Errore durante il calcolo SHA-256");
    }

    EVP_MD_CTX_free(ctx);
    hash.resize(hash_len);
    return hash;
}

inline std::string sha256_string(const std::string& str) {
    auto hash = sha256_bytes(reinterpret_cast<const uint8_t*>(str.data()), str.size());
    return bytes_to_hex(hash);
}

// Calcolo hash del file a blocchi per preservare il Data Minimization Principle
inline std::string sha256_file(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Impossibile aprire il file per l'hash: " + filepath);
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        if (ctx) EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Errore inizializzazione digest per file");
    }

    char buffer[16384]; // Buffer da 16 KB
    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
        if (EVP_DigestUpdate(ctx, buffer, static_cast<size_t>(file.gcount())) != 1) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("Errore durante la lettura del file per SHA-256");
        }
    }

    std::vector<uint8_t> hash(static_cast<size_t>(EVP_MD_size(EVP_sha256())));
    unsigned int hash_len = 0;
    if (EVP_DigestFinal_ex(ctx, hash.data(), &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Errore finalizzazione SHA-256 file");
    }

    EVP_MD_CTX_free(ctx);
    hash.resize(hash_len);
    return bytes_to_hex(hash);
}

// --- Costruzione Payload del Timestamp (Hash || Time) ---
inline std::vector<uint8_t> build_timestamp_payload(const std::string& hash_hex, uint64_t timestamp) {
    auto hash_bytes = hex_to_bytes(hash_hex);
    if (hash_bytes.size() != 32) {
        throw std::invalid_argument("L'hash SHA-256 deve essere di 32 byte (64 caratteri hex)");
    }

    // Convertiamo il tempo Unix in Big-Endian
    uint64_t be_time = htobe64(timestamp);

    std::vector<uint8_t> payload;
    payload.reserve(32 + sizeof(uint64_t));
    payload.insert(payload.end(), hash_bytes.begin(), hash_bytes.end());

    const uint8_t* time_bytes = reinterpret_cast<const uint8_t*>(&be_time);
    payload.insert(payload.end(), time_bytes, time_bytes + sizeof(uint64_t));

    return payload;
}

// --- Gestione Orari (UTC) ---

inline uint64_t get_current_epoch_time() {
    auto now = std::chrono::system_clock::now();
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count()
    );
}

inline std::string format_epoch_time(uint64_t epoch) {
    std::time_t t = static_cast<std::time_t>(epoch);
    std::tm tm_buf{};
    gmtime_r(&t, &tm_buf);
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", &tm_buf);
    return std::string(buf);
}

// --- Protocollo di Framing su TLS (Length-Prefixed JSON) ---
// [ 4 byte: uint32 length (Big-Endian) ] [ Payload JSON in UTF-8 ]

inline bool send_json_message(SSL* ssl, const nlohmann::json& j) {
    if (!ssl) return false;

    std::string data = j.dump();
    uint32_t len = static_cast<uint32_t>(data.size());

    if (len > MAX_PAYLOAD_SIZE) {
        std::cerr << "Errore: Messaggio troppo grande (" << len << " byte)" << std::endl;
        return false;
    }

    uint32_t net_len = htonl(len);
    std::vector<uint8_t> packet(4 + len);
    std::memcpy(packet.data(), &net_len, 4);
    std::memcpy(packet.data() + 4, data.data(), len);

    size_t total_sent = 0;
    while (total_sent < packet.size()) {
        int written = SSL_write(ssl, packet.data() + total_sent, 
                                static_cast<int>(packet.size() - total_sent));
        if (written <= 0) {
            int err = SSL_get_error(ssl, written);
            if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) continue;
            return false;
        }
        total_sent += static_cast<size_t>(written);
    }
    return true;
}

inline bool recv_json_message(SSL* ssl, nlohmann::json& j) {
    if (!ssl) return false;

    // 1. Legge i 4 byte del prefisso lunghezza
    uint32_t net_len = 0;
    size_t read_len = 0;
    uint8_t* p_len = reinterpret_cast<uint8_t*>(&net_len);

    while (read_len < 4) {
        int r = SSL_read(ssl, p_len + read_len, static_cast<int>(4 - read_len));
        if (r <= 0) {
            int err = SSL_get_error(ssl, r);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) continue;
            return false;
        }
        read_len += static_cast<size_t>(r);
    }

    uint32_t len = ntohl(net_len);
    if (len == 0 || len > MAX_PAYLOAD_SIZE) {
        std::cerr << "Errore: Dimensione messaggio non valida (" << len << " byte)" << std::endl;
        return false;
    }

    // 2. Legge il payload JSON
    std::string payload(len, '\0');
    size_t payload_read = 0;

    while (payload_read < len) {
        int r = SSL_read(ssl, &payload[payload_read], static_cast<int>(len - payload_read));
        if (r <= 0) {
            int err = SSL_get_error(ssl, r);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) continue;
            return false;
        }
        payload_read += static_cast<size_t>(r);
    }

    try {
        j = nlohmann::json::parse(payload);
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Errore nel parsing JSON: " << e.what() << std::endl;
        return false;
    }
}

inline void print_openssl_errors(const std::string& msg) {
    std::cerr << "Errore OpenSSL [" << msg << "]:" << std::endl;
    ERR_print_errors_fp(stderr);
}

} // namespace tss
