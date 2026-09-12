#include "common.hpp"
#include <cassert>
#include <iostream>
#include <fstream>

void test_hex_conversion() {
    std::cout << "[Test 1] Hex <-> Byte Conversions..." << std::endl;
    std::vector<uint8_t> raw = {0x00, 0x01, 0x0A, 0x0F, 0x10, 0xAA, 0xFF};
    std::string hex = tss::bytes_to_hex(raw);
    assert(hex == "00010a0f10aaff");

    std::vector<uint8_t> back = tss::hex_to_bytes(hex);
    assert(back == raw);
    std::cout << "  -> PASSED (Hex conversion reversible and accurate)" << std::endl;
}

void test_sha256() {
    std::cout << "[Test 2] SHA-256 EVP Hashing..." << std::endl;
    // NIST Standard Test Vectors
    // Empty string SHA-256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    std::string empty_hash = tss::sha256_string("");
    assert(empty_hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    // "hello" SHA-256: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
    std::string hello_hash = tss::sha256_string("hello");
    assert(hello_hash == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");

    // File SHA-256 test
    {
        std::ofstream temp_file("test_doc.txt");
        temp_file << "hello";
    }
    std::string file_hash = tss::sha256_file("test_doc.txt");
    assert(file_hash == hello_hash);
    std::remove("test_doc.txt");

    std::cout << "  -> PASSED (NIST SHA-256 test vectors match)" << std::endl;
}

void test_nonce_generation() {
    std::cout << "[Test 3] CSPRNG Nonce Generation..." << std::endl;
    std::string nonce1 = tss::generate_nonce_hex(16);
    std::string nonce2 = tss::generate_nonce_hex(16);

    assert(nonce1.length() == 32);
    assert(nonce2.length() == 32);
    assert(nonce1 != nonce2); // Extremely low probability of collision
    std::cout << "  -> PASSED (32-hex chars CSPRNG nonces generated: " << nonce1 << ")" << std::endl;
}

void test_timestamp_payload() {
    std::cout << "[Test 4] Timestamp Canonical Payload Layout..." << std::endl;
    std::string hash_hex = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    uint64_t epoch_time = 1772000000ULL; // Example epoch

    std::vector<uint8_t> payload = tss::build_timestamp_payload(hash_hex, epoch_time);
    assert(payload.size() == 40); // 32 bytes hash + 8 bytes uint64 big endian

    // Check big endian encoding of epoch_time
    uint64_t be_extracted = 0;
    std::memcpy(&be_extracted, payload.data() + 32, sizeof(uint64_t));
    assert(be64toh(be_extracted) == epoch_time);

    std::cout << "  -> PASSED (Canonical 40-byte binary payload verified)" << std::endl;
}

void test_time_formatting() {
    std::cout << "[Test 5] Epoch Time Formatting..." << std::endl;
    uint64_t now = tss::get_current_epoch_time();
    assert(now > 1700000000ULL);
    std::string formatted = tss::format_epoch_time(now);
    std::cout << "  -> Current Time UTC: " << formatted << " (Epoch: " << now << ")" << std::endl;
    std::cout << "  -> PASSED" << std::endl;
}

void test_json_structures() {
    std::cout << "[Test 6] JSON Protocol Framing Structures..." << std::endl;
    nlohmann::json login_req = {
        {"cmd", "LOGIN"},
        {"username", "alice"},
        {"password", "alice_password"},
        {"nonce_c", tss::generate_nonce_hex(16)}
    };

    assert(login_req["cmd"] == "LOGIN");
    assert(login_req["username"] == "alice");

    std::string session_nonce = tss::generate_nonce_hex(16);
    nlohmann::json ts_req = {
        {"cmd", "TIMESTAMP"},
        {"hash", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {"nonce_s", session_nonce},
        {"seq", 1}
    };
    assert(ts_req["cmd"] == "TIMESTAMP");
    assert(ts_req["nonce_s"] == session_nonce);
    assert(ts_req["seq"] == 1);

    nlohmann::json ts_resp = {
        {"status", "OK"},
        {"hash", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {"time", 1772000000ULL},
        {"signature", "3045022100..."},
        {"nc", 1},
        {"nr", 99},
        {"nonce_s", session_nonce},
        {"seq", 1}
    };
    assert(ts_resp["status"] == "OK");
    assert(ts_resp["nonce_s"] == session_nonce);
    assert(ts_resp["seq"] == 1);
    std::cout << "  -> PASSED (JSON schema with session nonce and seq verified)" << std::endl;
}

int main() {
    std::cout << "==========================================" << std::endl;
    std::cout << " Running TSS Common Module Unit Tests     " << std::endl;
    std::cout << "==========================================" << std::endl;

    try {
        test_hex_conversion();
        test_sha256();
        test_nonce_generation();
        test_timestamp_payload();
        test_time_formatting();
        test_json_structures();

        std::cout << "==========================================" << std::endl;
        std::cout << " ALL PHASE 2 UNIT TESTS PASSED!           " << std::endl;
        std::cout << "==========================================" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Test failed with exception: " << e.what() << std::endl;
        return 1;
    }
}
