// server.cpp
// Simple threaded TLS file server with AUTH, LIST, GET, PUT, QUIT.
// Build: g++ -std=c++17 server.cpp -lssl -lcrypto -lpthread -o server

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <filesystem>
#include <unordered_map>
#include <openssl/rand.h>
#include <openssl/evp.h>


namespace fs = std::filesystem;

const std::string SHARED_DIR = "shared_files";
const std::string USERS_DB = "users.db";
const int PBKDF2_ITER = 200000;
const int SALT_LEN = 16;
const size_t CHUNK = 64 * 1024;

std::mutex users_mutex;

// Helper: hex encode/decode
std::string to_hex(const std::vector<unsigned char>& v) {
    std::ostringstream oss;
    for (unsigned char c : v) oss << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    return oss.str();
}
std::vector<unsigned char> from_hex(const std::string& s) {
    std::vector<unsigned char> out;
    out.reserve(s.size()/2);
    for (size_t i=0;i+1<s.size(); i+=2) {
        unsigned int byte;
        std::istringstream iss(s.substr(i,2));
        iss >> std::hex >> byte;
        out.push_back((unsigned char)byte);
    }
    return out;
}

// PBKDF2 hash
bool pbkdf2_hash(const std::string& password, const std::vector<unsigned char>& salt, int iter, std::vector<unsigned char>& out_key) {
    out_key.resize(32); // SHA256
    if (!PKCS5_PBKDF2_HMAC(password.c_str(), (int)password.size(),
                           salt.data(), (int)salt.size(), iter,
                           EVP_sha256(), (int)out_key.size(), out_key.data())) {
        return false;
    }
    return true;
}

// Users DB format (text): username:salthex:hashhex\n
bool load_users(std::unordered_map<std::string, std::pair<std::string,std::string>>& users) {
    std::lock_guard<std::mutex> lk(users_mutex);
    users.clear();
    std::ifstream f(USERS_DB);
    if (!f.good()) return true; // no users yet
    std::string line;
    while (std::getline(f,line)) {
        if(line.empty()) continue;
        auto p1 = line.find(':');
        auto p2 = line.find(':', p1+1);
        if (p1==std::string::npos || p2==std::string::npos) continue;
        std::string user = line.substr(0,p1);
        std::string salthex = line.substr(p1+1, p2-p1-1);
        std::string hashhex = line.substr(p2+1);
        users[user] = {salthex, hashhex};
    }
    return true;
}

bool add_user_db(const std::string& username, const std::string& password) {
    // generate salt
    std::vector<unsigned char> salt(SALT_LEN);
    if (!RAND_bytes(salt.data(), SALT_LEN)) return false;
    std::vector<unsigned char> key;
    if (!pbkdf2_hash(password, salt, PBKDF2_ITER, key)) return false;
    std::string salthex = to_hex(salt), keyhex = to_hex(key);

    std::lock_guard<std::mutex> lk(users_mutex);
    // append to file
    std::ofstream f(USERS_DB, std::ios::app);
    if (!f.good()) return false;
    f << username << ":" << salthex << ":" << keyhex << "\n";
    return true;
}

// Network read/write wrappers using SSL
ssize_t ssl_write_all(SSL* ssl, const void* buf, size_t len) {
    const unsigned char* p = (const unsigned char*)buf;
    size_t total = 0;
    while (total < len) {
        int w = SSL_write(ssl, p + total, (int)std::min<size_t>(len - total, INT_MAX));
        if (w <= 0) {
            int err = SSL_get_error(ssl, w);
            return -1;
        }
        total += w;
    }
    return (ssize_t)total;
}

ssize_t ssl_read(SSL* ssl, void* buf, size_t len) {
    int r = SSL_read(ssl, buf, (int)len);
    if (r <= 0) return -1;
    return r;
}

bool sendline(SSL* ssl, const std::string& s) {
    std::string t = s + "\n";
    return ssl_write_all(ssl, t.data(), t.size()) == (ssize_t)t.size();
}

bool recvline(SSL* ssl, std::string& out) {
    out.clear();
    char c;
    while (true) {
        int r = SSL_read(ssl, &c, 1);
        if (r <= 0) return false;
        if (c == '\n') break;
        if (c == '\r') continue;
        out.push_back(c);
    }
    return true;
}

bool sanitize_and_resolve(const std::string& filename, fs::path& outpath) {
    fs::path candidate = fs::path(SHARED_DIR) / filename;
    try {
        fs::path abs = fs::canonical(candidate.parent_path()); // ensure parent exists? canonical will throw if not exists
        // create directory if missing (parent)
        fs::create_directories(candidate.parent_path());
        outpath = fs::weakly_canonical(candidate);
        fs::path shared_abs = fs::canonical(SHARED_DIR);
        if (outpath.string().rfind(shared_abs.string(), 0) != 0) {
            return false;
        }
        return true;
    } catch (...) {
        // if canonical fails because file doesn't exist, use lexically_normal on join
        outpath = fs::weakly_canonical(candidate);
        fs::path shared_abs = fs::weakly_canonical(SHARED_DIR);
        if (outpath.string().rfind(shared_abs.string(), 0) != 0) {
            return false;
        }
        return true;
    }
}

void handle_client(SSL* ssl, sockaddr_in addr) {
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    int client_port = ntohs(addr.sin_port);
    std::cout << "[+] conn from " << client_ip << ":" << client_port << std::endl;

    bool authenticated = false;
    std::string username;

    std::unordered_map<std::string,std::pair<std::string,std::string>> users;
    load_users(users);

    try {
        std::string line;
        while (recvline(ssl, line)) {
            if (line.empty()) continue;
            std::istringstream iss(line);
            std::string cmd;
            iss >> cmd;
            std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::toupper);

            if (cmd == "AUTH") {
                std::string user, pass;
                iss >> user;
                std::getline(iss, pass);
                if (!pass.empty() && pass[0]==' ') pass.erase(0,1);
                if (user.empty() || pass.empty()) { sendline(ssl, "ERR Missing username/password"); continue; }
                auto it = users.find(user);
                if (it == users.end()) {
                    sendline(ssl, "ERR Authentication failed");
                    continue;
                }
                std::vector<unsigned char> salt = from_hex(it->second.first);
                std::vector<unsigned char> expected = from_hex(it->second.second);
                std::vector<unsigned char> got;
                if (!pbkdf2_hash(pass, salt, PBKDF2_ITER, got)) {
                    sendline(ssl, "ERR Internal error");
                    continue;
                }
                if (got == expected) {
                    authenticated = true;
                    username = user;
                    sendline(ssl, "OK");
                    std::cout << "[+] " << client_ip << ":" << client_port << " authenticated as " << user << "\n";
                } else {
                    sendline(ssl, "ERR Authentication failed");
                }
            } else if (cmd == "LIST") {
                if (!authenticated) { sendline(ssl, "ERR Not authenticated"); continue;}
                for (auto &p: fs::directory_iterator(SHARED_DIR)) {
                    if (fs::is_regular_file(p.path())) {
                        sendline(ssl, p.path().filename().string());
                    }
                }
                sendline(ssl, "END");
            } else if (cmd == "GET") {
                if (!authenticated) { sendline(ssl, "ERR Not authenticated"); continue;}
                std::string fname;
                std::getline(iss, fname);
                if (!fname.empty() && fname[0]==' ') fname.erase(0,1);
                if (fname.empty()) { sendline(ssl, "ERR Missing filename"); continue;}
                fs::path resolved;
                if (!sanitize_and_resolve(fname, resolved)) { sendline(ssl, "ERR Invalid filename"); continue; }
                if (!fs::exists(resolved) || !fs::is_regular_file(resolved)) { sendline(ssl, "ERR File not found"); continue; }
                uint64_t size = fs::file_size(resolved);
                sendline(ssl, "SIZE " + std::to_string(size));
                std::string ready;
                if (!recvline(ssl, ready) || ready != "READY") { sendline(ssl,"ERR Expected READY"); continue; }
                std::ifstream ifs(resolved, std::ios::binary);
                char buffer[CHUNK];
                uint64_t remaining = size;
                while (remaining > 0) {
                    size_t toread = (size_t)std::min<uint64_t>(CHUNK, remaining);
                    ifs.read(buffer, toread);
                    size_t actually = ifs.gcount();
                    if (actually==0) break;
                    if (ssl_write_all(ssl, buffer, actually) != (ssize_t)actually) break;
                    remaining -= actually;
                }
            } else if (cmd == "PUT") {
                if (!authenticated) { sendline(ssl, "ERR Not authenticated"); continue;}
                std::string fname;
                uint64_t size = 0;
                iss >> fname >> size;
                if (fname.empty() || size==0) { sendline(ssl, "ERR Usage: PUT <filename> <size>"); continue;}
                fs::path resolved;
                if (!sanitize_and_resolve(fname, resolved)) { sendline(ssl, "ERR Invalid filename"); continue; }
                sendline(ssl, "READY");
                fs::create_directories(resolved.parent_path());
                std::ofstream ofs(resolved, std::ios::binary);
                if (!ofs.good()) { sendline(ssl, "ERR Cannot open file for writing"); continue; }
                uint64_t remaining = size;
                char buffer[CHUNK];
                while (remaining > 0) {
                    size_t toread = (size_t)std::min<uint64_t>(CHUNK, remaining);
                    int r = SSL_read(ssl, buffer, (int)toread);
                    if (r <= 0) { sendline(ssl, "ERR Connection lost"); break; }
                    ofs.write(buffer, r);
                    remaining -= r;
                }
                ofs.close();
                if (remaining == 0) sendline(ssl, "OK"); else sendline(ssl, "ERR Incomplete upload");
            } else if (cmd == "QUIT") {
                sendline(ssl, "OK");
                break;
            } else {
                sendline(ssl, "ERR Unknown command");
            }
        }
    } catch (...) {
        std::cerr << "[!] exception handling client\n";
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    std::cout << "[-] connection closed " << client_ip << ":" << client_port << std::endl;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "Usage: server <port> <cert.pem> <key.pem>\n"
                     "Example: server 9000 server.crt server.key\n";
        return 1;
    }
    int port = std::stoi(argv[1]);
    std::string certfile = argv[2];
    std::string keyfile = (argc >= 4) ? argv[3] : argv[2];

    // create shared dir if necessary
    fs::create_directories(SHARED_DIR);

    // ensure users db exists (create default test/test if none)
    {
        std::ifstream f(USERS_DB);
        if (!f.good()) {
            std::cout << "[*] creating default user test/test\n";
            add_user_db("test", "test");
        }
    }

    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) { std::cerr << "Unable to create SSL context\n"; ERR_print_errors_fp(stderr); return 1; }

    if (SSL_CTX_use_certificate_file(ctx, certfile.c_str(), SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "Error loading certificate\n"; ERR_print_errors_fp(stderr); return 1;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, keyfile.c_str(), SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "Error loading key\n"; ERR_print_errors_fp(stderr); return 1;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }
    if (listen(sock, 16) < 0) { perror("listen"); return 1; }
    std::cout << "[+] listening on 0.0.0.0:" << port << " (TLS)\n";

    while (true) {
        sockaddr_in client_addr;
        socklen_t len = sizeof(client_addr);
        int client = accept(sock, (struct sockaddr*)&client_addr, &len);
        if (client < 0) { perror("accept"); continue; }
        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            close(client);
            SSL_free(ssl);
            continue;
        }
        // spawn thread
        std::thread t(handle_client, ssl, client_addr);
        t.detach();
    }

    close(sock);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
}
