// client_ui.cpp
// Compile: g++ -std=c++17 client_ui.cpp -lssl -lcrypto -o client_ui

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;
const size_t CHUNK = 64*1024;

bool sendline(SSL* ssl, const std::string& s) {
    std::string t = s + "\n";
    int written = SSL_write(ssl, t.data(), (int)t.size());
    return written == (int)t.size();
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

void do_list(SSL* ssl) {
    sendline(ssl, "LIST");
    std::string line;
    std::cout << "---- Files on server ----\n";
    while (recvline(ssl, line)) {
        if (line == "END") break;
        std::cout << "  " << line << "\n";
    }
    std::cout << "-------------------------\n";
}

void do_get(SSL* ssl) {
    std::string fname;
    std::cout << "Enter filename to download: ";
    std::getline(std::cin, fname);
    if (fname.empty()) return;
    sendline(ssl, "GET " + fname);
    std::string res;
    if (!recvline(ssl, res)) { std::cerr << "No response\n"; return; }
    if (res.rfind("ERR",0)==0) { std::cerr << res << "\n"; return; }
    if (res.rfind("SIZE ",0)!=0) { std::cerr << "Unexpected: " << res << "\n"; return; }
    uint64_t size = std::stoull(res.substr(5));
    sendline(ssl, "READY");
    std::string out = fname;
    std::ofstream ofs(out, std::ios::binary);
    if (!ofs.good()) { std::cerr << "Cannot open " << out << "\n"; return; }
    uint64_t remaining = size;
    std::vector<char> buf(CHUNK);
    while (remaining > 0) {
        int r = SSL_read(ssl, buf.data(), (int)std::min<uint64_t>(CHUNK, remaining));
        if (r <= 0) { std::cerr << "Connection lost\n"; break; }
        ofs.write(buf.data(), r);
        remaining -= r;
    }
    ofs.close();
    if (remaining==0) std::cout << "[+] Downloaded " << out << " (" << size << " bytes)\n";
    else std::cerr << "Incomplete download\n";
}

void do_put(SSL* ssl) {
    std::string local;
    std::cout << "Enter local file path to upload: ";
    std::getline(std::cin, local);
    if (local.empty()) return;
    if (!fs::exists(local) || !fs::is_regular_file(local)) { std::cerr << "Local file not found\n"; return; }
    uint64_t size = fs::file_size(local);
    std::string remote = fs::path(local).filename().string();
    sendline(ssl, "PUT " + remote + " " + std::to_string(size));
    std::string r;
    if (!recvline(ssl, r)) { std::cerr << "No response\n"; return; }
    if (r != "READY") { std::cerr << "Server: " << r << "\n"; return; }
    std::ifstream ifs(local, std::ios::binary);
    std::vector<char> buf(CHUNK);
    while (ifs.good()) {
        ifs.read(buf.data(), CHUNK);
        std::streamsize got = ifs.gcount();
        if (got <= 0) break;
        int w = SSL_write(ssl, buf.data(), (int)got);
        if (w <= 0) { std::cerr << "Write error\n"; return; }
    }
    ifs.close();
    if (!recvline(ssl, r)) { std::cerr << "No final response\n"; return; }
    std::cout << "Server: " << r << std::endl;
}

int main() {
    std::string host;
    int port;
    std::string user, pass;

    std::cout << "Server host (default 127.0.0.1): ";
    std::getline(std::cin, host); if (host.empty()) host = "127.0.0.1";
    std::cout << "Server port (default 9000): ";
    std::string sport; std::getline(std::cin, sport);
    port = sport.empty() ? 9000 : std::stoi(sport);
    std::cout << "Username: "; std::getline(std::cin, user);
    std::cout << "Password: "; std::getline(std::cin, pass);

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) { ERR_print_errors_fp(stderr); return 1; }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) <= 0) {
        struct hostent* he = gethostbyname(host.c_str());
        if (!he) { std::cerr << "host lookup failed\n"; return 1; }
        addr.sin_addr = *(struct in_addr*)he->h_addr;
    }

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) { perror("connect"); return 1; }

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) { ERR_print_errors_fp(stderr); return 1; }

    sendline(ssl, "AUTH " + user + " " + pass);
    std::string r;
    if (!recvline(ssl, r)) { std::cerr << "No response\n"; return 1; }
    std::cout << "AUTH -> " << r << std::endl;
    if (r.rfind("OK",0) != 0) { std::cerr << "Authentication failed\n"; SSL_shutdown(ssl); SSL_free(ssl); close(sock); return 1; }
    std::cout << "[+] Authenticated. Connected to " << host << ":" << port << "\n";

    while (true) {
        std::cout << "\n--- MENU ---\n1. List files\n2. Download file\n3. Upload file\n4. Quit\nChoice: ";
        std::string choice; std::getline(std::cin, choice);
        if (choice=="1") do_list(ssl);
        else if (choice=="2") do_get(ssl);
        else if (choice=="3") do_put(ssl);
        else if (choice=="4") { sendline(ssl,"QUIT"); if (recvline(ssl,r)) std::cout<<r<<"\n"; break; }
        else std::cout << "Invalid choice\n";
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    return 0;
}
