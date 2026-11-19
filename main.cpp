// CodeAlpha C++ Internship - Task 2: Login and Registration System
//
// * One file per user inside the "users/" folder.
// * Passwords are never stored in plain text: a random salt + SHA-256
//   (iterated 10,000 times) hash is saved instead.
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#ifdef _WIN32
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

using namespace std;
namespace fs = std::filesystem;

const string USERS_DIR = "users";
const int ITERATIONS = 10000;

// ------------------------------------------------------------------
// SHA-256
// ------------------------------------------------------------------
namespace sha256 {
const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

string hash(const string& input) {
    uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

    vector<uint8_t> msg(input.begin(), input.end());
    uint64_t bitLen = (uint64_t)msg.size() * 8;
    msg.push_back(0x80);
    while (msg.size() % 64 != 56) msg.push_back(0);
    for (int i = 7; i >= 0; i--) msg.push_back((uint8_t)(bitLen >> (i * 8)));

    for (size_t chunk = 0; chunk < msg.size(); chunk += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; i++)
            w[i] = (msg[chunk + i * 4] << 24) | (msg[chunk + i * 4 + 1] << 16) |
                   (msg[chunk + i * 4 + 2] << 8) | msg[chunk + i * 4 + 3];
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 64; i++) {
            uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = hh + S1 + ch + K[i] + w[i];
            uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + maj;
            hh = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }

    static const char* hex = "0123456789abcdef";
    string out;
    for (int i = 0; i < 8; i++)
        for (int j = 7; j >= 0; j--) out += hex[(h[i] >> (j * 4)) & 0xF];
    return out;
}
}  // namespace sha256

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------
string generateSalt() {
    static const char* hex = "0123456789abcdef";
    random_device rd;
    string salt;
    for (int i = 0; i < 16; i++) salt += hex[rd() % 16];
    return salt;
}

string hashPassword(const string& password, const string& salt) {
    string digest = salt + password;
    for (int i = 0; i < ITERATIONS; i++) digest = sha256::hash(digest + salt);
    return digest;
}

string toLower(string s) {
    for (auto& c : s) c = (char)tolower((unsigned char)c);
    return s;
}

string userFilePath(const string& username) {
    return USERS_DIR + "/" + toLower(username) + ".txt";
}

// Reads a line without echoing characters (so the password stays hidden).
string readHidden(const string& prompt) {
    cout << prompt << flush;
    string result;
#ifdef _WIN32
    int ch;
    while ((ch = _getch()) != '\r' && ch != '\n') {
        if (ch == '\b') {
            if (!result.empty()) result.pop_back();
        } else {
            result += (char)ch;
        }
    }
#else
    termios oldt{};
    tcgetattr(STDIN_FILENO, &oldt);
    termios newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    getline(cin, result);
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif
    cout << "\n";
    return result;
}

// ------------------------------------------------------------------
// Validation
// ------------------------------------------------------------------
string validateUsername(const string& u) {
    if (u.size() < 3 || u.size() > 20)
        return "Username must be 3-20 characters long.";
    for (char c : u)
        if (!isalnum((unsigned char)c) && c != '_')
            return "Username can only contain letters, numbers and underscore.";
    return "";
}

string validatePassword(const string& p) {
    if (p.size() < 6) return "Password must be at least 6 characters long.";
    bool letter = false, digit = false;
    for (char c : p) {
        if (isalpha((unsigned char)c)) letter = true;
        if (isdigit((unsigned char)c)) digit = true;
    }
    if (!letter || !digit) return "Password must contain at least one letter and one number.";
    return "";
}

// ------------------------------------------------------------------
// Registration & Login
// ------------------------------------------------------------------
bool registerUser(const string& username, const string& password, string& message) {
    string err = validateUsername(username);
    if (err.empty()) err = validatePassword(password);
    if (!err.empty()) { message = err; return false; }

    fs::create_directories(USERS_DIR);
    if (fs::exists(userFilePath(username))) {
        message = "Username already exists. Please choose another one.";
        return false;
    }

    string salt = generateSalt();
    ofstream file(userFilePath(username));
    if (!file) { message = "Error: could not save user data."; return false; }
    file << username << "\n" << salt << "\n" << hashPassword(password, salt) << "\n";
    message = "Registration successful! You can now log in.";
    return true;
}

bool loginUser(const string& username, const string& password, string& message) {
    ifstream file(userFilePath(username));
    if (!file) { message = "Login failed: user not found."; return false; }

    string storedName, salt, storedHash;
    getline(file, storedName);
    getline(file, salt);
    getline(file, storedHash);

    if (hashPassword(password, salt) == storedHash) {
        message = "Login successful. Welcome, " + storedName + "!";
        return true;
    }
    message = "Login failed: incorrect password.";
    return false;
}

// ------------------------------------------------------------------
int main(int argc, char** argv) {
    if (argc > 1 && string(argv[1]) == "--selftest") {  // verifies SHA-256
        cout << sha256::hash("abc") << "\n";
        return 0;
    }

    while (true) {
        cout << "\n==============================\n";
        cout << "   LOGIN & REGISTRATION SYSTEM\n";
        cout << "==============================\n";
        cout << " 1. Register\n 2. Login\n 3. Exit\n";
        cout << "Choose an option: ";

        string choice;
        if (!getline(cin, choice)) break;

        if (choice == "1") {
            string username, message;
            cout << "Choose a username: ";
            getline(cin, username);
            string pass = readHidden("Choose a password: ");
            string confirm = readHidden("Confirm password: ");
            if (pass != confirm) {
                cout << "[Error] Passwords do not match.\n";
                continue;
            }
            bool ok = registerUser(username, pass, message);
            cout << (ok ? "[Success] " : "[Error] ") << message << "\n";
        } else if (choice == "2") {
            string username, message;
            cout << "Username: ";
            getline(cin, username);
            string pass = readHidden("Password: ");
            bool ok = loginUser(username, pass, message);
            cout << (ok ? "[Success] " : "[Error] ") << message << "\n";
        } else if (choice == "3") {
            cout << "Goodbye!\n";
            break;
        } else {
            cout << "[Error] Invalid option. Enter 1, 2 or 3.\n";
        }
    }
    return 0;
}
