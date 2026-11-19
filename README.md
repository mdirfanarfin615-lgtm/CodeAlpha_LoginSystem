# CodeAlpha_LoginSystem

A console-based **Login and Registration System** written in C++ as part of the **CodeAlpha C++ Programming Internship (Task 2)**.

## Features
- Register with a **username** and **password** (with confirmation)
- Input validation (username: 3-20 chars, letters/numbers/underscore; password: min 6 chars with a letter and a number)
- Duplicate username check
- Credentials stored in a file, **one file per user**, inside the `users/` folder
- Passwords are **never stored in plain text** - a random salt + SHA-256 (10,000 iterations) hash is saved
- Password input is hidden while typing
- Clear success and error messages for both registration and login

## Build & Run
```bash
g++ -std=c++17 -o login main.cpp
./login         # Windows: login.exe
```

## Stored File Format (`users/<username>.txt`)
```
username
salt
password_hash
```

## Concepts Used
File handling (`fstream`, `std::filesystem`), hashing (own SHA-256 implementation), functions, validation, string handling.

> Note: This is an educational project. For production systems use a vetted library (e.g. bcrypt/Argon2).
