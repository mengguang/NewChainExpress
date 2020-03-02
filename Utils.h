#pragma once

#include <cryptopp/secblock.h>

using CryptoPP::SecByteBlock;
using std::string;

bool string_equals_ci(const string& a, const string& b);
string read_file(const string& filename);
SecByteBlock hex_to_bin(const string& encoded);
string bin_to_hex(const SecByteBlock& decoded);
