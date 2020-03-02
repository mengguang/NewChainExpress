#include "Utils.h"

#include <fstream>
#include "cryptopp/hex.h"
#include "cryptopp/secblock.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/modes.h"
#include "cryptopp/eccrypto.h"

bool string_equals_ci(const std::string& a, const std::string& b)
{
	const auto sz = a.size();
	if (b.size() != sz)
	{
		return false;
	}

	for (unsigned int i = 0; i < sz; ++i)
	{
		if (tolower(a[i]) != tolower(b[i]))
		{
			return false;
		}
	}
	return true;
}

std::string read_file(const std::string& filename)
{
	std::ifstream ifs(filename);
	std::string content((std::istreambuf_iterator<char>(ifs)),
	                    (std::istreambuf_iterator<char>()));
	return content;
}

SecByteBlock hex_to_bin(const std::string& encoded)
{
	using namespace std;
	using namespace CryptoPP;
	SecByteBlock decoded;

	HexDecoder decoder;
	decoder.Put((byte*)encoded.data(), encoded.size());
	decoder.MessageEnd();

	const auto size = decoder.MaxRetrievable();
	if (size && size <= SIZE_MAX)
	{
		decoded.resize((unsigned int)size);
		decoder.Get(decoded.data(), decoded.size());
	}
	return decoded;
}

std::string bin_to_hex(const SecByteBlock& decoded)
{
	using namespace std;
	using namespace CryptoPP;
	string encoded;

	HexEncoder encoder;
	encoder.Put(decoded.data(), decoded.size());
	encoder.MessageEnd();

	const auto size = encoder.MaxRetrievable();
	if (size)
	{
		encoded.resize((unsigned int)size);
		encoder.Get((byte*)encoded.data(), encoded.size());
	}
	return encoded;
}
