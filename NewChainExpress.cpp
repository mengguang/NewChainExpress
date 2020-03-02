#include <iostream>
#include "ArduinoJson-v6.14.1.h"
#include "cryptopp/scrypt.h"
#include "cryptopp/secblock.h"
#include "cryptopp/keccak.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "cryptopp/eccrypto.h"
#include "cryptopp/oids.h"
#include "cryptopp/osrng.h"
#include "RLP.h"
#include "newchain_api_express.h"

using CryptoPP::SecByteBlock;

const char* hex_to_address = "A4d79e4efECD77ba0E1b6551388A7d7C0778824a";

SecByteBlock public_key_to_address(const CryptoPP::DL_Keys_ECDSA<CryptoPP::ECP>::PublicKey& publicKey)
{
	SecByteBlock public_key_binary(64);

	publicKey.GetPublicElement().x.Encode(public_key_binary.data(), 32);
	publicKey.GetPublicElement().y.Encode(public_key_binary.data() + 32, 32);

	CryptoPP::Keccak_256 ah;
	SecByteBlock full_address_hash(ah.DigestSize());
	ah.Update(public_key_binary.data(), public_key_binary.size());
	ah.Final(full_address_hash.data());
	SecByteBlock address_binary(20);
	address_binary.Assign(full_address_hash.data() + 12, 20);
	return address_binary;
}

std::string get_hex_address_from_keystore_text(const std::string& keystore_json)
{
	DynamicJsonDocument doc(4096);
	deserializeJson(doc, keystore_json);
	return doc["address"].as<std::string>();
}

CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::Keccak_256>::PrivateKey
get_private_key_from_keystore_text(const std::string& keystore_json)
{
	using namespace std;
	using namespace CryptoPP;
	DynamicJsonDocument doc(4096);
	deserializeJson(doc, keystore_json);

	//const char* address = doc["address"];
	//const char* id = doc["id"]; // "a6792603-243a-4163-870c-aad3272fb383"
	//int version = doc["version"]; // 3

	JsonObject crypto = doc["crypto"];
	//const char* crypto_cipher = crypto["cipher"]; // "aes-128-ctr"
	const char* crypto_ciphertext = crypto["ciphertext"];

	const char* crypto_cipherparams_iv = crypto["cipherparams"]["iv"];

	//const char* crypto_kdf = crypto["kdf"]; // "scrypt"

	JsonObject crypto_kdfparams = crypto["kdfparams"];
	int crypto_kdfparams_dklen = crypto_kdfparams["dklen"]; // 32
	long crypto_kdfparams_n = crypto_kdfparams["n"]; // 262144
	int crypto_kdfparams_p = crypto_kdfparams["p"]; // 1
	int crypto_kdfparams_r = crypto_kdfparams["r"]; // 8
	const char* crypto_kdfparams_salt = crypto_kdfparams["salt"];

	const char* crypto_mac = crypto["mac"];

	const std::string password = "1234qwer";

	SecByteBlock derived_key(crypto_kdfparams_dklen);

	auto crypto_kdfparams_salt_bin = hex_to_bin(crypto_kdfparams_salt);
	CryptoPP::Scrypt scrypt;
	auto n = scrypt.DeriveKey(derived_key.data(), derived_key.size(),
	                          (CryptoPP::byte*)password.data(), password.size(),
	                          crypto_kdfparams_salt_bin.data(), crypto_kdfparams_salt_bin.size(),
	                          crypto_kdfparams_n,
	                          crypto_kdfparams_r,
	                          crypto_kdfparams_p
	);
	(void)n;

	auto crypto_ciphertext_bin = hex_to_bin(crypto_ciphertext);

	CryptoPP::Keccak_256 hash;
	SecByteBlock calced_mac(hash.DigestSize());
	hash.Update(derived_key.data() + 16, 16);
	hash.Update(crypto_ciphertext_bin.data(), crypto_ciphertext_bin.size());
	hash.Final(calced_mac.data());

	auto calced_mac_hex = bin_to_hex(calced_mac);
	std::cout << calced_mac_hex << endl;

	if (string_equals_ci(calced_mac_hex, crypto_mac) == false)
	{
		std::cout << "password is wrong, please try again." << std::endl;
		throw std::exception("password is wrong");
	}

	auto crypto_cipherparams_iv_bin = hex_to_bin(crypto_cipherparams_iv);

	auto ctrDecryption = CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption(derived_key.data(), 16,
	                                                                   crypto_cipherparams_iv_bin.data());

	SecByteBlock secret_key(crypto_ciphertext_bin.size());
	ctrDecryption.ProcessData(secret_key.data(), crypto_ciphertext_bin.data(), crypto_ciphertext_bin.size());
	CryptoPP::Integer k;
	k.Decode(secret_key.data(), secret_key.size());
	ECDSA<ECP, Keccak_256>::PrivateKey privateKey;
	privateKey.Initialize(CryptoPP::ASN1::secp256r1(), k);
	return privateKey;
}

int main()
{
	using namespace std;
	using namespace CryptoPP;
	try
	{
		auto file_name = string("c:/tmp/0x769E219bdfa1CBc8C935B903B12Efe4379dCB1BE.json");
		auto keystore_json = read_file(file_name);
		cout << keystore_json << endl;

		auto privateKey = get_private_key_from_keystore_text(keystore_json);
		ECDSA<ECP, Keccak_256>::PublicKey publicKey;
		privateKey.MakePublicKey(publicKey);

		auto address_binary = public_key_to_address(publicKey);
		auto address_hex = bin_to_hex(address_binary);
		cout << address_hex << endl;

		auto address = get_hex_address_from_keystore_text(keystore_json);
		if (string_equals_ci(address_hex, address) == false)
		{
			cout << "address mismatch, please try again." << endl;
			return 1;
		}

		newchain_api_express api("testnet.cloud.diynova.com", 8888, address_hex);
		api.get_base_info();
		api.dump_base_info();

		Transaction tx;
		tx.set_nonce(api.get_nonce());
		tx.set_gas_price(api.get_gas_price());
		tx.set_gas_limit(api.get_gas_limit());
		tx.set_to_address(hex_to_address);
		tx.set_value_in_new(10);
		tx.set_chain_id(api.get_chain_id());
		auto unsigned_tx = tx.build_unsigned_transaction();
		auto hex_unsigned_tx = bin_to_hex(unsigned_tx);
		cout << hex_unsigned_tx << endl;

		ECDSA<ECP, Keccak_256>::Signer signer(privateKey);
		SecByteBlock signature(signer.MaxSignatureLength());
		AutoSeededRandomPool prng;
		auto signature_length = signer.SignMessage(prng,
		                                           unsigned_tx.data(), unsigned_tx.size(),
		                                           signature.data());
		cout << bin_to_hex(signature) << endl;
		cout << signature_length << endl;
		ECDSA<ECP, Keccak_256>::Verifier verifier(publicKey);
		auto result = verifier.VerifyMessage(unsigned_tx.data(), unsigned_tx.size(),
		                                     signature.data(), signature.size());
		cout << "verify result: " << result << endl;

		api.send_transaction(unsigned_tx, signature);

		cout << "All works fine!" << endl;
		return 0;
	}
	catch (std::exception& e)
	{
		cerr << e.what() << endl;
		return 1;
	}
}
