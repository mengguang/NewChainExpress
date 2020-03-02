#pragma once
#include <httplib.h>
#include "ArduinoJson-v6.14.1.h"
#include "cryptopp/integer.h"

class newchain_api_express
{
private:
	std::string host{};
	int port{};
	std::string from_address;

	long chain_id;
	long nonce{};
	long gas_price{};
	long gas_limit{};
	long balance_in_new{};
	long id{};
public:
	newchain_api_express(const std::string& _host, int _port, const std::string& _from_address)
		: host(_host), port(_port), from_address(_from_address),
		chain_id(0), nonce(0), gas_price(0), gas_limit(30000), balance_in_new(0), id(0)
	{
	}

	auto get_chain_id() const
	{
		return chain_id;
	}

	auto get_nonce() const
	{
		return nonce;
	}

	auto get_gas_price() const
	{
		return gas_price;
	}

	auto get_gas_limit() const
	{
		return gas_limit;
	}

	auto get_balance_in_new() const
	{
		return balance_in_new;
	}

	std::string post_request(const std::string& request_json)
	{
		httplib::Client cli(host, port);
		auto const res = cli.Post("/", request_json, "application/json");
		if (res)
		{
			if (res->status == 200)
			{
				return res->body;
			}
		}
		throw std::exception("httplib client request failed.");
	}

	void dump_base_info() const
	{
		std::cout << "Base info:" << std::endl;
		std::cout << "chain id:" << chain_id << std::endl;
		std::cout << "gas price:" << gas_price << std::endl;
		std::cout << "balance in NEW:" << balance_in_new << std::endl;
	}

	void get_base_info()
	{
		DynamicJsonDocument doc_request(4096);

		doc_request["jsonrpc"] = "2.0";
		doc_request["method"] = "newton_getBaseInfo";
		JsonArray params = doc_request.createNestedArray("params");
		params.add(std::string("0x") + from_address);
		doc_request["id"] = id++;

		std::string request_json;
		serializeJson(doc_request, request_json);
		auto response_json = post_request(request_json);

		DynamicJsonDocument doc_response(4096);
		deserializeJson(doc_response, response_json);

		//const char* jsonrpc = doc_response["jsonrpc"]; // "2.0"
		//int id = doc_response["id"]; // 1

		JsonObject result = doc_response["result"];
		const char* result_nonce = result["nonce"]; // "0x4df"
		const char* result_gasPrice = result["gasPrice"]; // "0x64"
		int result_networkID = result["networkID"]; // 1007
		const char* result_balance = result["balance"]; // "0x32b6fbe3b559ae26fceaf1"

		if (result_nonce)
		{
			nonce = std::stol(result_nonce, nullptr, 16);
		}
		if (result_gasPrice)
		{
			gas_price = std::stol(result_gasPrice, nullptr, 16);
		}
		chain_id = result_networkID;
		// auto bin_balance = hex_to_bin(result_balance);
		// CryptoPP::Integer balance(bin_balance.data(), bin_balance.size());
		CryptoPP::Integer balance(result_balance);
		balance /= CryptoPP::Integer("1000000000000000000");
		balance_in_new = balance.ConvertToLong();
	}

	void send_transaction(const SecByteBlock& unsigned_transaction, const SecByteBlock& signature)
	{
		DynamicJsonDocument doc_request(4096);

		doc_request["jsonrpc"] = "2.0";
		doc_request["method"] = "newton_sendTransaction";

		JsonArray params = doc_request.createNestedArray("params");

		JsonObject params_0 = params.createNestedObject();
		params_0["from"] = std::string("0x") + from_address;
		params_0["message"] = std::string("0x") + bin_to_hex(unsigned_transaction);
		params_0["signature"] = std::string("0x") + bin_to_hex(signature);
		(void)params.add(1);
		doc_request["id"] = id++;

		std::string request_json;
		serializeJson(doc_request, request_json);
		std::cout << request_json << std::endl;
		auto response_json = post_request(request_json);

		DynamicJsonDocument doc_response(4096);
		deserializeJson(doc_response, response_json);
		std::cout << response_json << std::endl;
		//const char* jsonrpc = doc_response["jsonrpc"]; // "2.0"
		//int id = doc_response["id"]; // 67
		const char* result = doc_response["result"];
		// "0xf172da87fc390f9b57205fd5ebb6bf2a716635951dffde28fe93be7ad2ec1b77"
		std::cout << "tx hash: " << result << std::endl;
	}
};
