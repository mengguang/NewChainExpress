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
	long nonce_latest{};
	long nonce_pending{};
	long gas_price{};
	long gas_limit{};
	long balance_in_new{};
	long id{};
public:
	newchain_api_express(std::string _host, int _port, std::string _from_address)
		: host(std::move(_host)), port(_port), from_address(std::move(_from_address)),
		  chain_id(0), nonce_latest(0), nonce_pending(0), gas_price(0), gas_limit(30000), balance_in_new(0), id(0)
	{
	}

	auto get_chain_id() const
	{
		return chain_id;
	}

	auto get_nonce_latest() const
	{
		return nonce_latest;
	}

	auto get_nonce_pending() const
	{
		return nonce_pending;
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

	std::string post_request(const std::string& request_json) const
	{
		httplib::Client cli(host, port);
		cli.set_read_timeout(10, 0);
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
		std::cout << "Base info: " << std::endl;
		std::cout << "chain id: " << chain_id << std::endl;
		std::cout << "nonce latest: " << nonce_latest << std::endl;
		std::cout << "nonce pending: " << nonce_pending << std::endl;
		std::cout << "gas price: " << gas_price << std::endl;
		std::cout << "balance in NEW: " << balance_in_new << std::endl;
	}

	void get_base_info()
	{
		DynamicJsonDocument doc_request(4096);

		doc_request["jsonrpc"] = "2.0";
		doc_request["method"] = "newton_getBaseInfo";
		auto params = doc_request.createNestedObject("params");
		params["address"] = std::string("0x") + from_address;
		doc_request["id"] = id++;

		std::string request_json;
		serializeJson(doc_request, request_json);
		std::cout << request_json << std::endl;
		auto response_json = post_request(request_json);

		DynamicJsonDocument doc_response(4096);
		deserializeJson(doc_response, response_json);
		std::cout << response_json << std::endl;
		//const char* jsonrpc = doc_response["jsonrpc"]; // "2.0"
		//int id = doc_response["id"]; // 1

		JsonObject result = doc_response["result"];
		if (!result)
		{
			throw std::exception("newton_getBaseInfo response error.");
		}
		const char* result_nonce_latest = result["nonceLatest"]; // "0x4df"
		const char* result_nonce_pending = result["noncePending"]; // "0x4df"
		const char* result_gasPrice = result["gasPrice"]; // "0x64"
		int result_networkID = result["networkID"]; // 1007
		const char* result_balance = result["balance"]; // "0x32b6fbe3b559ae26fceaf1"

		if (result_nonce_latest)
		{
			nonce_latest = std::stol(result_nonce_latest, nullptr, 16);
		}
		if (result_nonce_pending)
		{
			nonce_pending = std::stol(result_nonce_pending, nullptr, 16);
		}
		if (result_gasPrice)
		{
			gas_price = std::stol(result_gasPrice, nullptr, 16);
		}
		chain_id = result_networkID;

		CryptoPP::Integer balance(result_balance);
		balance /= CryptoPP::Integer("1000000000000000000");
		balance_in_new = balance.ConvertToLong();
	}

	void send_transaction(const SecByteBlock& unsigned_transaction, const SecByteBlock& signature, const int wait = 1)
	{
		DynamicJsonDocument doc_request(4096);

		doc_request["jsonrpc"] = "2.0";
		doc_request["method"] = "newton_sendTransaction";

		JsonObject method_params = doc_request.createNestedObject("params");

		//JsonObject method_params = params.createNestedObject();
		method_params["from"] = std::string("0x") + from_address;
		method_params["tx"] = std::string("0x") + bin_to_hex(unsigned_transaction);
		method_params["signature"] = std::string("0x") + bin_to_hex(signature);
		method_params["wait"] = wait;
		//(void)params.add(1);
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
		if (result)
		{
			std::cout << "tx hash: " << result << std::endl;
		}
	}
};
