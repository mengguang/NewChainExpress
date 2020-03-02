#pragma once
#include <cryptopp/integer.h>
#include <cstdint>

#include "Utils.h"
using CryptoPP::SecByteBlock;

class Transaction
{
private:
	SecByteBlock nonce;
	SecByteBlock gas_price;
	SecByteBlock gas_limit;
	SecByteBlock to_address;
	SecByteBlock value;
	SecByteBlock data;
	SecByteBlock chain_id;

	static uint32_t rlp_calculate_data_size(const uint32_t length, const uint8_t* data)
	{
		if (length == 1 && data[0] <= 0x7f)
		{
			return 1;
		}
		else if (length <= 55) // Include length == 0
		{
			return 1 + length;
		}
		else if (length <= 0xff)
		{
			return 2 + length;
		}
		else if (length <= 0xffff)
		{
			return 3 + length;
		}
		else
		{
			return 4 + length;
		}
	}

	static uint32_t rlp_calculate_data_size(SecByteBlock data)
	{
		return rlp_calculate_data_size(data.size(), data.data());
	}

	static uint32_t rlp_write_data(const SecByteBlock& data, uint8_t* result)
	{
		return rlp_write_data(data.size(), data.data(), result);
	}

	static uint32_t rlp_write_data(const uint32_t length, const uint8_t* data, uint8_t* result)
	{
		if (length > 0xFFFFFF)
		{
			return 0;
		}
		uint8_t header_length = 0;
		if (length == 1 && data[0] <= 0x7f)
		{
			header_length = 0;
		}
		else if (length <= 55)
		{
			result[0] = 0x80 + length;
			header_length = 1;
		}
		else if (length <= 0xff)
		{
			result[0] = 0xb7 + 1;
			result[1] = (uint8_t)length;
			header_length = 2;
		}
		else if (length <= 0xffff)
		{
			result[0] = 0xb7 + 2;
			result[1] = length >> 8;
			result[2] = length & 0xff;
			header_length = 3;
		}
		else
		{
			result[0] = 0xb7 + 3;
			result[1] = length >> 16;
			result[2] = length >> 8;
			result[3] = length & 0xff;
			header_length = 4;
		}
		memcpy(result + header_length, data, length);
		return header_length + length;
	}

	static uint32_t rlp_calc_list_header_size(const uint32_t length)
	{
		if (length > 0xFFFFFF)
		{
			return 0;
		}
		if (length <= 55)
		{
			return 1;
		}
		else if (length <= 0xff)
		{
			return 2;
		}
		else if (length <= 0xffff)
		{
			return 3;
		}
		else
		{
			return 4;
		}
	}

	static uint32_t rlp_write_list_header(const uint32_t length, uint8_t* result)
	{
		if (length > 0xFFFFFF)
		{
			return 0;
		}
		if (length <= 55)
		{
			result[0] = 0xc0 + length;
			return 1;
		}
		else if (length <= 0xff)
		{
			result[0] = 0xf7 + 1;
			result[1] = (uint8_t)length;
			return 2;
		}
		else if (length <= 0xffff)
		{
			result[0] = 0xf7 + 2;
			result[1] = length >> 8;
			result[2] = length & 0xff;
			return 3;
		}
		else
		{
			result[0] = 0xf7 + 3;
			result[1] = length >> 16;
			result[2] = length >> 8;
			result[3] = length & 0xff;
			return 4;
		}
	}

public:
	void set_chain_id(const long chain_id)
	{
		const CryptoPP::Integer _chain_id(chain_id);
		const auto size = _chain_id.MinEncodedSize();
		this->chain_id.resize(size);
		_chain_id.Encode(this->chain_id.data(), size);
	}

	void set_data(const uint8_t* data, const uint32_t length)
	{
		this->data.Assign(data, length);
	}

	void set_value_in_new(const long value_in_new)
	{
		CryptoPP::Integer _value_in_new(value_in_new);
		_value_in_new *= CryptoPP::Integer("1000000000000000000");
		const auto size = _value_in_new.MinEncodedSize();
		this->value.resize(size);
		_value_in_new.Encode(this->value.data(), size);
	}

	void set_to_address(const std::string& hex_to_address)
	{
		this->to_address = hex_to_bin(hex_to_address);
	}

	void set_nonce(const long nonce)
	{
		if (nonce == 0)
		{
			this->nonce.resize(0);
		}
		else
		{
			const CryptoPP::Integer _nonce(nonce);
			const auto size = _nonce.MinEncodedSize();
			this->nonce.resize(size);
			_nonce.Encode(this->nonce.data(), size);
		}
	}

	void set_gas_price(const long gas_price)
	{
		const CryptoPP::Integer _gas_price(gas_price);
		const auto size = _gas_price.MinEncodedSize();
		this->gas_price.resize(size);
		_gas_price.Encode(this->gas_price.data(), size);
	}

	void set_gas_limit(const long gas_limit)
	{
		const CryptoPP::Integer _gas_limit(gas_limit);
		const auto size = _gas_limit.MinEncodedSize();
		this->gas_limit.resize(size);
		_gas_limit.Encode(this->gas_limit.data(), size);
	}

	CryptoPP::SecByteBlock build_unsigned_transaction() const
	{
		CryptoPP::SecByteBlock result;

		uint32_t data_length = 0;
		data_length += rlp_calculate_data_size(this->nonce);
		data_length += rlp_calculate_data_size(this->gas_price);
		data_length += rlp_calculate_data_size(this->gas_limit);
		data_length += rlp_calculate_data_size(this->to_address);
		data_length += rlp_calculate_data_size(this->value);
		data_length += rlp_calculate_data_size(this->data);
		data_length += rlp_calculate_data_size(this->chain_id);
		data_length += rlp_calculate_data_size(0, nullptr);
		data_length += rlp_calculate_data_size(0, nullptr);

		const auto total_length = data_length + rlp_calc_list_header_size(data_length);
		result.resize(total_length);

		//start to write data to result.
		uint32_t data_offset = 0;
		data_offset += rlp_write_list_header(data_length, result.data());
		// CryptoPP::Integer i_nonce(nonce.data(), nonce.size());
		// if (i_nonce == 0)
		// {
		// 	data_offset += rlp_write_data(0, nullptr, result.data() + data_offset);
		// }
		// else
		// {
		// 	data_offset += rlp_write_data(this->nonce, result.data() + data_offset);
		// }
		data_offset += rlp_write_data(this->nonce, result.data() + data_offset);
		data_offset += rlp_write_data(this->gas_price, result.data() + data_offset);
		data_offset += rlp_write_data(this->gas_limit, result.data() + data_offset);
		data_offset += rlp_write_data(this->to_address, result.data() + data_offset);
		data_offset += rlp_write_data(this->value, result.data() + data_offset);
		data_offset += rlp_write_data(this->data, result.data() + data_offset);
		data_offset += rlp_write_data(this->chain_id, result.data() + data_offset);
		data_offset += rlp_write_data(0, nullptr, result.data() + data_offset);
		data_offset += rlp_write_data(0, nullptr, result.data() + data_offset);

		(void)data_offset;

		return result;
	}
};
