// Copyright (c) 2017 Pieter Wuille
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Bech32 is a string encoding format used in newer address types.
// The output consists of a human-readable part (alphanumeric), a
// separator character (1), and a base32 data section, the last
// 6 characters of which are a checksum.
//
// For more information, see BIP 173.

#include <stdint.h>
#include <string>
#include <vector>

namespace bech32
{

/** Encode a Bech32 string. Returns the empty string in case of failure. */
std::string Encode(const std::string& hrp, const std::vector<uint8_t>& values);

/** Decode a Bech32 string. Returns (hrp, data). Empty hrp means failure.
 *
 *  CONSENSUS-FROZEN (FreeBank): withdrawal destinations are decoded with this
 *  function (via DecodeDestination(..., fMainchain=true)) when a withdrawal
 *  bundle is built and verified, and v0.2.13+ stores bech32 withdrawal
 *  destinations as BIP173-checksummed "carrier" strings (mainchainaddress.h).
 *  Never upgrade this function to BIP350 or otherwise change what it accepts:
 *  stored rows would stop decoding and the chain would split. Use DecodeEx /
 *  EncodeM below for BIP350 (bech32m) work. */
std::pair<std::string, std::vector<uint8_t>> Decode(const std::string& str);

/** Which checksum a bech32-family string carries (BIP173 bech32 or BIP350 bech32m). */
enum class Encoding {
    INVALID,
    BECH32,  //!< BIP173 checksum constant 1
    BECH32M, //!< BIP350 checksum constant 0x2bc830a3
};

/** Encode with the BIP350 (bech32m) checksum. Returns the empty string in case of failure. */
std::string EncodeM(const std::string& hrp, const std::vector<uint8_t>& values);

struct DecodeResult {
    Encoding encoding;          //!< INVALID on any failure
    std::string hrp;            //!< lower-cased; empty on failure
    std::vector<uint8_t> data;  //!< 5-bit values without the checksum
    DecodeResult() : encoding(Encoding::INVALID) {}
};

/** Decode a bech32 OR bech32m string and report which checksum it carries.
 *  Same syntax rules as Decode (<= 90 chars, no mixed case, charset). Additive:
 *  Decode above is unchanged. Port of Core 0.21's bech32::Decode. */
DecodeResult DecodeEx(const std::string& str);

} // namespace bech32
