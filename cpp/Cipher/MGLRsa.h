//
//  MGLRsa.hpp
//  react-native-quick-crypto
//
//  Created by Oscar on 22.06.22.
//

#ifndef MGLRsa_hpp
#define MGLRsa_hpp

#include <jsi/jsi.h>

#include <memory>
#include <optional>
#include <utility>

#include "MGLKeys.h"
#ifdef ANDROID
#include "Utils/MGLUtils.h"
#else
#include "MGLUtils.h"
#endif

namespace margelo {

namespace jsi = facebook::jsi;

// TODO: keep in in sync with JS side (src/rsa.ts)
enum RSAKeyVariant {
  kKeyVariantRSA_SSA_PKCS1_v1_5,
  kKeyVariantRSA_PSS,
  kKeyVariantRSA_OAEP
};

// On node there is a complete madness of structs/classes that encapsulate and
// initialize the data in a generic manner this is to be later be used to
// generate the keys in a thread-safe manner (I think) I'm however too dumb and
// after ~4hrs I have given up on trying to replicate/extract the important
// parts For now I'm storing a single config param, a generic abstraction is
// necessary for more schemes. this struct is just a very simplified version
// meant to carry information around
struct RsaKeyPairGenConfig {
  PublicKeyEncodingConfig public_key_encoding;
  PrivateKeyEncodingConfig private_key_encoding;
  ManagedEVPPKey key;

  KeyVariant variant;
  unsigned int modulus_bits;
  unsigned int exponent;

  // The following options are used for RSA-PSS. If any of them are set, a
  // RSASSA-PSS-params sequence will be added to the key.
  const EVP_MD* md = nullptr;
  const EVP_MD* mgf1_md = nullptr;
  int saltlen = -1;
};

RsaKeyPairGenConfig prepareRsaKeyGenConfig(jsi::Runtime& runtime,
                                         const jsi::Value* arguments);

std::pair<jsi::Value, jsi::Value> generateRsaKeyPair(
    jsi::Runtime& runtime, std::shared_ptr<RsaKeyPairGenConfig> config);

jsi::Value ExportJWKRsaKey(jsi::Runtime &rt,
                           std::shared_ptr<KeyObjectData> key,
                           jsi::Object &target);

std::shared_ptr<KeyObjectData> ImportJWKRsaKey(jsi::Runtime &rt,
                                               jsi::Object &jwk);

jsi::Value GetRsaKeyDetail(jsi::Runtime &rt,
                           std::shared_ptr<KeyObjectData> key);

struct RsaKeyExportConfig final {
  WebCryptoKeyFormat format;
  std::shared_ptr<KeyObjectData> key_;
  KeyVariant variant;
};

class RsaKeyExport {
 public:
  bool GetParamsFromJS(jsi::Runtime &rt, const jsi::Value *args);
  WebCryptoKeyExportStatus DoExport(ByteSource* out);
 private:
  RsaKeyExportConfig params_;
};

struct RSACipherConfig final {
  WebCryptoCipherMode mode;
  std::shared_ptr<KeyObjectData> key;
  ByteSource data;
  RSAKeyVariant variant;
  ByteSource label;
  int padding = 0;
  const EVP_MD* digest = nullptr;

  RSACipherConfig() = default;
};

class RSACipher {
 public:
  RSACipher() {}
  RSACipherConfig GetParamsFromJS(jsi::Runtime &rt, const jsi::Value *args);
  WebCryptoCipherStatus DoCipher(const RSACipherConfig &params, ByteSource *out);
};

}  // namespace margelo

#endif /* MGLRsa_hpp */
