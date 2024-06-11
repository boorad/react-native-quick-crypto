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
#include "KeyPairGen.h"

#ifdef ANDROID
#include "Utils/MGLUtils.h"
#else
#include "MGLUtils.h"
#endif

namespace margelo
{

  namespace jsi = facebook::jsi;

  class RsaKeyPairGen : protected KeyPairGen
  {
  public:
    EVPKeyCtxPointer Setup();
    void PrepareConfig(jsi::Runtime &rt, const jsi::Value *args);
    // void GenerateKeyPair();
  protected:
    unsigned int modulus_bits;
    unsigned int exponent;

    // The following options are used for RSA-PSS. If any of them are set, a
    // RSASSA-PSS-params sequence will be added to the key.
    const EVP_MD *md = nullptr;
    const EVP_MD *mgf1_md = nullptr;
    int saltlen = -1;
  };

  jsi::Value ExportJWKRsaKey(jsi::Runtime &rt,
                             std::shared_ptr<KeyObjectData> key,
                             jsi::Object &target);

  std::shared_ptr<KeyObjectData> ImportJWKRsaKey(jsi::Runtime &rt,
                                                 jsi::Object &jwk);

  jsi::Value GetRsaKeyDetail(jsi::Runtime &rt,
                             std::shared_ptr<KeyObjectData> key);

} // namespace margelo

#endif /* MGLRsa_hpp */
