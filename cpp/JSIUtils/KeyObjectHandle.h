#ifndef KeyObjectHandle_h
#define KeyObjectHandle_h

#include <jsi/jsi.h>

#include "KeyObjectData.h"
#include "MGLJSIMacros.h"
#include "MGLJSIUtils.h"
#include "MGLRsa.h"
#include "crypto_ec.h"

namespace margelo {

namespace jsi = facebook::jsi;

// Analogous to the KeyObjectHandle class in node
// https://github.com/nodejs/node/blob/main/src/crypto/crypto_keys.h#L164
class JSI_EXPORT KeyObjectHandle: public jsi::HostObject {
 public:
    KeyObjectHandle() {}
    jsi::Value get(jsi::Runtime &rt, const jsi::PropNameID &propNameID);
    const std::shared_ptr<KeyObjectData>& Data();

 protected:
    jsi::Value Export(jsi::Runtime &rt);
    jsi::Value ExportJWK(jsi::Runtime &rt);
    jsi::Value ExportPublicKey(
      jsi::Runtime& rt,
      const PublicKeyEncodingConfig& config) const;
    jsi::Value ExportPrivateKey(
      jsi::Runtime& rt,
      const PrivateKeyEncodingConfig& config) const;
    jsi::Value ExportSecretKey(jsi::Runtime& rt) const;
    jsi::Value Init(jsi::Runtime &rt);
    jsi::Value InitECRaw(jsi::Runtime &rt);
    jsi::Value InitJWK(jsi::Runtime &rt);
    jsi::Value GetKeyDetail(jsi::Runtime &rt);

 private:
    std::shared_ptr<KeyObjectData> data_;
};

}  // namespace margelo

#endif  // KeyObjectHandle_h
