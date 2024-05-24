#ifndef MGLKeyPair_h
#define MGLKeyPair_h

#include <jsi/jsi.h>
#include "MGLKeys.h"

#ifdef ANDROID
// #include "Utils/MGLUtils.h"
// #include "JSIUtils/MGLSmartHostObject.h"
#else
// #include "MGLUtils.h"
// #include "MGLSmartHostObject.h"
#endif

namespace margelo {

namespace jsi = facebook::jsi;

class KeyPairGen {
  public:
    virtual EVPKeyCtxPointer Setup();
    virtual void PrepareConfig(jsi::Runtime& rt, const jsi::Value* args);
    virtual void GenerateKeyPair();
    inline static jsi::Value toJSI(jsi::Runtime& rt, std::shared_ptr<KeyObjectData> data) {
      auto handle = KeyObjectHandle::Create(data);
      auto out = jsi::Object::createFromHostObject(rt, handle);
      return jsi::Value(std::move(out));
    };
  protected:
    KeyVariant variant;
    ManagedEVPPKey key;
    EVPKeyCtxPointer ctx;
    PublicKeyEncodingConfig public_key_encoding;
    PrivateKeyEncodingConfig private_key_encoding;
    std::shared_ptr<KeyObjectHandle> publicKey;
    std::shared_ptr<KeyObjectHandle> privateKey;
};

}  // namespace margelo

#endif /* MGLKeyPair_h */
