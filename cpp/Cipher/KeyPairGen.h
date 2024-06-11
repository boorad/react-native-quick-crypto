#ifndef KeyPairGen_h
#define KeyPairGen_h

#include <jsi/jsi.h>
#include "MGLJSIUtils.h"
#include "ManagedEVPPKey.h"

#ifdef ANDROID
// #include "Utils/MGLUtils.h"
// #include "JSIUtils/MGLSmartHostObject.h"
#else
// #include "MGLUtils.h"
// #include "MGLSmartHostObject.h"
#endif

namespace margelo
{

  namespace jsi = facebook::jsi;

  class KeyPairGen
  {
  public:
    virtual EVPKeyCtxPointer Setup();
    virtual void PrepareConfig(jsi::Runtime &rt, const jsi::Value *args);
    void GenerateKeyPair();

  protected:
    KeyVariant variant;
    ManagedEVPPKey key;
    EVPKeyCtxPointer ctx;
    PublicKeyEncodingConfig public_key_encoding;
    PrivateKeyEncodingConfig private_key_encoding;
    inline jsi::Value GetJsiPublicKey(jsi::Runtime &runtime)
    {
      return toJSI(runtime, this->publicKey);
    }
    inline jsi::Value GetJsiPrivateKey(jsi::Runtime &runtime)
    {
      return toJSI(runtime, this->privateKey);
    }
    JSVariant publicKey;
    JSVariant privateKey;
  };

} // namespace margelo

#endif /* KeyPairGen_h */
