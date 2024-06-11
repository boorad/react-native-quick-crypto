#ifndef ManagedEVPPKey_h
#define ManagedEVPPKey_h

#include <jsi/jsi.h>
#include <openssl/evp.h>

#include "MGLJSIMacros.h"
// #include "MGLJSIUtils.h"
#include "MGLKeys.h"
// #include "MGLUtils.h"

namespace margelo {

namespace jsi = facebook::jsi;

// Here node uses extends MemoryRetainer no clue what that is, something with
// Snapshots stripped it for our implementation but if something doesn't work,
// you know why
class ManagedEVPPKey {
 public:
  ManagedEVPPKey() {}
  explicit ManagedEVPPKey(EVPKeyPointer &&pkey);
  ManagedEVPPKey(const ManagedEVPPKey &that);
  ManagedEVPPKey &operator=(const ManagedEVPPKey &that);

  operator bool() const;
  EVP_PKEY *get() const;

  static PublicKeyEncodingConfig GetPublicKeyEncodingFromJs(
      jsi::Runtime &runtime, const jsi::Value *arguments, unsigned int *offset,
      KeyEncodingContext context);

  static NonCopyableMaybe<PrivateKeyEncodingConfig> GetPrivateKeyEncodingFromJs(
      jsi::Runtime &runtime, const jsi::Value *arguments, unsigned int *offset,
      KeyEncodingContext context);
  //
  static ManagedEVPPKey GetParsedKey(jsi::Runtime &runtime,
                                     EVPKeyPointer &&pkey,
                                     ParseKeyResult ret,
                                     const char *default_msg);

  static ManagedEVPPKey GetPublicOrPrivateKeyFromJs(jsi::Runtime &runtime,
                                                    const jsi::Value *args,
                                                    unsigned int *offset);

  static ManagedEVPPKey GetPrivateKeyFromJs(jsi::Runtime &runtime,
                                            const jsi::Value *args,
                                            unsigned int *offset,
                                            bool allow_key_object);

  static JSVariant ToEncodedPublicKey(ManagedEVPPKey key,
                                      const PublicKeyEncodingConfig& config);


  static JSVariant ToEncodedPrivateKey(ManagedEVPPKey key,
                                       const PrivateKeyEncodingConfig &config);

 private:
   size_t size_of_private_key() const;
   size_t size_of_public_key() const;

  EVPKeyPointer pkey_;
};

}  // namespace margelo

#endif  // ManagedEVPPKey_h
