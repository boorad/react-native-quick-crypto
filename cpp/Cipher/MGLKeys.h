#ifndef MGLKeys_h
#define MGLKeys_h

#include <openssl/evp.h>

#include <memory>
#include <optional>
#include <string>
#include <variant>

#include "MGLJSIUtils.h"

// #ifdef ANDROID
// #include "Utils/MGLUtils.h"
// #include "JSIUtils/MGLSmartHostObject.h"
// #else
// #include "MGLSmartHostObject.h"
// #endif

namespace margelo {

enum PKEncodingType {
  // RSAPublicKey / RSAPrivateKey according to PKCS#1.
  kKeyEncodingPKCS1,
  // PrivateKeyInfo or EncryptedPrivateKeyInfo according to PKCS#8.
  kKeyEncodingPKCS8,
  // SubjectPublicKeyInfo according to X.509.
  kKeyEncodingSPKI,
  // ECPrivateKey according to SEC1.
  kKeyEncodingSEC1
};

enum PKFormatType { kKeyFormatDER, kKeyFormatPEM, kKeyFormatJWK };

enum KeyType { kKeyTypeSecret, kKeyTypePublic, kKeyTypePrivate };

enum KeyEncodingContext {
  kKeyContextInput,
  kKeyContextExport,
  kKeyContextGenerate
};

enum class ParseKeyResult {
  kParseKeyOk,
  kParseKeyNotRecognized,
  kParseKeyNeedPassphrase,
  kParseKeyFailed
};

enum class WebCryptoKeyExportStatus {
  OK,
  INVALID_KEY_TYPE,
  FAILED
};

struct AsymmetricKeyEncodingConfig {
  bool output_key_object_ = false;
  PKFormatType format_ = kKeyFormatDER;
  std::optional<PKEncodingType> type_ = std::nullopt;
};

using PublicKeyEncodingConfig = AsymmetricKeyEncodingConfig;

struct PrivateKeyEncodingConfig : public AsymmetricKeyEncodingConfig {
  const EVP_CIPHER *cipher_;
  // The ByteSource alone is not enough to distinguish between "no passphrase"
  // and a zero-length passphrase (which can be a null pointer), therefore, we
  // use a NonCopyableMaybe.
  NonCopyableMaybe<ByteSource> passphrase_;
};

JSVariant BIOToStringOrBuffer(BIO* bio, PKFormatType format);

JSVariant WritePublicKey(EVP_PKEY* pkey,
                         const PublicKeyEncodingConfig& config);

JSVariant WritePrivateKey(EVP_PKEY* pkey,
                          const PrivateKeyEncodingConfig& config);

}  // namespace margelo

#endif /* MGLKeys_h */
