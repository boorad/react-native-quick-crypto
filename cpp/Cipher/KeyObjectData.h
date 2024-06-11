#ifndef KeyObjectData_h
#define KeyObjectData_h

#include <string>

#include "ManagedEVPPKey.h"
#include "MGLKeys.h"

namespace margelo {

// Analogous to the KeyObjectData class on node
// https://github.com/nodejs/node/blob/main/src/crypto/crypto_keys.h#L132
class KeyObjectData {
 public:
  static std::shared_ptr<KeyObjectData> CreateSecret(ByteSource key);

  static KeyObjectData CreateAsymmetric(KeyType type,
                                        const ManagedEVPPKey& pkey);

  KeyType GetKeyType() const;

  // These functions allow unprotected access to the raw key material and should
  // only be used to implement cryptographic operations requiring the key.
  
  ManagedEVPPKey GetAsymmetricKey() const;
  std::string GetSymmetricKey() const;
  size_t GetSymmetricKeySize() const;

 private:
 explicit KeyObjectData(ByteSource symmetric_key);

  KeyObjectData(
      KeyType type,
      const ManagedEVPPKey& pkey);

  const KeyType key_type_;
  const ByteSource symmetric_key_;
  const size_t symmetric_key_len_;
  const ManagedEVPPKey asymmetric_key_;
};

}  // namespace margelo

#endif  // KeyObjectData_h
