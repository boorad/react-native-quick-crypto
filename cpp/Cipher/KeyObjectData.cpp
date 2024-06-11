#include "KeyObjectData.h"

namespace margelo {

namespace jsi = facebook::jsi;

KeyObjectData::KeyObjectData(ByteSource symmetric_key)
: key_type_(KeyType::kKeyTypeSecret),
  symmetric_key_(std::move(symmetric_key)),
  symmetric_key_len_(symmetric_key_.size()),
  asymmetric_key_() {}

KeyObjectData::KeyObjectData(KeyType type,
                             const ManagedEVPPKey& pkey)
: key_type_(type),
  symmetric_key_(),
  symmetric_key_len_(0),
  asymmetric_key_{pkey} {}

std::shared_ptr<KeyObjectData> KeyObjectData::CreateSecret(ByteSource key)
{
  CHECK(key);
  return std::shared_ptr<KeyObjectData>(new KeyObjectData(std::move(key)));
}

KeyObjectData KeyObjectData::CreateAsymmetric(
  KeyType key_type,
  const ManagedEVPPKey& pkey
) {
  CHECK(pkey);
  return KeyObjectData(key_type, pkey);
}

KeyType KeyObjectData::GetKeyType() const {
  return key_type_;
}

ManagedEVPPKey KeyObjectData::GetAsymmetricKey() const {
  CHECK_NE(key_type_, kKeyTypeSecret);
  return asymmetric_key_;
}

/** Gets the symmetric key value
 * binary data stored in string, tolerates \0 characters
 */
std::string KeyObjectData::GetSymmetricKey() const {
  CHECK_EQ(key_type_, kKeyTypeSecret);
  return symmetric_key_.ToString();
}

size_t KeyObjectData::GetSymmetricKeySize() const {
  CHECK_EQ(key_type_, kKeyTypeSecret);
  return symmetric_key_len_;
}

}  // namespace margelo
