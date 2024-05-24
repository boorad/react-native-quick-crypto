#include "MGLKeyPair.h"

namespace margelo {

void KeyPairGen::GenerateKeyPair() {
  CheckEntropy();

  // Generate the key
  EVP_PKEY* pkey = nullptr;
  if (!EVP_PKEY_keygen(this->ctx.get(), &pkey)) {
    throw std::runtime_error("Error generating key (RSA)");
  }

  this->key = ManagedEVPPKey(EVPKeyPointer(pkey));

  std::shared_ptr<KeyObjectHandle> publicKey =
      ManagedEVPPKey::ToEncodedPublicKey(std::move(this->key),
                                         this->public_key_encoding);
  std::shared_ptr<KeyObjectHandle> privateKey =
      ManagedEVPPKey::ToEncodedPrivateKey(std::move(this->key),
                                          this->private_key_encoding);

  this->publicKey = std::move(publicKey);
  this->privateKey = std::move(privateKey);
}

}  // namespace margelo
