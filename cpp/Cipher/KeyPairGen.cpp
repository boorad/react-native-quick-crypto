#include "KeyPairGen.h"

namespace margelo
{
  EVPKeyCtxPointer KeyPairGen::Setup() {};
  void KeyPairGen::PrepareConfig(jsi::Runtime &rt, const jsi::Value *args) {};

  void KeyPairGen::GenerateKeyPair()
  {
    CheckEntropy();

    // Generate the key
    EVP_PKEY *pkey = nullptr;
    if (!EVP_PKEY_keygen(this->ctx.get(), &pkey))
    {
      throw std::runtime_error("Error generating key pair");
    }

    this->key = ManagedEVPPKey(EVPKeyPointer(pkey));

    auto pub = ManagedEVPPKey::ToEncodedPublicKey(std::move(this->key),
                                                  this->public_key_encoding);
    this->publicKey = pub;
    this->privateKey =
        ManagedEVPPKey::ToEncodedPrivateKey(std::move(this->key),
                                            this->private_key_encoding);
  }

} // namespace margelo
