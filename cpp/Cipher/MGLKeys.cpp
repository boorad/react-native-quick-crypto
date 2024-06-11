//
//  MGLKeys.cpp
//  react-native-quick-crypto
//
//  Created by Oscar on 20.06.22.
//

#include "MGLKeys.h"

#include <jsi/jsi.h>
#include <openssl/bio.h>
#include <openssl/ec.h>

#include <algorithm>
#include <iostream>
#include <optional>
#include <utility>
#include <vector>

#ifdef ANDROID
#include "Cipher/MGLRsa.h"
#include "JSIUtils/MGLJSIMacros.h"
#include "JSIUtils/MGLJSIUtils.h"
#include "JSIUtils/MGLTypedArray.h"
#include "Utils/MGLUtils.h"
#include "webcrypto/crypto_ec.h"
#else
#include "MGLRsa.h"
#include "MGLJSIMacros.h"
#include "MGLJSIUtils.h"
#include "MGLTypedArray.h"
#include "MGLUtils.h"
#include "crypto_ec.h"
#endif

namespace margelo {

namespace jsi = facebook::jsi;

JSVariant BIOToStringOrBuffer(BIO* bio, PKFormatType format) {
  BUF_MEM* bptr;
  BIO_get_mem_ptr(bio, &bptr);
  if (format == kKeyFormatPEM) {
    // PEM is an ASCII format, so we will return it as a string.
    return JSVariant(std::string(bptr->data, bptr->length));
  } else {
    CHECK_EQ(format, kKeyFormatDER);
    // DER is binary, return it as a buffer.
    ByteSource::Builder out(bptr->length);
    memcpy(out.data<void>(), bptr->data, bptr->length);
    return JSVariant(std::move(out).release());
  }
}

JSVariant WritePrivateKey(EVP_PKEY* pkey,
                          const PrivateKeyEncodingConfig& config) {
  BIOPointer bio(BIO_new(BIO_s_mem()));
  CHECK(bio);

  // If an empty string was passed as the passphrase, the ByteSource might
  // contain a null pointer, which OpenSSL will ignore, causing it to invoke its
  // default passphrase callback, which would block the thread until the user
  // manually enters a passphrase. We could supply our own passphrase callback
  // to handle this special case, but it is easier to avoid passing a null
  // pointer to OpenSSL.
  char* pass = nullptr;
  size_t pass_len = 0;
  if (!config.passphrase_.IsEmpty()) {
    pass = const_cast<char*>(config.passphrase_->data<char>());
    pass_len = config.passphrase_->size();
    if (pass == nullptr) {
      // OpenSSL will not actually dereference this pointer, so it can be any
      // non-null pointer. We cannot assert that directly, which is why we
      // intentionally use a pointer that will likely cause a segmentation fault
      // when dereferenced.
      //      CHECK_EQ(pass_len, 0);
      pass = reinterpret_cast<char*>(-1);
      //      CHECK_NE(pass, nullptr);
    }
  }

  bool err = false;
  PKEncodingType encoding_type;

  if (config.type_.has_value()) {
    encoding_type = config.type_.value();
  } else {
    // default for no value in std::option `config.type_`
    encoding_type = kKeyEncodingSEC1;
  }

  if (encoding_type == kKeyEncodingPKCS1) {
    // PKCS#1 is only permitted for RSA keys.
    //    CHECK_EQ(EVP_PKEY_id(pkey), EVP_PKEY_RSA);

    RsaPointer rsa(EVP_PKEY_get1_RSA(pkey));
    if (config.format_ == kKeyFormatPEM) {
      // Encode PKCS#1 as PEM.
      err = PEM_write_bio_RSAPrivateKey(bio.get(), rsa.get(), config.cipher_,
                                        reinterpret_cast<unsigned char*>(pass),
                                        pass_len, nullptr, nullptr) != 1;
    } else {
      // Encode PKCS#1 as DER. This does not permit encryption.
      CHECK_EQ(config.format_, kKeyFormatDER);
      CHECK_NULL(config.cipher_);
      err = i2d_RSAPrivateKey_bio(bio.get(), rsa.get()) != 1;
    }
  } else if (encoding_type == kKeyEncodingPKCS8) {
    if (config.format_ == kKeyFormatPEM) {
      // Encode PKCS#8 as PEM.
      err = PEM_write_bio_PKCS8PrivateKey(bio.get(), pkey, config.cipher_, pass,
                                          pass_len, nullptr, nullptr) != 1;
    } else {
      // Encode PKCS#8 as DER.
      CHECK_EQ(config.format_, kKeyFormatDER);
      err = i2d_PKCS8PrivateKey_bio(bio.get(), pkey, config.cipher_, pass,
                                    pass_len, nullptr, nullptr) != 1;
    }
  } else {
    CHECK_EQ(encoding_type, kKeyEncodingSEC1);

    // SEC1 is only permitted for EC keys.
    CHECK_EQ(EVP_PKEY_id(pkey), EVP_PKEY_EC);

    ECKeyPointer ec_key(EVP_PKEY_get1_EC_KEY(pkey));
    if (config.format_ == kKeyFormatPEM) {
      // Encode SEC1 as PEM.
      err = PEM_write_bio_ECPrivateKey(bio.get(),ec_key.get(), config.cipher_,
                                       reinterpret_cast<unsigned char*>(pass),
                                       pass_len, nullptr, nullptr) != 1;
    } else {
      // Encode SEC1 as DER. This does not permit encryption.
      CHECK_EQ(config.format_, kKeyFormatDER);
      // CHECK_NULL(config.cipher_);
      err = i2d_ECPrivateKey_bio(bio.get(), ec_key.get()) != 1;
    }
  }

  if (err) {
    throw std::runtime_error("Failed to encode private key");
  }

  return BIOToStringOrBuffer(bio.get(), config.format_);
}

bool WritePublicKeyInner(EVP_PKEY* pkey, const BIOPointer& bio,
                         const PublicKeyEncodingConfig& config) {
  if (!config.type_.has_value()) return false;
  if (config.type_.value() == kKeyEncodingPKCS1) {
    // PKCS#1 is only valid for RSA keys.
    CHECK_EQ(EVP_PKEY_id(pkey), EVP_PKEY_RSA);
    RsaPointer rsa(EVP_PKEY_get1_RSA(pkey));
    if (config.format_ == kKeyFormatPEM) {
      // Encode PKCS#1 as PEM.
      return PEM_write_bio_RSAPublicKey(bio.get(), rsa.get()) == 1;
    } else {
      // Encode PKCS#1 as DER.
      CHECK_EQ(config.format_, kKeyFormatDER);
      return i2d_RSAPublicKey_bio(bio.get(), rsa.get()) == 1;
    }
  } else {
    CHECK_EQ(config.type_.value(), kKeyEncodingSPKI);
    if (config.format_ == kKeyFormatPEM) {
      // Encode SPKI as PEM.
      return PEM_write_bio_PUBKEY(bio.get(), pkey) == 1;
    } else {
      // Encode SPKI as DER.
      CHECK_EQ(config.format_, kKeyFormatDER);
      return i2d_PUBKEY_bio(bio.get(), pkey) == 1;
    }
  }
}

JSVariant WritePublicKey(EVP_PKEY* pkey,
                         const PublicKeyEncodingConfig& config) {
  BIOPointer bio(BIO_new(BIO_s_mem()));
  CHECK(bio);

  if (!WritePublicKeyInner(pkey, bio, config)) {
    throw std::runtime_error("Failed to encode public key");
  }

  return BIOToStringOrBuffer(bio.get(), config.format_);
}

}  // namespace margelo
