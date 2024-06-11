#include "ManagedEVPPKey.h"

namespace margelo {

void GetKeyFormatAndTypeFromJs(AsymmetricKeyEncodingConfig* config,
                               jsi::Runtime& runtime, const jsi::Value* args,
                               unsigned int* offset,
                               KeyEncodingContext context) {
  // During key pair generation, it is possible not to specify a key encoding,
  // which will lead to a key object being returned.
  if (args[*offset].isUndefined()) {
    CHECK_EQ(context, kKeyContextGenerate);
    CHECK(args[*offset + 1].isUndefined());
    config->output_key_object_ = true;
  } else {
    config->output_key_object_ = false;

    // TODO(osp) implement check
    //    CHECK(args[*offset]->IsInt32());
    config->format_ = static_cast<PKFormatType>((int)args[*offset].getNumber());

    if (args[*offset + 1].isNumber()) {
      config->type_ =
          static_cast<PKEncodingType>((int)args[*offset + 1].getNumber());
    } else {
      CHECK(
          (context == kKeyContextInput && config->format_ == kKeyFormatPEM) ||
          (context == kKeyContextGenerate && config->format_ == kKeyFormatJWK));
      CHECK(args[*offset + 1].isUndefined());
      config->type_ = std::nullopt;
    }
  }

  *offset += 2;
}

ParseKeyResult TryParsePublicKey(
    EVPKeyPointer* pkey, const BIOPointer& bp, const char* name,
    const std::function<EVP_PKEY*(const unsigned char** p, long l)>& parse) {
  unsigned char* der_data;
  long der_len;

  // This skips surrounding data and decodes PEM to DER.
  if (PEM_bytes_read_bio(&der_data, &der_len, nullptr, name, bp.get(), nullptr,
                         nullptr) != 1) {
    return ParseKeyResult::kParseKeyNotRecognized;
  }

  // OpenSSL might modify the pointer, so we need to make a copy before parsing.
  const unsigned char* p = der_data;
  pkey->reset(parse(&p, der_len));
  OPENSSL_clear_free(der_data, der_len);

  return *pkey ? ParseKeyResult::kParseKeyOk : ParseKeyResult::kParseKeyFailed;
}

ParseKeyResult ParsePublicKeyPEM(EVPKeyPointer* pkey, const char* key_pem,
                                 int key_pem_len) {
  BIOPointer bp(BIO_new_mem_buf(const_cast<char*>(key_pem), key_pem_len));
  if (!bp) return ParseKeyResult::kParseKeyFailed;

  ParseKeyResult ret;

  // Try parsing as a SubjectPublicKeyInfo first.
  ret = TryParsePublicKey(pkey, bp, "PUBLIC KEY",
                          [](const unsigned char** p, long l) {
                            return d2i_PUBKEY(nullptr, p, l);
                          });

  if (ret != ParseKeyResult::kParseKeyNotRecognized) return ret;

  // Maybe it is PKCS#1.
  BIO_reset(bp.get());
  ret = TryParsePublicKey(pkey, bp, "RSA PUBLIC KEY",
                          [](const unsigned char** p, long l) {
                            return d2i_PublicKey(EVP_PKEY_RSA, nullptr, p, l);
                          });
  if (ret != ParseKeyResult::kParseKeyNotRecognized) return ret;

  // X.509 fallback.
  BIO_reset(bp.get());
  return TryParsePublicKey(
      pkey, bp, "CERTIFICATE", [](const unsigned char** p, long l) {
        X509Pointer x509(d2i_X509(nullptr, p, l));
        return x509 ? X509_get_pubkey(x509.get()) : nullptr;
      });
}

ParseKeyResult ParsePublicKey(EVPKeyPointer* pkey,
                              const PublicKeyEncodingConfig& config,
                              const char* key, size_t key_len) {
  if (config.format_ == kKeyFormatPEM) {
    return ParsePublicKeyPEM(pkey, key, (int)key_len);
  } else {
    //    CHECK_EQ(config.format_, kKeyFormatDER);

    const unsigned char* p = reinterpret_cast<const unsigned char*>(key);
    if (config.type_.value() == kKeyEncodingPKCS1) {
      pkey->reset(d2i_PublicKey(EVP_PKEY_RSA, nullptr, &p, key_len));
    } else {
      //      CHECK_EQ(config.type_.ToChecked(), kKeyEncodingSPKI);
      pkey->reset(d2i_PUBKEY(nullptr, &p, key_len));
    }

    return *pkey ? ParseKeyResult::kParseKeyOk
                 : ParseKeyResult::kParseKeyFailed;
  }
}

bool IsASN1Sequence(const unsigned char* data, size_t size, size_t* data_offset,
                    size_t* data_size) {
  if (size < 2 || data[0] != 0x30) return false;

  if (data[1] & 0x80) {
    // Long form.
    size_t n_bytes = data[1] & ~0x80;
    if (n_bytes + 2 > size || n_bytes > sizeof(size_t)) return false;
    size_t length = 0;
    for (size_t i = 0; i < n_bytes; i++) length = (length << 8) | data[i + 2];
    *data_offset = 2 + n_bytes;
    *data_size = std::min(size - 2 - n_bytes, length);
  } else {
    // Short form.
    *data_offset = 2;
    *data_size = std::min<size_t>(size - 2, data[1]);
  }

  return true;
}

bool IsRSAPrivateKey(const unsigned char* data, size_t size) {
  // Both RSAPrivateKey and RSAPublicKey structures start with a SEQUENCE.
  size_t offset, len;
  if (!IsASN1Sequence(data, size, &offset, &len)) return false;

  // An RSAPrivateKey sequence always starts with a single-byte integer whose
  // value is either 0 or 1, whereas an RSAPublicKey starts with the modulus
  // (which is the product of two primes and therefore at least 4), so we can
  // decide the type of the structure based on the first three bytes of the
  // sequence.
  return len >= 3 && data[offset] == 2 && data[offset + 1] == 1 &&
         !(data[offset + 2] & 0xfe);
}

bool IsEncryptedPrivateKeyInfo(const unsigned char* data, size_t size) {
  // Both PrivateKeyInfo and EncryptedPrivateKeyInfo start with a SEQUENCE.
  size_t offset, len;
  if (!IsASN1Sequence(data, size, &offset, &len)) return false;

  // A PrivateKeyInfo sequence always starts with an integer whereas an
  // EncryptedPrivateKeyInfo starts with an AlgorithmIdentifier.
  return len >= 1 && data[offset] != 2;
}

ParseKeyResult ParsePrivateKey(EVPKeyPointer* pkey,
                               const PrivateKeyEncodingConfig& config,
                               const char* key, size_t key_len) {
  const ByteSource* passphrase = config.passphrase_.get();

  if (config.format_ == kKeyFormatPEM) {
    BIOPointer bio(BIO_new_mem_buf(key, (int)key_len));
    if (!bio) {
      return ParseKeyResult::kParseKeyFailed;
    }

    pkey->reset(PEM_read_bio_PrivateKey(bio.get(), nullptr, PasswordCallback,
                                        &passphrase));
  } else {
    CHECK_EQ(config.format_, kKeyFormatDER);

    if (!config.type_.has_value()) {
      throw new std::runtime_error("ParsePrivateKey key config has no type!");
    }

    if (config.type_.value() == kKeyEncodingPKCS1) {
      const unsigned char* p = reinterpret_cast<const unsigned char*>(key);
      pkey->reset(d2i_PrivateKey(EVP_PKEY_RSA, nullptr, &p, key_len));
    } else if (config.type_.value() == kKeyEncodingPKCS8) {
      BIOPointer bio(BIO_new_mem_buf(key, (int)key_len));
      if (!bio) return ParseKeyResult::kParseKeyFailed;

      if (IsEncryptedPrivateKeyInfo(reinterpret_cast<const unsigned char*>(key),
                                    key_len)) {
        pkey->reset(d2i_PKCS8PrivateKey_bio(bio.get(), nullptr,
                                            PasswordCallback, &passphrase));
      } else {
        PKCS8Pointer p8inf(d2i_PKCS8_PRIV_KEY_INFO_bio(bio.get(), nullptr));
        if (p8inf) pkey->reset(EVP_PKCS82PKEY(p8inf.get()));
      }
    } else {
      CHECK_EQ(config.type_.value(), kKeyEncodingSEC1);
      const unsigned char* p = reinterpret_cast<const unsigned char*>(key);
      pkey->reset(d2i_PrivateKey(EVP_PKEY_EC, nullptr, &p, key_len));
    }
  }

  // OpenSSL can fail to parse the key but still return a non-null pointer.
  unsigned long err = ERR_peek_error();  // NOLINT(runtime/int)
  auto reason = ERR_GET_REASON(err);
  // Per OpenSSL documentation PEM_R_NO_START_LINE signals all PEM certs have
  // been consumed and is a harmless error
  if (reason == PEM_R_NO_START_LINE && *pkey) {
    return ParseKeyResult::kParseKeyOk;
  }

  if (err != 0) pkey->reset();

  if (*pkey) {
    return ParseKeyResult::kParseKeyOk;
  }

  if (ERR_GET_LIB(err) == ERR_LIB_PEM) {
    if (reason == PEM_R_BAD_PASSWORD_READ && config.passphrase_.IsEmpty()) {
      return ParseKeyResult::kParseKeyNeedPassphrase;
    }
  }
  return ParseKeyResult::kParseKeyFailed;
}

// ManagedEVPPKey
ManagedEVPPKey::ManagedEVPPKey(EVPKeyPointer&& pkey) : pkey_(std::move(pkey)) {}

ManagedEVPPKey::ManagedEVPPKey(const ManagedEVPPKey& that) { *this = that; }

ManagedEVPPKey& ManagedEVPPKey::operator=(const ManagedEVPPKey& that) {
  //  Mutex::ScopedLock lock(*that.mutex_);

  pkey_.reset(that.get());

  if (pkey_) EVP_PKEY_up_ref(pkey_.get());

  //  mutex_ = that.mutex_;

  return *this;
}

ManagedEVPPKey::operator bool() const { return !!pkey_; }

EVP_PKEY* ManagedEVPPKey::get() const { return pkey_.get(); }

// Mutex* ManagedEVPPKey::mutex() const {
//  return mutex_.get();
//}
//
// void ManagedEVPPKey::MemoryInfo(MemoryTracker* tracker) const {
//  tracker->TrackFieldWithSize("pkey",
//                              !pkey_ ? 0 : kSizeOf_EVP_PKEY +
//                              size_of_private_key() +
//                              size_of_public_key());
//}

size_t ManagedEVPPKey::size_of_private_key() const {
 size_t len = 0;
 return (pkey_ && EVP_PKEY_get_raw_private_key(pkey_.get(), nullptr, &len) == 1)
  ? len : 0;
}

size_t ManagedEVPPKey::size_of_public_key() const {
 size_t len = 0;
 return (pkey_ && EVP_PKEY_get_raw_public_key(pkey_.get(), nullptr, &len) == 1)
  ? len : 0;
}


NonCopyableMaybe<PrivateKeyEncodingConfig>
ManagedEVPPKey::GetPrivateKeyEncodingFromJs(jsi::Runtime& runtime,
                                            const jsi::Value* arguments,
                                            unsigned int* offset,
                                            KeyEncodingContext context) {
  PrivateKeyEncodingConfig result;
  GetKeyFormatAndTypeFromJs(&result, runtime, arguments, offset, context);

  if (result.output_key_object_) {
    if (context != kKeyContextInput) (*offset)++;
  } else {
    bool needs_passphrase = false;
    if (context != kKeyContextInput) {
      if (arguments[*offset].isString()) {
        auto cipher_name = arguments[*offset].getString(runtime).utf8(runtime);
        result.cipher_ = EVP_get_cipherbyname(cipher_name.c_str());
        if (result.cipher_ == nullptr) {
          throw jsi::JSError(runtime, "Unknown cipher");
        }
        needs_passphrase = true;
      } else {
        //        CHECK(args[*offset]->IsNullOrUndefined());
        result.cipher_ = nullptr;
      }
      (*offset)++;
    }

    if (CheckIsArrayBuffer(runtime, arguments[*offset])) {
      //      CHECK_IMPLIES(context != kKeyContextInput, result.cipher_ !=
      //      nullptr); ArrayBufferOrViewContents<char>
      //      passphrase(arguments[*offset]);
      jsi::ArrayBuffer passphrase =
          arguments[*offset].asObject(runtime).getArrayBuffer(runtime);
      if (!CheckSizeInt32(runtime, passphrase)) {
        throw jsi::JSError(runtime, "passphrase is too long");
      }

      result.passphrase_ = NonCopyableMaybe<ByteSource>(
          ToNullTerminatedByteSource(runtime, passphrase));
    } else {
      if (needs_passphrase &&
          (arguments[*offset].isNull() || arguments[*offset].isUndefined())) {
        throw jsi::JSError(
            runtime, "passphrase is null or undefined but it is required");
      }
    }
  }

  (*offset)++;
  return NonCopyableMaybe<PrivateKeyEncodingConfig>(std::move(result));
}

PublicKeyEncodingConfig ManagedEVPPKey::GetPublicKeyEncodingFromJs(
    jsi::Runtime& runtime, const jsi::Value* arguments, unsigned int* offset,
    KeyEncodingContext context) {
  PublicKeyEncodingConfig result;
  GetKeyFormatAndTypeFromJs(&result, runtime, arguments, offset, context);
  return result;
}

ManagedEVPPKey ManagedEVPPKey::GetPrivateKeyFromJs(jsi::Runtime& runtime,
                                                   const jsi::Value* args,
                                                   unsigned int* offset,
                                                   bool allow_key_object) {
  if (args[*offset].isString() ||
      args[*offset].asObject(runtime).isArrayBuffer(runtime)) {
    ByteSource key = ByteSource::FromStringOrBuffer(runtime, args[*offset]);
    (*offset)++;
    NonCopyableMaybe<PrivateKeyEncodingConfig> config =
        GetPrivateKeyEncodingFromJs(runtime, args, offset, kKeyContextInput);
    if (config.IsEmpty()) return ManagedEVPPKey();

    EVPKeyPointer pkey;
    ParseKeyResult ret =
        ParsePrivateKey(&pkey, config.Release(), key.data<char>(), key.size());
    return GetParsedKey(runtime, std::move(pkey), ret,
                        "Failed to read private key");
  } else {
    //    CHECK(args[*offset]->IsObject() && allow_key_object);
    //    KeyObjectHandle* key;
    //    ASSIGN_OR_RETURN_UNWRAP(&key, args[*offset].As<Object>(),
    //    ManagedEVPPKey()); CHECK_EQ(key->Data()->GetKeyType(),
    //    kKeyTypePrivate);
    //    (*offset) += 4;
    //    return key->Data()->GetAsymmetricKey();
    throw jsi::JSError(runtime, "KeyObject are not currently supported");
  }
}

ManagedEVPPKey ManagedEVPPKey::GetPublicOrPrivateKeyFromJs(
    jsi::Runtime& runtime, const jsi::Value* args, unsigned int* offset) {
  if (args[*offset].asObject(runtime).isArrayBuffer(runtime)) {
    auto dataArrayBuffer =
        args[(*offset)++].asObject(runtime).getArrayBuffer(runtime);

    if (!CheckSizeInt32(runtime, dataArrayBuffer)) {
      throw jsi::JSError(runtime, "data is too big");
    }

    NonCopyableMaybe<PrivateKeyEncodingConfig> config_ =
        GetPrivateKeyEncodingFromJs(runtime, args, offset, kKeyContextInput);
    if (config_.IsEmpty()) return ManagedEVPPKey();

    ParseKeyResult ret;
    PrivateKeyEncodingConfig config = config_.Release();
    EVPKeyPointer pkey;
    if (config.format_ == kKeyFormatPEM) {
      // For PEM, we can easily determine whether it is a public or private
      // key by looking for the respective PEM tags.
      ret = ParsePublicKeyPEM(&pkey, (const char*)dataArrayBuffer.data(runtime),
                              (int)dataArrayBuffer.size(runtime));
      if (ret == ParseKeyResult::kParseKeyNotRecognized) {
        ret = ParsePrivateKey(&pkey, config,
                              (const char*)dataArrayBuffer.data(runtime),
                              (int)dataArrayBuffer.size(runtime));
      }
    } else {
      // For DER, the type determines how to parse it. SPKI, PKCS#8 and SEC1
      // are easy, but PKCS#1 can be a public key or a private key.
      bool is_public;
      switch (config.type_.value()) {
        case kKeyEncodingPKCS1:
          is_public = !IsRSAPrivateKey(reinterpret_cast<const unsigned char*>(
                                           dataArrayBuffer.data(runtime)),
                                       dataArrayBuffer.size(runtime));
          break;
        case kKeyEncodingSPKI:
          is_public = true;
          break;
        case kKeyEncodingPKCS8:
        case kKeyEncodingSEC1:
          is_public = false;
          break;
        default:
          throw jsi::JSError(runtime, "Invalid key encoding type");
      }

      if (is_public) {
        ret = ParsePublicKey(&pkey, config,
                             (const char*)dataArrayBuffer.data(runtime),
                             dataArrayBuffer.size(runtime));
      } else {
        ret = ParsePrivateKey(&pkey, config,
                              (const char*)dataArrayBuffer.data(runtime),
                              dataArrayBuffer.size(runtime));
      }
    }

    return ManagedEVPPKey::GetParsedKey(runtime, std::move(pkey), ret,
                                        "Failed to read asymmetric key");
  } else {
    throw jsi::JSError(
        runtime, "public encrypt only supports ArrayBuffer at the moment");
    //    CHECK(args[*offset]->IsObject());
    //    KeyObjectHandle* key =
    //    Unwrap<KeyObjectHandle>(args[*offset].As<Object>());
    //    CHECK_NOT_NULL(key);
    //    CHECK_NE(key->Data()->GetKeyType(), kKeyTypeSecret);
    //    (*offset) += 4;
    //    return key->Data()->GetAsymmetricKey();
  }
}

ManagedEVPPKey ManagedEVPPKey::GetParsedKey(jsi::Runtime& runtime,
                                            EVPKeyPointer&& pkey,
                                            ParseKeyResult ret,
                                            const char* default_msg) {
  switch (ret) {
    case ParseKeyResult::kParseKeyOk:
      //       CHECK(pkey);
      break;
    case ParseKeyResult::kParseKeyNeedPassphrase:
      throw jsi::JSError(runtime, "Passphrase required for encrypted key");
      break;
    default:
      throw jsi::JSError(runtime, default_msg);
  }

  return ManagedEVPPKey(std::move(pkey));
}

// JSVariant BIOToStringOrBuffer(BIO* bio, PKFormatType format) {
//   BUF_MEM* bptr;
//   BIO_get_mem_ptr(bio, &bptr);
//   if (format == kKeyFormatPEM) {
//     // PEM is an ASCII format, so we will return it as a string.
//     return std::string(bptr->data, bptr->length);
//   } else {
//     CHECK_EQ(format, kKeyFormatDER);
//     // DER is binary, return it as a buffer.
//     ByteSource::Builder out(bptr->length);
//     memcpy(out.data<void>(), bptr->data, bptr->length);
//     return std::move(out).release();
//   }
// }

BIO* WritePrivateKey(EVP_PKEY* pkey,
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

  return bio.get();
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
