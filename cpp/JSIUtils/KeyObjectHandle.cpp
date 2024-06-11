#include "KeyObjectHandle.h"

namespace margelo {

namespace jsi = facebook::jsi;

std::shared_ptr<KeyObjectData> ImportJWKSecretKey(jsi::Runtime &rt,
                                                  jsi::Object &jwk) {
  std::string key = jwk
    .getProperty(rt, "k")
    .asString(rt)
    .utf8(rt);

  // TODO: when adding tests, trap errors like below (i.e. no `k` property, undefined)
  //  Local<Value> key;
  //  if (!jwk->Get(env->context(), env->jwk_k_string()).ToLocal(&key) ||
  //      !key->IsString()) {
  //    THROW_ERR_CRYPTO_INVALID_JWK(env, "Invalid JWK secret key format");
  //    return std::shared_ptr<KeyObjectData>();
  //  }

  ByteSource key_data = ByteSource::FromEncodedString(rt, key, encoding::BASE64URL);
  if (key_data.size() > INT_MAX) {
    throw jsi::JSError(rt, "Invalid crypto key length");
    return std::shared_ptr<KeyObjectData>();
  }

  return KeyObjectData::CreateSecret(std::move(key_data));
}

std::shared_ptr<KeyObjectData> ImportJWKAsymmetricKey(jsi::Runtime &rt,
                                                      jsi::Object &jwk,
                                                      std::string kty,
                                                      jsi::Value &namedCurve) {
  if (kty.compare("RSA") == 0) {
    return ImportJWKRsaKey(rt, jwk);
  } else if (kty.compare("EC") == 0) {
    return ImportJWKEcKey(rt, jwk, namedCurve);
  }

  throw jsi::JSError(rt, "%s is not a supported JWK key type", kty);
  return std::shared_ptr<KeyObjectData>();
}

jsi::Value GetSecretKeyDetail(jsi::Runtime &rt,
                              std::shared_ptr<KeyObjectData> key) {
  jsi::Object target = jsi::Object(rt);
  // For the secret key detail, all we care about is the length,
  // converted to bits.
  size_t length = key->GetSymmetricKeySize() * CHAR_BIT;
  target.setProperty(rt, "length", static_cast<double>(length));
  return std::move(target);
}

jsi::Value GetAsymmetricKeyDetail(jsi::Runtime &rt,
                                  std::shared_ptr<KeyObjectData> key) {
  switch (EVP_PKEY_id(key->GetAsymmetricKey().get())) {
    case EVP_PKEY_RSA:
      // Fall through
    case EVP_PKEY_RSA_PSS: return GetRsaKeyDetail(rt, key);
    // case EVP_PKEY_DSA: return GetDsaKeyDetail(env, key);
    case EVP_PKEY_EC: return GetEcKeyDetail(rt, key);
    // case EVP_PKEY_DH: return GetDhKeyDetail(env, key);
  }
  throw jsi::JSError(rt, "Invalid Key Type");
  return false;
}

jsi::Value ExportJWKInner(jsi::Runtime &rt,
                          std::shared_ptr<KeyObjectData> key,
                          jsi::Object &result,
                          bool handleRsaPss) {
  switch (key->GetKeyType()) {
    case kKeyTypeSecret:
      return ExportJWKSecretKey(rt, key, result);
    case kKeyTypePublic:
      // Fall through
    case kKeyTypePrivate:
      return ExportJWKAsymmetricKey(rt, key, result, handleRsaPss);
    default:
      throw jsi::JSError(rt, "unreachable code in ExportJWKInner");
  }
}

jsi::Value ExportJWKSecretKey(jsi::Runtime &rt,
                              std::shared_ptr<KeyObjectData> key,
                              jsi::Object &result) {
  CHECK_EQ(key->GetKeyType(), kKeyTypeSecret);

  std::string key_data = EncodeBase64(key->GetSymmetricKey(), true);

  result.setProperty(rt, "kty", "oct");
  result.setProperty(rt, "k", key_data);
  return std::move(result);
}

jsi::Value ExportJWKAsymmetricKey(jsi::Runtime &rt,
                                  std::shared_ptr<KeyObjectData> key,
                                  jsi::Object &target,
                                  bool handleRsaPss) {
  switch (EVP_PKEY_id(key->GetAsymmetricKey().get())) {
    case EVP_PKEY_RSA_PSS: {
      if (handleRsaPss) return ExportJWKRsaKey(rt, key, target);
      break;
    }
    case EVP_PKEY_RSA: return ExportJWKRsaKey(rt, key, target);
    case EVP_PKEY_EC: return ExportJWKEcKey(rt, key, target);
    // case EVP_PKEY_ED25519:
    //   // Fall through
    // case EVP_PKEY_ED448:
    //   // Fall through
    // case EVP_PKEY_X25519:
    //   // Fall through
    // case EVP_PKEY_X448: return ExportJWKEdKey(rt, key, target);
  }
  throw jsi::JSError(rt, "Unsupported JWK asymmetric key type");
}


// KeyObjectHandle

jsi::Value KeyObjectHandle::get(
  jsi::Runtime &rt,
  const jsi::PropNameID &propNameID) {
    auto name = propNameID.utf8(rt);

    if (name == "export") {
      return this->Export(rt);
    } else if (name == "exportJwk") {
      return this->ExportJWK(rt);
    } else if (name == "initECRaw") {
      return this-> InitECRaw(rt);
    } else if (name == "init") {
      return this->Init(rt);
    } else if (name == "initJwk") {
      return this->InitJWK(rt);
    } else if (name == "keyDetail") {
      return this->GetKeyDetail(rt);
    }

    return {};
}

// v8::Local<v8::Function> KeyObjectHandle::Initialize(Environment* env) {
//   Local<Function> templ = env->crypto_key_object_handle_constructor();
//   if (!templ.IsEmpty()) {
//     return templ;
//   }
//   Local<FunctionTemplate> t = env->NewFunctionTemplate(New);
//   t->InstanceTemplate()->SetInternalFieldCount(
//                                                KeyObjectHandle::kInternalFieldCount);
//   t->Inherit(BaseObject::GetConstructorTemplate(env));
//
//   env->SetProtoMethod(t, "init", Init);
//   env->SetProtoMethodNoSideEffect(t, "getSymmetricKeySize",
//                                   GetSymmetricKeySize);
//   env->SetProtoMethodNoSideEffect(t, "getAsymmetricKeyType",
//                                   GetAsymmetricKeyType);
//   env->SetProtoMethod(t, "export", Export);
//   env->SetProtoMethod(t, "exportJwk", ExportJWK);
//   env->SetProtoMethod(t, "initECRaw", InitECRaw);
//   env->SetProtoMethod(t, "initEDRaw", InitEDRaw);
//   env->SetProtoMethod(t, "initJwk", InitJWK);
//   env->SetProtoMethod(t, "keyDetail", GetKeyDetail);
//   env->SetProtoMethod(t, "equals", Equals);
//
//   auto function = t->GetFunction(env->context()).ToLocalChecked();
//   env->set_crypto_key_object_handle_constructor(function);
//   return function;
// }
//
// void KeyObjectHandle::RegisterExternalReferences(
//                                                  ExternalReferenceRegistry*
//                                                  registry) {
//   registry->Register(New);
//   registry->Register(Init);
//   registry->Register(GetSymmetricKeySize);
//   registry->Register(GetAsymmetricKeyType);
//   registry->Register(Export);
//   registry->Register(ExportJWK);
//   registry->Register(InitECRaw);
//   registry->Register(InitEDRaw);
//   registry->Register(InitJWK);
//   registry->Register(GetKeyDetail);
//   registry->Register(Equals);
// }

// std::shared_ptr<KeyObjectHandle> KeyObjectHandle::Create(std::string data) {
//   auto handle = std::make_shared<KeyObjectHandle>();
//   handle->string_ = data;
//   return handle;
// }

// std::shared_ptr<KeyObjectHandle> KeyObjectHandle::Create(ByteSource data) {
//   auto handle = std::make_shared<KeyObjectHandle>();
//   handle->bytesource_ = data;
//   return handle;
// }

// std::shared_ptr<KeyObjectHandle> KeyObjectHandle::Create(std::shared_ptr<KeyObjectData> data) {
//   auto handle = std::make_shared<KeyObjectHandle>();
//   handle->data_ = data;
//   return handle;
// }


const std::shared_ptr<KeyObjectData>& KeyObjectHandle::Data() {
  return this->data_;
}
//
// void KeyObjectHandle::New(const FunctionCallbackInfo<Value>& args) {
//   CHECK(args.IsConstructCall());
//   Environment* env = Environment::GetCurrent(args);
//   new KeyObjectHandle(env, args.This());
// }
//
// KeyObjectHandle::KeyObjectHandle(Environment* env,
//                                  Local<Object> wrap)
//: BaseObject(env, wrap) {
//  MakeWeak();
//}
//

jsi::Value KeyObjectHandle::Init(jsi::Runtime &rt) {
  return HOSTFN("init", 2) {
    CHECK(args[0].isNumber());
    KeyType type = static_cast<KeyType>((int32_t)args[0].asNumber());

    unsigned int offset;
    ManagedEVPPKey pkey;

    switch (type) {
      case kKeyTypeSecret: {
        // CHECK_EQ(args.Length(), 2);

        ByteSource key = ByteSource::FromStringOrBuffer(rt, args[1]);
        this->data_ = KeyObjectData::CreateSecret(std::move(key));
        break;
      }
      case kKeyTypePublic: {
        // CHECK_EQ(args.Length(), 5);

        offset = 1;
        pkey = ManagedEVPPKey::GetPublicOrPrivateKeyFromJs(rt, args, &offset);
        if (!pkey)
          return false;
        this->data_ = std::make_shared<KeyObjectData>(
          KeyObjectData::CreateAsymmetric(type, pkey));
        break;
      }
      case kKeyTypePrivate: {
        // CHECK_EQ(args.Length(), 5);

        offset = 1;
        pkey = ManagedEVPPKey::GetPrivateKeyFromJs(rt, args, &offset, false);
        if (!pkey)
          return false;
        this->data_ = std::make_shared<KeyObjectData>(
          KeyObjectData::CreateAsymmetric(type, pkey));
        break;
      }
      default:
        throw jsi::JSError(rt, "invalid keytype for init(): " + std::to_string(type));
    }

    return true;
  });
}

jsi::Value KeyObjectHandle::InitJWK(jsi::Runtime &rt) {
  return HOSTFN("initJwk", 2) {
    // The argument must be a JavaScript object that we will inspect
    // to get the JWK properties from.
    jsi::Object jwk = jsi::Object(jsi::Value(rt, args[0]).asObject(rt));
    jsi::Value namedCurve;
    if (count == 2)
      namedCurve = jsi::Value(rt, args[1]);

    // Step one, Secret key or not?
    std::string kty = jwk
      .getProperty(rt, "kty")
      .asString(rt)
      .utf8(rt);

    if (kty.compare("oct") == 0) {
      // Secret key
      this->data_ = ImportJWKSecretKey(rt, jwk);
      if (!this->data_) {
        // ImportJWKSecretKey is responsible for throwing an appropriate error
        return jsi::Value::undefined();
      }
    } else {
      this->data_ = ImportJWKAsymmetricKey(rt, jwk, kty, namedCurve);
      if (!this->data_) {
        // ImportJWKAsymmetricKey is responsible for throwing an appropriate
        // error
       return jsi::Value::undefined();
      }
    }

    return static_cast<int>(this->data_->GetKeyType());
  });
}

jsi::Value KeyObjectHandle::InitECRaw(jsi::Runtime &rt) {
  return HOSTFN("initECRaw", 2) {
      CHECK(args[0].isString());
      std::string curveName = args[0].asString(rt).utf8(rt);
      int id = OBJ_txt2nid(curveName.c_str());
      ECKeyPointer eckey(EC_KEY_new_by_curve_name(id));
      if (!eckey) {
          return false;
      }

      CHECK(args[1].isObject());
      if (!args[1].getObject(rt).isArrayBuffer(rt)) {
        throw jsi::JSError(rt,
                          "KeyObjectHandle::InitECRaw: second argument "
                          "has to be of type ArrayBuffer!");
      }
      auto buf = args[1].asObject(rt).getArrayBuffer(rt);

      const EC_GROUP* group = EC_KEY_get0_group(eckey.get());
      ECPointPointer pub(ECDH::BufferToPoint(rt, group, buf));

      if (!pub ||
          !eckey ||
          !EC_KEY_set_public_key(eckey.get(), pub.get())) {
          return false;
      }

      EVPKeyPointer pkey(EVP_PKEY_new());
      if (!EVP_PKEY_assign_EC_KEY(pkey.get(), eckey.get())) {
          return false;
      }

      eckey.release();  // Release ownership of the key

      this->data_ = std::make_shared<KeyObjectData>(
        KeyObjectData::CreateAsymmetric(kKeyTypePublic,
                                        ManagedEVPPKey(std::move(pkey))));

      return true;
  });
}

// void KeyObjectHandle::InitEDRaw(const FunctionCallbackInfo<Value>& args) {
//  Environment* env = Environment::GetCurrent(args);
//  KeyObjectHandle* key;
//  ASSIGN_OR_RETURN_UNWRAP(&key, args.Holder());
//
//  CHECK(args[0]->IsString());
//  Utf8Value name(env->isolate(), args[0]);
//
//  ArrayBufferOrViewContents<unsigned char> key_data(args[1]);
//  KeyType type = static_cast<KeyType>(args[2].As<Int32>()->Value());
//
//  MarkPopErrorOnReturn mark_pop_error_on_return;
//
//  typedef EVP_PKEY* (*new_key_fn)(int, ENGINE*, const unsigned char*,
//  size_t); new_key_fn fn = type == kKeyTypePrivate ?
//  EVP_PKEY_new_raw_private_key : EVP_PKEY_new_raw_public_key;
//
//  int id = GetOKPCurveFromName(*name);
//
//  switch (id) {
//    case EVP_PKEY_X25519:
//    case EVP_PKEY_X448:
//    case EVP_PKEY_ED25519:
//    case EVP_PKEY_ED448: {
//      EVPKeyPointer pkey(fn(id, nullptr, key_data.data(), key_data.size()));
//      if (!pkey)
//        return args.GetReturnValue().Set(false);
//      key->data_ =
//      KeyObjectData::CreateAsymmetric(
//                                      type,
//                                      ManagedEVPPKey(std::move(pkey)));
//      CHECK(key->data_);
//      break;
//    }
//    default:
//      throw jsi::JSError(rt, "unreachable code in InitEDRaw");
//  }
//
//  args.GetReturnValue().Set(true);
//}
//
// void KeyObjectHandle::Equals(const FunctionCallbackInfo<Value>& args) {
//  KeyObjectHandle* self_handle;
//  KeyObjectHandle* arg_handle;
//  ASSIGN_OR_RETURN_UNWRAP(&self_handle, args.Holder());
//  ASSIGN_OR_RETURN_UNWRAP(&arg_handle, args[0].As<Object>());
//  std::shared_ptr<KeyObjectData> key = self_handle->Data();
//  std::shared_ptr<KeyObjectData> key2 = arg_handle->Data();
//
//  KeyType key_type = key->GetKeyType();
//  CHECK_EQ(key_type, key2->GetKeyType());
//
//  bool ret;
//  switch (key_type) {
//    case kKeyTypeSecret: {
//      size_t size = key->GetSymmetricKeySize();
//      if (size == key2->GetSymmetricKeySize()) {
//        ret = CRYPTO_memcmp(
//                            key->GetSymmetricKey(),
//                            key2->GetSymmetricKey(),
//                            size) == 0;
//      } else {
//        ret = false;
//      }
//      break;
//    }
//    case kKeyTypePublic:
//    case kKeyTypePrivate: {
//      EVP_PKEY* pkey = key->GetAsymmetricKey().get();
//      EVP_PKEY* pkey2 = key2->GetAsymmetricKey().get();
//#if OPENSSL_VERSION_MAJOR >= 3
//      int ok = EVP_PKEY_eq(pkey, pkey2);
//#else
//      int ok = EVP_PKEY_cmp(pkey, pkey2);
//#endif
//      if (ok == -2) {
//        Environment* env = Environment::GetCurrent(args);
//        return THROW_ERR_CRYPTO_UNSUPPORTED_OPERATION(env);
//      }
//      ret = ok == 1;
//      break;
//    }
//    default:
//        throw jsi::JSError(rt, "unreachable code in Equals");
//  }
//
//  args.GetReturnValue().Set(ret);
//}

jsi::Value KeyObjectHandle::GetKeyDetail(jsi::Runtime &rt) {
  return HOSTFN("keyDetail", 0) {
    std::shared_ptr<KeyObjectData> data = this->Data();

    switch (data->GetKeyType()) {
      case kKeyTypeSecret:
        return GetSecretKeyDetail(rt, data);
        break;
      case kKeyTypePublic:
        // Fall through
      case kKeyTypePrivate:
        return GetAsymmetricKeyDetail(rt, data);
        break;
      default:
        throw jsi::JSError(rt, "unreachable code in GetKeyDetail");
    }
  });
}

// Local<Value> KeyObjectHandle::GetAsymmetricKeyType() const {
//  const ManagedEVPPKey& key = data_->GetAsymmetricKey();
//  switch (EVP_PKEY_id(key.get())) {
//    case EVP_PKEY_RSA:
//      return env()->crypto_rsa_string();
//    case EVP_PKEY_RSA_PSS:
//      return env()->crypto_rsa_pss_string();
//    case EVP_PKEY_DSA:
//      return env()->crypto_dsa_string();
//    case EVP_PKEY_DH:
//      return env()->crypto_dh_string();
//    case EVP_PKEY_EC:
//      return env()->crypto_ec_string();
//    case EVP_PKEY_ED25519:
//      return env()->crypto_ed25519_string();
//    case EVP_PKEY_ED448:
//      return env()->crypto_ed448_string();
//    case EVP_PKEY_X25519:
//      return env()->crypto_x25519_string();
//    case EVP_PKEY_X448:
//      return env()->crypto_x448_string();
//    default:
//      return Undefined(env()->isolate());
//  }
//}
//
// void KeyObjectHandle::GetAsymmetricKeyType(
//                                           const
//                                           FunctionCallbackInfo<Value>&
//                                           args) {
//  KeyObjectHandle* key;
//  ASSIGN_OR_RETURN_UNWRAP(&key, args.Holder());
//
//  args.GetReturnValue().Set(key->GetAsymmetricKeyType());
//}
//
// void KeyObjectHandle::GetSymmetricKeySize(
//                                          const FunctionCallbackInfo<Value>&
//                                          args) {
//  KeyObjectHandle* key;
//  ASSIGN_OR_RETURN_UNWRAP(&key, args.Holder());
//  args.GetReturnValue().Set(
//                            static_cast<uint32_t>(key->Data()->GetSymmetricKeySize()));
//}

jsi::Value KeyObjectHandle::Export(jsi::Runtime &rt) {
  return HOSTFN("export", 2) {
    KeyType type = this->data_->GetKeyType();
    jsi::Value result;
    if (type == kKeyTypeSecret) {
      result = this->ExportSecretKey(rt);
    }
    else if (type == kKeyTypePublic) {
      unsigned int offset = 0;
      PublicKeyEncodingConfig config =
          ManagedEVPPKey::GetPublicKeyEncodingFromJs(
              rt, args, &offset, kKeyContextExport);
      result = this->ExportPublicKey(rt, config);
    }
    else if (type == kKeyTypePrivate) {
      unsigned int offset = 0;
      NonCopyableMaybe<PrivateKeyEncodingConfig> config =
          ManagedEVPPKey::GetPrivateKeyEncodingFromJs(
              rt, args, &offset, kKeyContextExport);
      if (!config.IsEmpty()) {
        result = this->ExportPrivateKey(rt, config.Release());
      }
    }
    return result;
  });
}

jsi::Value KeyObjectHandle::ExportSecretKey(jsi::Runtime &rt) const {
  std::string ret = data_->GetSymmetricKey();
  return toJSI(rt, JSVariant(ret));
}

jsi::Value KeyObjectHandle::ExportPublicKey(
    jsi::Runtime& rt,
    const PublicKeyEncodingConfig& config) const {
  return WritePublicKey(data_->GetAsymmetricKey().get(), config);
}

jsi::Value KeyObjectHandle::ExportPrivateKey(
    jsi::Runtime &rt,
    const PrivateKeyEncodingConfig& config) const {
  auto key = WritePrivateKey(data_->GetAsymmetricKey().get(), config);
  return toJSI(rt, key);
}

jsi::Value KeyObjectHandle::ExportJWK(jsi::Runtime &rt) {
  return HOSTFN("exportJwk", 2) {
    CHECK(args[0].isObject());
    CHECK(args[1].isBool());
    std::shared_ptr<KeyObjectData> data = this->Data();
    jsi::Object result = args[0].asObject(rt);
    return ExportJWKInner(rt, data, result, args[1].asBool());
  });
}

// void NativeKeyObject::Initialize(Environment* env, Local<Object> target) {
//  env->SetMethod(target, "createNativeKeyObjectClass",
//                 NativeKeyObject::CreateNativeKeyObjectClass);
//}
//
// void NativeKeyObject::RegisterExternalReferences(
//                                                 ExternalReferenceRegistry*
//                                                 registry) {
//  registry->Register(NativeKeyObject::CreateNativeKeyObjectClass);
//  registry->Register(NativeKeyObject::New);
//}
//
// void NativeKeyObject::New(const FunctionCallbackInfo<Value>& args) {
//  Environment* env = Environment::GetCurrent(args);
//  CHECK_EQ(args.Length(), 1);
//  CHECK(args[0]->IsObject());
//  KeyObjectHandle* handle = Unwrap<KeyObjectHandle>(args[0].As<Object>());
//  new NativeKeyObject(env, args.This(), handle->Data());
//}
//
// void NativeKeyObject::CreateNativeKeyObjectClass(
//                                                 const
//                                                 FunctionCallbackInfo<Value>&
//                                                 args) {
//  Environment* env = Environment::GetCurrent(args);
//
//  CHECK_EQ(args.Length(), 1);
//  Local<Value> callback = args[0];
//  CHECK(callback->IsFunction());
//
//  Local<FunctionTemplate> t =
//  env->NewFunctionTemplate(NativeKeyObject::New);
//  t->InstanceTemplate()->SetInternalFieldCount(
//                                               KeyObjectHandle::kInternalFieldCount);
//  t->Inherit(BaseObject::GetConstructorTemplate(env));
//
//  Local<Value> ctor;
//  if (!t->GetFunction(env->context()).ToLocal(&ctor))
//    return;
//
//  Local<Value> recv = Undefined(env->isolate());
//  Local<Value> ret_v;
//  if (!callback.As<Function>()->Call(
//                                     env->context(), recv, 1,
//                                     &ctor).ToLocal(&ret_v)) {
//                                       return;
//                                     }
//  Local<Array> ret = ret_v.As<Array>();
//  if (!ret->Get(env->context(), 1).ToLocal(&ctor)) return;
//  env->set_crypto_key_object_secret_constructor(ctor.As<Function>());
//  if (!ret->Get(env->context(), 2).ToLocal(&ctor)) return;
//  env->set_crypto_key_object_public_constructor(ctor.As<Function>());
//  if (!ret->Get(env->context(), 3).ToLocal(&ctor)) return;
//  env->set_crypto_key_object_private_constructor(ctor.As<Function>());
//  args.GetReturnValue().Set(ret);
//}
//
// BaseObjectPtr<BaseObject>
// NativeKeyObject::KeyObjectTransferData::Deserialize(
//                                                        Environment* env,
//                                                        Local<Context>
//                                                        context,
//                                                        std::unique_ptr<worker::TransferData>
//                                                        self) {
//  if (context != env->context()) {
//    THROW_ERR_MESSAGE_TARGET_CONTEXT_UNAVAILABLE(env);
//    return {};
//  }
//
//  Local<Value> handle;
//  if (!KeyObjectHandle::Create(env, data_).ToLocal(&handle))
//    return {};
//
//  Local<Function> key_ctor;
//  Local<Value> arg = FIXED_ONE_BYTE_STRING(env->isolate(),
//                                           "internal/crypto/keys");
//  if (env->native_module_require()->
//      Call(context, Null(env->isolate()), 1, &arg).IsEmpty()) {
//    return {};
//  }
//  switch (data_->GetKeyType()) {
//    case kKeyTypeSecret:
//      key_ctor = env->crypto_key_object_secret_constructor();
//      break;
//    case kKeyTypePublic:
//      key_ctor = env->crypto_key_object_public_constructor();
//      break;
//    case kKeyTypePrivate:
//      key_ctor = env->crypto_key_object_private_constructor();
//      break;
//    default:
//      CHECK(false);
//  }
//
//  Local<Value> key;
//  if (!key_ctor->NewInstance(context, 1, &handle).ToLocal(&key))
//    return {};
//
//  return
//  BaseObjectPtr<BaseObject>(Unwrap<KeyObjectHandle>(key.As<Object>()));
//}
//
// BaseObject::TransferMode NativeKeyObject::GetTransferMode() const {
//  return BaseObject::TransferMode::kCloneable;
//}
//
// std::unique_ptr<worker::TransferData> NativeKeyObject::CloneForMessaging()
// const {
//  return std::make_unique<KeyObjectTransferData>(handle_data_);
//}
//
// WebCryptoKeyExportStatus PKEY_SPKI_Export(
//                                          KeyObjectData* key_data,
//                                          ByteSource* out) {
//  CHECK_EQ(key_data->GetKeyType(), kKeyTypePublic);
//  ManagedEVPPKey m_pkey = key_data->GetAsymmetricKey();
//  Mutex::ScopedLock lock(*m_pkey.mutex());
//  BIOPointer bio(BIO_new(BIO_s_mem()));
//  CHECK(bio);
//  if (!i2d_PUBKEY_bio(bio.get(), m_pkey.get()))
//    return WebCryptoKeyExportStatus::FAILED;
//
//  *out = ByteSource::FromBIO(bio);
//  return WebCryptoKeyExportStatus::OK;
//}
//
// WebCryptoKeyExportStatus PKEY_PKCS8_Export(
//                                           KeyObjectData* key_data,
//                                           ByteSource* out) {
//  CHECK_EQ(key_data->GetKeyType(), kKeyTypePrivate);
//  ManagedEVPPKey m_pkey = key_data->GetAsymmetricKey();
//  Mutex::ScopedLock lock(*m_pkey.mutex());
//
//  BIOPointer bio(BIO_new(BIO_s_mem()));
//  CHECK(bio);
//  PKCS8Pointer p8inf(EVP_PKEY2PKCS8(m_pkey.get()));
//  if (!i2d_PKCS8_PRIV_KEY_INFO_bio(bio.get(), p8inf.get()))
//    return WebCryptoKeyExportStatus::FAILED;
//
//  *out = ByteSource::FromBIO(bio);
//  return WebCryptoKeyExportStatus::OK;
//}

//  void RegisterExternalReferences(ExternalReferenceRegistry * registry) {
//    KeyObjectHandle::RegisterExternalReferences(registry);
//  }

}  // namespace margelo
