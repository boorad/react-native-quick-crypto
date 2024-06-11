#ifndef JSVariant_h
#define JSVariant_h

#include <jsi/jsi.h>
#include "MGLUtils.h"       // for ByteSource
#include "KeyObjectData.h"  // for KeyObjectData

namespace margelo {

namespace jsi = facebook::jsi;

using JSVariant = std::variant<nullptr_t, std::string, ByteSource, KeyObjectData>;

inline jsi::Value toJSI(jsi::Runtime& rt, JSVariant value) {
  if (std::holds_alternative<std::string>(value)) {
    return jsi::String::createFromUtf8(rt, std::get<std::string>(value));
  } else if (std::holds_alternative<ByteSource>(value)) {
    ByteSource& source = std::get<ByteSource>(value);
    jsi::Function array_buffer_ctor =
        rt.global().getPropertyAsFunction(rt, "ArrayBuffer");
    jsi::Object o = array_buffer_ctor.callAsConstructor(rt, (int)source.size())
                        .getObject(rt);
    jsi::ArrayBuffer buf = o.getArrayBuffer(rt);
    // You cannot share raw memory between native and JS
    // always copy the data
    // see https://github.com/facebook/hermes/pull/419 and
    // https://github.com/facebook/hermes/issues/564.
    memcpy(buf.data(rt), source.data(), source.size());
    return o;
  } else if (std::holds_alternative<KeyObjectData>(value)) {
    // inline static jsi::Value toJSI(jsi::Runtime& rt, std::shared_ptr<KeyObjectData> data) {
    //   auto handle = KeyObjectHandle::Create(data);
    //   auto out = jsi::Object::createFromHostObject(rt, handle);
    //   return jsi::Value(std::move(out));
    // };
  } else {
    return jsi::Value::null();
  }
}

inline JSVariant ToEncodedPublicKey(ManagedEVPPKey key,
                                    const PublicKeyEncodingConfig& config) {
  if (!key) return JSVariant(nullptr);
  if (config.output_key_object_) {
    // Note that this has the downside of containing sensitive data of the
    // private key.
    auto data = KeyObjectData::CreateAsymmetric(kKeyTypePublic, std::move(key));
    return JSVariant(data);
  } else
  if (config.format_ == kKeyFormatJWK) {
    throw std::runtime_error("ToEncodedPublicKey 2 (JWK) not implemented from node");
    // std::shared_ptr<KeyObjectData> data =
    // KeyObjectData::CreateAsymmetric(kKeyTypePublic, std::move(key));
    // *out = Object::New(env->isolate());
    // return ExportJWKInner(env, data, *out, false);
  }

  return WritePublicKey(key.get(), config);
}

inline JSVariant ToEncodedPrivateKey(ManagedEVPPKey key,
                                     const PrivateKeyEncodingConfig& config) {
  if (!key) return JSVariant({});
  if (config.output_key_object_) {
    auto data = KeyObjectData::CreateAsymmetric(kKeyTypePrivate, std::move(key));
    return JSVariant(data);
  } else
  if (config.format_ == kKeyFormatJWK) {
    throw std::runtime_error("ToEncodedPrivateKey 2 (JWK) not implemented from node");
    // std::shared_ptr<KeyObjectData> data =
    // KeyObjectData::CreateAsymmetric(kKeyTypePrivate, std::move(key));
    // *out = Object::New(env->isolate());
    // return ExportJWKInner(env, data, *out, false);
  }

  return WritePrivateKey(key.get(), config);
}

} // namespace margelo

#endif /* JSVariant_h */
