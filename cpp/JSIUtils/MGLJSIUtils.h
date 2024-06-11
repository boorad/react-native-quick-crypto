//
//  MGLJSIUtils.h
//  Pods
//
//  Created by Oscar on 20.06.22.
//

#ifndef MGLJSIUtils_h
#define MGLJSIUtils_h

#include <jsi/jsi.h>
#include <limits>

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

inline bool CheckIsArrayBuffer(jsi::Runtime &runtime, const jsi::Value &value) {
  return !value.isNull() && !value.isUndefined() && value.isObject() &&
         value.asObject(runtime).isArrayBuffer(runtime);
}

inline bool CheckSizeInt32(jsi::Runtime &runtime, jsi::ArrayBuffer &buffer) {
  return buffer.size(runtime) <= INT_MAX;
}

inline bool CheckIsInt32(const jsi::Value &value) {
  if (!value.isNumber()) {
    return false;
  }
  double d = value.getNumber();
  return (d >= std::numeric_limits<int32_t>::lowest() && d <= std::numeric_limits<int32_t>::max());
}

}  // namespace margelo

#endif /* MGLJSIUtils_h */
