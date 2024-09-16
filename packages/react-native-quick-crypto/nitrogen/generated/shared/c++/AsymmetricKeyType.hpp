///
/// AsymmetricKeyType.hpp
/// This file was generated by nitrogen. DO NOT MODIFY THIS FILE.
/// https://github.com/mrousavy/nitro
/// Copyright © 2024 Marc Rousavy @ Margelo
///

#pragma once

#if __has_include(<NitroModules/NitroHash.hpp>)
#include <NitroModules/NitroHash.hpp>
#else
#error NitroModules cannot be found! Are you sure you installed NitroModules properly?
#endif
#if __has_include(<NitroModules/JSIConverter.hpp>)
#include <NitroModules/JSIConverter.hpp>
#else
#error NitroModules cannot be found! Are you sure you installed NitroModules properly?
#endif
#if __has_include(<NitroModules/NitroDefines.hpp>)
#include <NitroModules/NitroDefines.hpp>
#else
#error NitroModules cannot be found! Are you sure you installed NitroModules properly?
#endif

namespace margelo::nitro::crypto {

  /**
   * An enum which can be represented as a JavaScript union (AsymmetricKeyType).
   */
  enum class AsymmetricKeyType {
    RSA      SWIFT_NAME(rsa) = 0,
    RSA_PSS      SWIFT_NAME(rsaPss) = 1,
    DSA      SWIFT_NAME(dsa) = 2,
    EC      SWIFT_NAME(ec) = 3,
  } CLOSED_ENUM;

} // namespace margelo::nitro::crypto

namespace margelo::nitro {

  using namespace margelo::nitro::crypto;

  // C++ AsymmetricKeyType <> JS AsymmetricKeyType (union)
  template <>
  struct JSIConverter<AsymmetricKeyType> {
    static inline AsymmetricKeyType fromJSI(jsi::Runtime& runtime, const jsi::Value& arg) {
      std::string unionValue = JSIConverter<std::string>::fromJSI(runtime, arg);
      switch (hashString(unionValue.c_str(), unionValue.size())) {
        case hashString("rsa"): return AsymmetricKeyType::RSA;
        case hashString("rsa-pss"): return AsymmetricKeyType::RSA_PSS;
        case hashString("dsa"): return AsymmetricKeyType::DSA;
        case hashString("ec"): return AsymmetricKeyType::EC;
        default: [[unlikely]]
          throw std::runtime_error("Cannot convert \"" + unionValue + "\" to enum AsymmetricKeyType - invalid value!");
      }
    }
    static inline jsi::Value toJSI(jsi::Runtime& runtime, AsymmetricKeyType arg) {
      switch (arg) {
        case AsymmetricKeyType::RSA: return JSIConverter<std::string>::toJSI(runtime, "rsa");
        case AsymmetricKeyType::RSA_PSS: return JSIConverter<std::string>::toJSI(runtime, "rsa-pss");
        case AsymmetricKeyType::DSA: return JSIConverter<std::string>::toJSI(runtime, "dsa");
        case AsymmetricKeyType::EC: return JSIConverter<std::string>::toJSI(runtime, "ec");
        default: [[unlikely]]
          throw std::runtime_error("Cannot convert AsymmetricKeyType to JS - invalid value: "
                                    + std::to_string(static_cast<int>(arg)) + "!");
      }
    }
    static inline bool canConvert(jsi::Runtime& runtime, const jsi::Value& value) {
      if (!value.isString()) {
        return false;
      }
      std::string unionValue = JSIConverter<std::string>::fromJSI(runtime, value);
      switch (hashString(unionValue.c_str(), unionValue.size())) {
        case hashString("rsa"):
        case hashString("rsa-pss"):
        case hashString("dsa"):
        case hashString("ec"):
          return true;
        default:
          return false;
      }
    }
  };

} // namespace margelo::nitro
