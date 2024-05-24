//
//  MGLGenerateKeyPairInstaller.cpp
//  react-native-quick-crypto
//
//  Created by Oscar on 24.06.22.
//

#include "MGLGenerateKeyPairInstaller.h"

#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>

#include "MGLRsa.h"

#ifdef ANDROID
#include "JSIUtils/MGLJSIMacros.h"
#include "JSIUtils/MGLTypedArray.h"
#include "webcrypto/crypto_ec.h"
#else
#include "MGLJSIMacros.h"
#include "MGLTypedArray.h"
#include "crypto_ec.h"
#endif

using namespace facebook;

namespace margelo {

std::mutex m;

FieldDefinition getGenerateKeyPairFieldDefinition(
    std::shared_ptr<react::CallInvoker> jsCallInvoker,
    std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue) {
  return buildPair(
      "generateKeyPair", JSIF([=]) {

        if (!arguments[0].isNumber()) {
          throw jsi::JSError(runtime, "KeyVariant is not a number");
        }
        KeyVariant variant =
          static_cast<KeyVariant>((int)arguments[0].getNumber());
        KeyPairGen keyPairGen;

        // prepare configuration
        keyPairGen->PrepareConfig(runtime, arguments);

        auto promiseConstructor =
            runtime.global().getPropertyAsFunction(runtime, "Promise");

        auto promise = promiseConstructor.callAsConstructor(
            runtime,
            jsi::Function::createFromHostFunction(
                runtime,
                jsi::PropNameID::forAscii(runtime, "executor"),
                4,
                [&jsCallInvoker, keyPairGen](
                    jsi::Runtime &runtime, const jsi::Value &,
                    const jsi::Value *promiseArgs, size_t) -> jsi::Value {
                  auto resolve =
                      std::make_shared<jsi::Value>(runtime, promiseArgs[0]);
                  auto reject =
                      std::make_shared<jsi::Value>(runtime, promiseArgs[1]);

                  std::thread t([&runtime, resolve, reject, jsCallInvoker,
                      variant, config]() {
                    m.lock();
                    try {
                      jsCallInvoker->invokeAsync([&runtime, resolve,
                          variant, config]() {
                        std::pair<jsi::Value, jsi::Value> keys;

                        // switch on variant to get proper generateKeyPair
                        if (variant == kvRSA_SSA_PKCS1_v1_5 ||
                            variant == kvRSA_PSS ||
                            variant == kvRSA_OAEP
                        ) {
                          keys = generateRsaKeyPair(runtime, config);
                        } else
                        if (variant == kvEC) {
                          keys = generateEcKeyPair(runtime, config);
                        } else {
                          throw std::runtime_error("KeyVariant not implemented"
                            + std::to_string((int)variant));
                        }

                        auto res = jsi::Array::createWithElements(
                          runtime,
                          jsi::Value::undefined(),
                          keys.first,
                          keys.second);
                        resolve->asObject(runtime).asFunction(runtime).call(
                            runtime, std::move(res));
                      });
                    } catch (std::exception e) {
                      jsCallInvoker->invokeAsync(
                          [&runtime, reject]() {
                            auto res = jsi::Array::createWithElements(
                              runtime,
                              jsi::String::createFromUtf8(
                                runtime, "Error generating key"),
                              jsi::Value::undefined(),
                              jsi::Value::undefined());
                            reject->asObject(runtime).asFunction(runtime).call(
                                runtime, std::move(res));
                          });
                    }
                    m.unlock();
                  });

                  t.detach();

                  return {};
                }));

        return promise;
      });
}

KeyPairGen GetKeyPairGen(KeyVariant variant) {
  switch (variant) {
    case kvRSA_SSA_PKCS1_v1_5:
    case kvRSA_PSS:
    case kvRSA_OAEP:
      return KeyPairGen<RsaKeyPairGen>();
      break;
    case kvEC:
      return KeyPairGen<EcKeyPairGen>();
      break;
    default:
      throw std::runtime_error("KeyVariant not implemented"
        + std::to_string((int)variant));
  }


};

}  // namespace margelo
