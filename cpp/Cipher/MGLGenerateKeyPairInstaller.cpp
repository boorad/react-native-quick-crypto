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
#include "KeyPairGen.h"

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

        // prepare key pair generator
        KeyVariant variant =
          static_cast<KeyVariant>((int)arguments[0].getNumber());
        auto keyPairGen = GetKeyPairGen(variant);
        keyPairGen->PrepareConfig(runtime, arguments);

        // run key pair generation in a separate thread
        std::thread t([variant, keyPairGen]() {
          m.lock();
          try {
            keyPairGen->GenerateKeyPair();
          } catch (std::exception e) {
            m.unlock();
            throw e;
          }
          m.unlock();
        });
        t.join();

        // return key pair as JSI promise
        auto promiseConstructor =
            runtime.global().getPropertyAsFunction(runtime, "Promise");

        auto promise = promiseConstructor.callAsConstructor(
            runtime,
            jsi::Function::createFromHostFunction(
                runtime,
                jsi::PropNameID::forAscii(runtime, "executor"),
                1,
                [keyPairGen](
                    jsi::Runtime &runtime, const jsi::Value &,
                    const jsi::Value *promiseArgs, size_t) -> jsi::Value {
                  auto resolve =
                      std::make_shared<jsi::Value>(runtime, promiseArgs[0]);
                  auto reject =
                      std::make_shared<jsi::Value>(runtime, promiseArgs[1]);

                  try {
                    auto res = jsi::Array::createWithElements(
                      runtime,
                      jsi::Value::undefined(),
                      keyPairGen->GetJsiPublicKey(runtime),
                      keyPairGen->GetJsiPrivateKey(runtime));
                    resolve->asObject(runtime).asFunction(runtime).call(
                        runtime, res);
                  } catch (std::exception e) {
                    auto res = jsi::Array::createWithElements(
                      runtime,
                      jsi::String::createFromUtf8(
                        runtime, "Error generating key"),
                      jsi::Value::undefined(),
                      jsi::Value::undefined());
                    reject->asObject(runtime).asFunction(runtime).call(
                        runtime, std::move(res));
                  }

                }));

        return promise;
      });
}

std::shared_ptr<KeyPairGen> GetKeyPairGen(KeyVariant variant) {
  switch (variant) {
    case kvRSA_SSA_PKCS1_v1_5:
    case kvRSA_PSS:
    case kvRSA_OAEP:
      return std::make_shared<KeyPairGen>(RsaKeyPairGen());
      break;
    case kvEC:
      return std::make_shared<KeyPairGen>(EcKeyPairGen());
      break;
    default:
      throw std::runtime_error("KeyVariant not implemented"
        + std::to_string((int)variant));
  }
};

}  // namespace margelo
