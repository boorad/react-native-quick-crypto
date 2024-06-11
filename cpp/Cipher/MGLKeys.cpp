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

}  // namespace margelo
