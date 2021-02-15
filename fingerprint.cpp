/*
 * Copyright (C) 2021 Marijn Suijten
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Conversion notes:
// - RequestStatus from the HAL is analogous to errno types, as mentioned in fingerprint.h header docs

#define LOG_TAG "AOSP FPC HAL"

#include "SynchronizedWorkerThread.h"

// #include <errno.h>
// #include <malloc.h>
// #include <stdio.h>
// #include <string.h>
#include <hardware/fingerprint.h>
#include <hardware/hardware.h>
#include <log/log.h>
// #include <inttypes.h>
// #include <pthread.h>
// #include <netinet/in.h>
// #include <byteswap.h>
// #include <sys/stat.h>
// #include "fpc_imp.h"
// #include <unistd.h>

#include <mutex>

extern "C" {
#include "fpc_imp.h"
}

struct BiometricsFingerprint : public ::SynchronizedWorker::WorkHandler {
    fingerprint_device_t hw;  // "inheritance"

   public:
    BiometricsFingerprint();
    ~BiometricsFingerprint();

    // Methods from ::android::hardware::biometrics::fingerprint::V2_1::IBiometricsFingerprint follow.
    uint64_t setNotify(fingerprint_notify_t clientCallback);
    uint64_t preEnroll();
    int enroll(const hw_auth_token_t *hat, uint32_t gid, uint32_t timeoutSec);
    int postEnroll();
    uint64_t getAuthenticatorId();
    int cancel();
    int enumerate();
    int remove(uint32_t gid, uint32_t fid);
    int setActiveGroup(uint32_t gid, const char *storePath);
    int authenticate(uint64_t operationId, uint32_t gid);

    // Methods from ::SynchronizedWorker::WorkHandler
    inline ::SynchronizedWorker::Thread &getWorker() override {
        return mWt;
    }
    void AuthenticateAsync() override;
    void EnrollAsync() override;
    void IdleAsync() override;

   private:
    static int ErrorFilter(int32_t error);

    // Internal machinery to set the active group
    int __setActiveGroup(uint32_t gid);

    ::SynchronizedWorker::Thread mWt;
    char db_path[255];
    fpc_imp_data_t *fpc = nullptr;
    std::mutex mClientCallbackMutex;
    uint32_t gid;
    uint64_t auth_challenge, enroll_challenge;
};

static BiometricsFingerprint *dev_to_bf(fingerprint_device_t *dev) {
    return (BiometricsFingerprint *)((uint8_t *)dev - offsetof(BiometricsFingerprint, hw));
}

static BiometricsFingerprint *hw_dev_to_bf(hw_device_t *dev) {
    return dev_to_bf((fingerprint_device_t *)((uint8_t *)dev - offsetof(fingerprint_device_t, common)));
}

static int fingerprint_close(hw_device_t *dev) {
    auto sdev = hw_dev_to_bf(dev);
    delete sdev;
    return 0;
}

static uint64_t fingerprint_pre_enroll(struct fingerprint_device *dev) {
    auto sdev = dev_to_bf(dev);
    return sdev->preEnroll();
}

static int fingerprint_enroll(struct fingerprint_device *dev,
                              const hw_auth_token_t *hat,
                              uint32_t gid,
                              uint32_t timeout_sec) {
    auto sdev = dev_to_bf(dev);
    return sdev->enroll(hat, gid, timeout_sec);
}

static int fingerprint_post_enroll(struct fingerprint_device *dev) {
    auto sdev = dev_to_bf(dev);
    return sdev->postEnroll();
}

static uint64_t fingerprint_get_auth_id(struct fingerprint_device *dev) {
    auto sdev = dev_to_bf(dev);
    return sdev->getAuthenticatorId();
}

static int fingerprint_cancel(struct fingerprint_device *dev) {
    auto sdev = dev_to_bf(dev);
    return sdev->cancel();
}

static int fingerprint_remove(struct fingerprint_device *dev,
                              uint32_t gid, uint32_t fid) {
    auto sdev = dev_to_bf(dev);
    return sdev->remove(gid, fid);
}

static int fingerprint_set_active_group(struct fingerprint_device *dev,
                                        uint32_t gid, const char *store_path) {
    auto sdev = dev_to_bf(dev);
    return sdev->setActiveGroup(gid, store_path);
}

#if PLATFORM_SDK_VERSION >= 24
static int fingerprint_enumerate(struct fingerprint_device *dev) {
    auto sdev = dev_to_bf(dev);
    return sdev->enumerate();
}
#else
// Not implemented, compiler error for now.
// static int fingerprint_enumerate(struct fingerprint_device *dev,
//                                  fingerprint_finger_id_t *results,
//                                  uint32_t *max_size) {
// }
#endif

static int fingerprint_authenticate(struct fingerprint_device *dev,
                                    uint64_t operation_id, uint32_t gid) {
    auto sdev = dev_to_bf(dev);
    return sdev->authenticate(operation_id, gid);
}

static int set_notify_callback(struct fingerprint_device *dev,
                               fingerprint_notify_t notify) {
    auto sdev = dev_to_bf(dev);
    return sdev->setNotify(notify);
}

static int fingerprint_open(const hw_module_t *module, const char __attribute__((unused)) * id,
                            hw_device_t **device) {
    if (!device) {
        ALOGE("NULL device on open");
        return -EINVAL;
    }

    auto fpc = new BiometricsFingerprint();
    auto dev = &fpc->hw;

    dev->common.tag = HARDWARE_DEVICE_TAG;
#if PLATFORM_SDK_VERSION >= 24
    dev->common.version = FINGERPRINT_MODULE_API_VERSION_2_1;
#else
    dev->common.version = FINGERPRINT_MODULE_API_VERSION_2_0;
#endif
    dev->common.module = (struct hw_module_t *)module;
    dev->common.close = fingerprint_close;

    dev->pre_enroll = fingerprint_pre_enroll;
    dev->enroll = fingerprint_enroll;
    dev->post_enroll = fingerprint_post_enroll;
    dev->get_authenticator_id = fingerprint_get_auth_id;
    dev->cancel = fingerprint_cancel;
    dev->remove = fingerprint_remove;
    dev->set_active_group = fingerprint_set_active_group;
    dev->enumerate = fingerprint_enumerate;
    dev->authenticate = fingerprint_authenticate;
    dev->set_notify = set_notify_callback;
    dev->notify = nullptr;

    *device = &fpc->hw.common;

    return 0;
}

static struct hw_module_methods_t fingerprint_module_methods = {
    .open = fingerprint_open,
};

__BEGIN_DECLS

fingerprint_module_t HAL_MODULE_INFO_SYM = {
    .common = {
        .tag = HARDWARE_MODULE_TAG,
#if PLATFORM_SDK_VERSION >= 24
        .module_api_version = FINGERPRINT_MODULE_API_VERSION_2_1,
#else
        .module_api_version = FINGERPRINT_MODULE_API_VERSION_2_0,
#endif
        .hal_api_version = HARDWARE_HAL_API_VERSION,
        .id = FINGERPRINT_HARDWARE_MODULE_ID,
        .name = "Sony OSS Fingerprint HAL",
        .author = "Marijn Suijten",
        .methods = &fingerprint_module_methods,
    },
};

__END_DECLS
