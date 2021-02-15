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

#include <byteswap.h>
#include <hardware/fingerprint.h>
#include <hardware/hardware.h>
#include <inttypes.h>
#include <log/log.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <unistd.h>

#include <mutex>

extern "C" {
#include "fpc_imp.h"
}

using namespace ::SynchronizedWorker;

struct BiometricsFingerprint : public WorkHandler {
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
    // Internal machinery to set the active group
    int __setActiveGroup(uint32_t gid);

    // Internal callback helpers:
    inline void onAcquired(fingerprint_acquired_info_t acquired_info) {
        fingerprint_msg_t msg = {
            .type = FINGERPRINT_ACQUIRED,
            .data.acquired.acquired_info = acquired_info,
        };
        hw.notify(&msg);
    }
    inline void onAuthenticated(uint32_t fid, uint32_t gid, hw_auth_token_t *hat) {
        fingerprint_msg_t msg = {
            .type = FINGERPRINT_AUTHENTICATED,
            .data.authenticated.finger.fid = fid,
            .data.authenticated.finger.gid = gid,
        };

        if (hat)
            memcpy(&msg.data.authenticated.hat, hat, sizeof(*hat));

        hw.notify(&msg);
    }
    inline void onEnrollResult(uint32_t fid, uint32_t gid, uint32_t remaining_touches) {
        fingerprint_msg_t msg = {
            .type = FINGERPRINT_TEMPLATE_ENROLLING,
            .data.enroll.finger.fid = fid,
            .data.enroll.finger.gid = gid,
            .data.enroll.samples_remaining = remaining_touches,
        };
        hw.notify(&msg);
    }
    inline void onEnumerate(uint32_t fid, uint32_t gid, uint32_t remaining_templates) {
        fingerprint_msg_t msg = {
            .type = FINGERPRINT_TEMPLATE_ENUMERATING,
            .data.enumerated.finger.fid = fid,
            .data.enumerated.finger.gid = gid,
            .data.enumerated.remaining_templates = remaining_templates,
        };
        hw.notify(&msg);
    }
    inline void onError(fingerprint_error_t err) {
        fingerprint_msg_t msg = {
            .type = FINGERPRINT_ERROR,
            .data.error = err,
        };
        hw.notify(&msg);
    }

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

BiometricsFingerprint::BiometricsFingerprint() : mWt(this) {
    if (fpc_init(&fpc, mWt.getEventFd()) < 0)
        LOG_ALWAYS_FATAL("Could not init FPC device");

    mWt.Start();
}

BiometricsFingerprint::~BiometricsFingerprint() {
    ALOGV(__func__);
    if (fpc == nullptr) {
        ALOGE("%s: No valid device", __func__);
        return;
    }
    fpc_close(&fpc);
    // TODO: RAII only stops and joins the thread here, after fpc_close. Race conditions on resources?
}

uint64_t BiometricsFingerprint::setNotify(fingerprint_notify_t notify) {
    std::lock_guard<std::mutex> lock(mClientCallbackMutex);
    hw.notify = notify;
    return 0;
}

uint64_t BiometricsFingerprint::preEnroll() {
    enroll_challenge = fpc_load_auth_challenge(fpc);
    ALOGI("%s : Challenge is : %ju", __func__, enroll_challenge);
    return enroll_challenge;
}

int BiometricsFingerprint::enroll(const hw_auth_token_t *authToken,
                                  uint32_t gid,
                                  uint32_t timeoutSec) {
    if (gid != this->gid) {
        ALOGE("gid mismatch; change group and through setActiveGroup first!");
        return -EINVAL;
    }

    if (!mWt.Pause())
        return -EBUSY;

    ALOGI("%s : hat->challenge %lu", __func__, (unsigned long)authToken->challenge);
    ALOGI("%s : hat->user_id %lu", __func__, (unsigned long)authToken->user_id);
    ALOGI("%s : hat->authenticator_id %lu", __func__, (unsigned long)authToken->authenticator_id);
    ALOGI("%s : hat->authenticator_type %d", __func__, authToken->authenticator_type);
    ALOGI("%s : hat->timestamp %lu", __func__, (unsigned long)authToken->timestamp);
    ALOGI("%s : hat size %lu", __func__, (unsigned long)sizeof(hw_auth_token_t));

    int rc = fpc_verify_auth_challenge(fpc, (void *)authToken, sizeof(hw_auth_token_t));
    if (rc)
        return rc;

    bool success = mWt.waitForState(AsyncState::Enroll);
    return success ? 0 : -EAGAIN;
}

int BiometricsFingerprint::postEnroll() {
    ALOGI("%s: Resetting challenge", __func__);
    enroll_challenge = 0;
    return 0;
}

uint64_t BiometricsFingerprint::getAuthenticatorId() {
    uint64_t id = fpc_load_db_id(fpc);
    ALOGI("%s : ID : %ju", __func__, id);
    return id;
}

int BiometricsFingerprint::cancel() {
    ALOGI("%s", __func__);

    if (mWt.Resume()) {
        ALOGI("%s : Successfully moved to pause state", __func__);
        return 0;
    }

    ALOGE("%s : Failed to move to pause state", __func__);
    return -EINVAL;
}

int BiometricsFingerprint::enumerate() {
    // TODO: No lock around notify?
    if (hw.notify == nullptr) {
        ALOGE("Client callback not set");
        return -EFAULT;
    }

    ALOGV(__func__);

    if (!mWt.Pause())
        return -EBUSY;

    fpc_fingerprint_index_t print_indices;
    int rc = fpc_get_print_index(fpc, &print_indices);

    if (!rc) {
        if (!print_indices.print_count) {
            // When there are no fingers, the service still needs to know that (potentially async)
            // enumeration has finished. By convention, send fid=0 and remaining=0 to signal this:
            onEnumerate(0, gid, 0);
        } else
            for (size_t i = 0; i < print_indices.print_count; i++) {
                ALOGD("%s : found print : %lu at index %zu", __func__, (unsigned long)print_indices.prints[i], i);

                uint32_t remaining_templates = (uint32_t)(print_indices.print_count - i - 1);

                onEnumerate(print_indices.prints[i], gid, remaining_templates);
            }
    }

    mWt.Resume();

    return rc;
}

int BiometricsFingerprint::remove(uint32_t gid, uint32_t fid) {
    if (gid != this->gid) {
        ALOGE("gid mismatch; change group and through setActiveGroup first!");
        return -EINVAL;
    }

    // TODO: Locking?
    if (hw.notify == nullptr) {
        ALOGE("Client callback not set");
        return -EINVAL;
    }

    if (!mWt.Pause())
        return -EBUSY;

    int rc = 0;

    fingerprint_msg_t msg;
    msg.type = FINGERPRINT_TEMPLATE_REMOVED;

#if PLATFORM_SDK_VERSION >= 25
    if (fid == 0) {
        // Delete all fingerprints when fid is zero:
        ALOGD("Deleting all fingerprints for gid %d", gid);

        fpc_fingerprint_index_t print_indices;
        rc = fpc_get_print_index(fpc, &print_indices);
        if (!rc)
            for (auto remaining = print_indices.print_count; remaining--;) {
                auto fid = print_indices.prints[remaining];
                ALOGD("Deleting print %d, %d remaining", fid, remaining);
                rc = fpc_del_print_id(fpc, fid);
                if (rc)
                    break;
                msg.data.removed.finger.fid = fid;
                msg.data.removed.finger.gid = gid;
                msg.data.removed.remaining_templates = remaining;
                hw.notify(&msg);
            }
    } else
#else
    LOG_ALWAYS_FATAL_IF(fid == 0, "SDK < 25 does not support removing all fingerprints with fid==0!");
#endif
    {
        ALOGD("Removing finger %u for gid %u", fid, gid);
        rc = fpc_del_print_id(fpc, fid);
        if (!rc) {
            msg.data.removed.finger.fid = fid;
            msg.data.removed.finger.gid = gid;
            hw.notify(&msg);
        }
    }

    if (rc) {
        onError(FINGERPRINT_ERROR_UNABLE_TO_REMOVE);
    } else {
        uint32_t db_length = fpc_get_user_db_length(fpc);
        ALOGD("%s : User Database Length Is : %u", __func__, db_length);
        rc = fpc_store_user_db(fpc, db_length, db_path);
    }

    mWt.Resume();

    return rc;
}

int BiometricsFingerprint::__setActiveGroup(uint32_t gid) {
    int result;
    bool created_empty_db = false;
    struct stat sb;

    if (stat(db_path, &sb) == -1) {
        // No existing database, load an empty one
        if ((result = fpc_load_empty_db(fpc)) != 0) {
            ALOGE("Error creating empty user database: %d\n", result);
            return result;
        }
        created_empty_db = true;
    } else {
        if ((result = fpc_load_user_db(fpc, db_path)) != 0) {
            ALOGE("Error loading existing user database: %d\n", result);
            return result;
        }
    }

    if ((result = fpc_set_gid(fpc, gid)) != 0) {
        ALOGE("Error setting current gid: %d\n", result);
    }

    // if user database was created in this instance, store it directly
    if (created_empty_db) {
        int length = fpc_get_user_db_length(fpc);
        if ((result = fpc_store_user_db(fpc, length, db_path))) {
            ALOGE("Failed to store empty user database: %d\n", result);
            return result;
        }
        if ((result = fpc_load_user_db(fpc, db_path))) {
            ALOGE("Error loading empty user database: %d\n", result);
            return result;
        }
    }
    return result;
}

int BiometricsFingerprint::setActiveGroup(uint32_t gid,
                                          const char *storePath) {
    int result;

    // if (storePath.size() >= PATH_MAX || storePath.size() <= 0) {
    //     ALOGE("Bad path length: %zd", storePath.size());
    //     return -EINVAL;
    // }
    if (access(storePath, W_OK)) {
        return -EINVAL;
    }

    sprintf(db_path, "%s/user.db", storePath);
    this->gid = gid;

    ALOGI("%s : storage path set to : %s", __func__, db_path);

    if (!mWt.Pause())
        return -EBUSY;

    result = __setActiveGroup(gid);

    mWt.Resume();

    return result;
}

int BiometricsFingerprint::authenticate(uint64_t operation_id,
                                        uint32_t gid) {
    if (gid != this->gid) {
        ALOGE("gid mismatch; change group and through setActiveGroup first!");
        return -EINVAL;
    }

    ALOGI("%s: operation_id=%ju", __func__, operation_id);

    if (!mWt.Pause())
        return -EBUSY;

    err_t r = fpc_set_auth_challenge(fpc, operation_id);
    auth_challenge = operation_id;
    if (r < 0) {
        ALOGE("%s: Error setting auth challenge to %ju. r=0x%08X", __func__, operation_id, r);
        return -EAGAIN;
    }

    bool success = mWt.waitForState(AsyncState::Authenticate);
    return success ? 0 : -EAGAIN;
}

void BiometricsFingerprint::IdleAsync() {
    ALOGD(__func__);
    int rc;

    if (!fpc_navi_supported(fpc)) {
        WorkHandler::IdleAsync();
        return;
    }

    // Wait for a new state for at most 500ms before entering navigation mode.
    // This gives the service some time to execute multiple commands on the HAL
    // sequentially before needlessly going into navigation mode and exit it
    // almost immediately after.
    else if (mWt.isEventAvailable(500)) {
        ALOGD("%s: EXIT: Handle event instead of navigation", __func__);
        return;
    }

    ALOGD("%s: Start gesture polling", __func__);

    if (fpc_set_power(&fpc->event, FPC_PWRON) < 0) {
        ALOGE("Error starting device");
        return;
    }

    rc = fpc_navi_enter(fpc);
    ALOGE_IF(rc, "Failed to enter navigation state: rc=%d", rc);

    if (!rc) {
        rc = fpc_navi_poll(fpc);
        ALOGE_IF(rc, "Failed to poll navigation: rc=%d", rc);

        rc = fpc_navi_exit(fpc);
        ALOGE_IF(rc, "Failed to exit navigation: rc=%d", rc);
    }

    if (fpc_set_power(&fpc->event, FPC_PWROFF) < 0)
        ALOGE("Error stopping device");
}

void BiometricsFingerprint::EnrollAsync() {
    // WARNING: Not implemented on any platform
    int32_t print_count = 0;
    // ALOGD("%s : print count is : %u", __func__, print_count);

    std::lock_guard<std::mutex> lock(mClientCallbackMutex);
    if (hw.notify == nullptr) {
        ALOGE("Receiving callbacks before the client callback is registered.");
        return;
    }

    if (fpc_set_power(&fpc->event, FPC_PWRON) < 0) {
        ALOGE("Error starting device");
        onError(FINGERPRINT_ERROR_UNABLE_TO_PROCESS);
        return;
    }

    int ret = fpc_enroll_start(fpc, print_count);
    if (ret < 0) {
        ALOGE("Starting enroll failed: %d\n", ret);
    }

    int status = 1;

    while ((status = fpc_capture_image(fpc)) >= 0) {
        ALOGD("%s : Got Input status=%d", __func__, status);

        if (mWt.isEventAvailable()) {
            onError(FINGERPRINT_ERROR_CANCELED);
            break;
        }

        fingerprint_acquired_info_t hidlStatus = (fingerprint_acquired_info_t)status;

        if (hidlStatus <= FINGERPRINT_ACQUIRED_TOO_FAST)
            onAcquired(hidlStatus);

        //image captured
        if (status == FINGERPRINT_ACQUIRED_GOOD) {
            ALOGI("%s : Enroll Step", __func__);
            uint32_t remaining_touches = 0;
            int ret = fpc_enroll_step(fpc, &remaining_touches);
            ALOGI("%s: step: %d, touches=%d\n", __func__, ret, remaining_touches);
            if (ret > 0) {
                ALOGI("%s : Touches Remaining : %d", __func__, remaining_touches);
                if (remaining_touches > 0) {
                    fingerprint_msg_t msg = {
                        .type = FINGERPRINT_TEMPLATE_ENROLLING,
                        .data.enroll.samples_remaining = remaining_touches,
                    };
                    hw.notify(&msg);
                }
            } else if (ret == 0) {
                uint32_t print_id = 0;
                int print_index = fpc_enroll_end(fpc, &print_id);

                if (print_index < 0) {
                    ALOGE("%s : Error getting new print index : %d", __func__, print_index);
                    onError(FINGERPRINT_ERROR_UNABLE_TO_PROCESS);
                    break;
                }

                uint32_t db_length = fpc_get_user_db_length(fpc);
                ALOGI("%s : User Database Length Is : %lu", __func__, (unsigned long)db_length);
                fpc_store_user_db(fpc, db_length, db_path);
                ALOGI("%s : Got print id : %lu", __func__, (unsigned long)print_id);
                onEnrollResult(print_id, gid, 0);
                break;
            } else {
                ALOGE("Error in enroll step, aborting enroll: %d\n", ret);
                onError(FINGERPRINT_ERROR_UNABLE_TO_PROCESS);
                break;
            }
        }
    }

    if (fpc_set_power(&fpc->event, FPC_PWROFF) < 0)
        ALOGE("Error stopping device");

    if (status < 0)
        onError(FINGERPRINT_ERROR_HW_UNAVAILABLE);
}

void BiometricsFingerprint::AuthenticateAsync() {
    int result;
    int status = 1;

    std::lock_guard<std::mutex> lock(mClientCallbackMutex);
    if (hw.notify == nullptr) {
        ALOGE("Receiving callbacks before the client callback is registered.");
        return;
    }

    if (fpc_set_power(&fpc->event, FPC_PWRON) < 0) {
        ALOGE("Error starting device");
        onError(FINGERPRINT_ERROR_UNABLE_TO_PROCESS);
        return;
    }

    fpc_auth_start(fpc);

    while ((status = fpc_capture_image(fpc)) >= 0) {
        ALOGV("%s : Got Input with status %d", __func__, status);

        if (mWt.isEventAvailable()) {
            onError(FINGERPRINT_ERROR_CANCELED);
            break;
        }

        fingerprint_acquired_info_t hidlStatus = (fingerprint_acquired_info_t)status;

        if (hidlStatus <= FINGERPRINT_ACQUIRED_TOO_FAST) {
            fingerprint_msg_t msg;
            msg.type = FINGERPRINT_ACQUIRED;
            msg.data.acquired.acquired_info = hidlStatus;
        }

        if (status == FINGERPRINT_ACQUIRED_GOOD) {
            uint32_t print_id = 0;
            int verify_state = fpc_auth_step(fpc, &print_id);
            ALOGI("%s : Auth step = %d", __func__, verify_state);

            /* After getting something that ought to have been
             * recognizable: Either send proper notification, or
             * dummy one where fid=zero stands for unrecognized.
             */
            uint32_t fid = 0;

            if (verify_state >= 0) {
                result = fpc_update_template(fpc);
                if (result < 0) {
                    ALOGE("Error updating template: %d", result);
                } else if (result) {
                    ALOGI("Storing db");
                    result = fpc_store_user_db(fpc, 0, db_path);
                    if (result) ALOGE("Error storing database: %d", result);
                }

                if (print_id > 0) {
                    hw_auth_token_t hat;
                    ALOGI("%s : Got print id : %u", __func__, print_id);

                    if (auth_challenge) {
                        fpc_get_hw_auth_obj(fpc, &hat, sizeof(hw_auth_token_t));

                        ALOGW_IF(auth_challenge != hat.challenge,
                                 "Local auth challenge %ju does not match hat challenge %ju",
                                 auth_challenge, hat.challenge);

                        ALOGI("%s : hat->challenge %ju", __func__, hat.challenge);
                        ALOGI("%s : hat->user_id %ju", __func__, hat.user_id);
                        ALOGI("%s : hat->authenticator_id %ju", __func__, hat.authenticator_id);
                        ALOGI("%s : hat->authenticator_type %u", __func__, ntohl(hat.authenticator_type));
                        ALOGI("%s : hat->timestamp " PRIu64, __func__, bswap_64(hat.timestamp));
                        ALOGI("%s : hat size %zu", __func__, sizeof(hw_auth_token_t));
                    } else {
                        // Without challenge, there's no reason to bother the TZ to
                        // provide an "invalid" response token.
                        ALOGD("No authentication challenge set. Reporting empty HAT");
                        memset(&hat, 0, sizeof(hat));
                    }

                    fid = print_id;

                    onAuthenticated(fid, gid, &hat);
                    break;
                } else {
                    ALOGI("%s : Got print id : %u", __func__, print_id);
                    onAuthenticated(fid, gid, nullptr);
                }

            } else if (verify_state == -EAGAIN) {
                ALOGI("%s : retrying due to receiving -EAGAIN", __func__);
                onAuthenticated(fid, gid, nullptr);
            } else {
                /*
                 * Reinitialize the TZ app and parameters
                 * to clear the TZ error generated by flooding it
                 */
                result = fpc_close(&fpc);
                LOG_ALWAYS_FATAL_IF(result < 0, "REINITIALIZE: Failed to close fpc: %d", result);
                sleep(1);
                result = fpc_init(&fpc, mWt.getEventFd());
                LOG_ALWAYS_FATAL_IF(result < 0, "REINITIALIZE: Failed to init fpc: %d", result);
#ifdef USE_FPC_YOSHINO
                int grp_err = __setActiveGroup(gid);
                if (grp_err)
                    ALOGE("%s : Cannot reinitialize database", __func__);
#else
                // Break out of the loop, and make sure ERROR_HW_UNAVAILABLE
                // is raised afterwards, similar to the stock hal:
                status = -1;
                break;
#endif
            }
        }
    }

    if (fpc_set_power(&fpc->event, FPC_PWROFF) < 0)
        ALOGE("Error stopping device");

    if (status < 0)
        onError(FINGERPRINT_ERROR_HW_UNAVAILABLE);
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
    ALOGI("Starting libhardware fingerprint module");

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
