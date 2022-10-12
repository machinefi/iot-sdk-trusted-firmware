/*
 * Copyright (c) 2017-2019, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include <stdint.h>
#include <stdbool.h>

#ifdef IOTEXTF_USE_MUTEX
#include "os_wrapper/mutex.h"
#endif

#include "tfm_api.h"
#include "tfm_ns_interface.h"

/**
 * \brief the ns_lock ID
 */
static void *ns_lock_handle = NULL;

//__attribute__((weak))
int32_t tfm_ns_interface_dispatch(veneer_fn fn,
                                  void * arg0, uint32_t arg1,
                                  void * arg2, uint32_t arg3)
{
    int32_t result;

    /* TFM request protected by NS lock */
#ifdef IOTEXTF_USE_MUTEX
    if (os_wrapper_mutex_acquire(ns_lock_handle, OS_WRAPPER_WAIT_FOREVER)
            != OS_WRAPPER_SUCCESS) {
        return (int32_t)TFM_ERROR_GENERIC;
    }
#endif

    result = fn(arg0, arg1, arg2, arg3);

#ifdef IOTEXTF_USE_MUTEX
    if (os_wrapper_mutex_release(ns_lock_handle) != OS_WRAPPER_SUCCESS) {
        return (int32_t)TFM_ERROR_GENERIC;
    }
#endif

    return result;
}

//__attribute__((weak))
enum tfm_status_e tfm_ns_interface_init(void)
{
    void *handle;

#ifdef IOTEXTF_USE_MUTEX
    handle = os_wrapper_mutex_create();
    if (!handle) {
        return TFM_ERROR_GENERIC;
    }

    ns_lock_handle = handle;
#endif

    return TFM_SUCCESS;
}
