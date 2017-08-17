// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>
#ifdef _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif
#include "azure_c_shared_utility/platform.h"
#include "azure_c_shared_utility/xio.h"
#include "azure_c_shared_utility/tlsio_mbed_socket_async_remoto.h"
#include "azure_c_shared_utility/xlogging.h"
#include "lwip/apps/sntp.h"
//#include "lwip/apps/sntp_time.h"

#include "FreeRTOS.h"

int platform_init(void)
{
    sntp_init();
    u32_t ts = 0;
    vTaskDelay(5000 / portTICK_RATE_MS);
    /*while(ts == 0){
        vTaskDelay(5000 / portTICK_RATE_MS);
        ts = sntp_get_current_timestamp();
        LogInfo("%s", sntp_get_real_time(ts));
    }*/
    return 0;
}

const IO_INTERFACE_DESCRIPTION* platform_get_default_tlsio(void)
{
    return tlsio_mbedtls_get_interface_description();
}

STRING_HANDLE platform_get_platform_info(void)
{
    return STRING_construct("(freertos)");
}

void platform_deinit(void)
{
     sntp_stop();
}
