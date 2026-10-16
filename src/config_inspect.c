#include "config_inspect.h"
#include "xhttp_download.h"
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int endpoint(char *output, size_t capacity, size_t *used, const char *kind, const vless_config_t *config) {
    for (const unsigned char *p=(const unsigned char *)config->server_host;*p;p++)
        if (*p <= 0x20 || *p == 0x7f) return -1;
    int length=snprintf(output+*used,capacity-*used,"%s\t%s\t%u\n",kind,config->server_host,(unsigned)config->server_port);
    if (length < 0 || (size_t)length >= capacity-*used) return -1;
    *used+=(size_t)length;
    return 0;
}

int core_config_inspect(const vless_config_t *config, char *output, size_t capacity, char *error, size_t error_capacity) {
    if (!config || !output || capacity < 10) return -1;
    output[0]=0;
    memcpy(output,"CONFIG\t1\n",10);
    size_t used=9;
    int result=endpoint(output,capacity,&used,"PRIMARY",config);
    if (!result && config->xhttp_download_settings[0]) {
        vless_config_t *download=calloc(1,sizeof(*download));
        if (!download) result=-1;
        else {
            result=core_xhttp_download_config(config,download,error,error_capacity);
            if (!result) result=endpoint(output,capacity,&used,"DOWNLOAD",download);
            OPENSSL_cleanse(download,sizeof(*download)); free(download);
        }
    }
    if (!result && capacity-used > 4) memcpy(output+used,"END\n",5);
    else result=-1;
    if (result) { output[0]=0; if (error && error_capacity && !*error) snprintf(error,error_capacity,"invalid configuration inspection output"); }
    return result;
}
