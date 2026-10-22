#ifndef CORE_CONFIG_INTERNAL_H
#define CORE_CONFIG_INTERNAL_H
#include "uri.h"
int core_config_endpoint(const char *,char *,size_t,uint16_t *);
int core_config_parameter(vless_config_t *,const char *,const char *,char *,size_t);
int core_config_query(vless_config_t *,char *,char *,size_t);
int core_config_finalize(vless_config_t *,char *,size_t);
int core_vmess_parse_uri(const char *,vless_config_t *,char *,size_t);
int core_vmess_parameter(vless_config_t *,const char *,const char *,char *,size_t);
int core_ss_parse_uri(const char *,vless_config_t *,char *,size_t);
int core_ss_parameter(vless_config_t *,const char *,const char *,char *,size_t);
#endif
