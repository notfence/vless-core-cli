#ifndef VLESS_CORE_LOG_H
#define VLESS_CORE_LOG_H

#if defined(__GNUC__) || defined(__clang__)
#define VC_LOG_PRINTF(format_index, arguments_index) \
    __attribute__((format(printf, format_index, arguments_index)))
#else
#define VC_LOG_PRINTF(format_index, arguments_index)
#endif

void vc_log_debug(const char *component, const char *format, ...)
    VC_LOG_PRINTF(2, 3);
void vc_log_info(const char *component, const char *format, ...)
    VC_LOG_PRINTF(2, 3);
void vc_log_warning(const char *component, const char *format, ...)
    VC_LOG_PRINTF(2, 3);
void vc_log_error(const char *component, const char *format, ...)
    VC_LOG_PRINTF(2, 3);
void vc_log_probe(int success,const char *text);
int vc_log_flush(void);

#undef VC_LOG_PRINTF

#endif
