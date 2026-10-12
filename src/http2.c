#include "http2.h"
#include <limits.h>

static uint32_t value32(const uint8_t *data) {
    return ((uint32_t)data[0]<<24)|((uint32_t)data[1]<<16)|((uint32_t)data[2]<<8)|data[3];
}

int core_http2_validate_frame(core_http2_validation_t *state, uint8_t type, uint8_t flags, uint32_t stream, const uint8_t *data, size_t length) {
    if (!state || (!data && length) || length > 16384 || stream > 0x7fffffffU) return -1;
    if (!state->settings_received && (type != 4 || (flags&1) || stream)) return -1;
    if (state->continuation && (type != 9 || stream != state->continuation)) return -1;
    int error=0;
    switch (type) {
    case 0:
        if (!stream || ((flags&8) && (!length || data[0] >= length))) return -1;
        break;
    case 1: {
        if (!stream) return -1;
        size_t start=0,end=length;
        if (flags&8) { if (!length || data[0] >= length) return -1; start=1; end-=data[0]; }
        if (flags&32) {
            if (end-start < 5) return -1;
            if ((value32(data+start)&0x7fffffffU) == stream) error=-2;
        }
        if (!(flags&4)) state->continuation=stream;
        break;
    }
    case 2:
        if (!stream) return -1;
        if (length != 5 || (value32(data)&0x7fffffffU) == stream) return -2;
        break;
    case 3:
        if (!stream || length != 4) return -1;
        break;
    case 4:
        if (stream || (flags&1 ? length != 0 : length%6 != 0)) return -1;
        if (flags&1) {
            if (!state->settings_pending) return -1;
            state->settings_pending--; break;
        }
        for (size_t i=0;i<length;i+=6) {
            unsigned id=((unsigned)data[i]<<8)|data[i+1]; uint32_t value=value32(data+i+2);
            if ((id == 2 && value != 0) || (id == 4 && value > INT_MAX) || (id == 5 && (value < 16384 || value > 16777215))) return -1;
        }
        if (!state->settings_received) state->settings_pending=1;
        state->settings_received=1;
        break;
    case 5:
        return -1;
    case 6:
        if (stream || length != 8) return -1;
        break;
    case 7:
        if (stream || length < 8) return -1;
        break;
    case 8:
        if (length != 4) return -1;
        if (!(value32(data)&0x7fffffffU)) return stream ? -2 : -1;
        break;
    case 9:
        if (!state->continuation || stream != state->continuation) return -1;
        if (flags&4) state->continuation=0;
        break;
    default:
        break;
    }
    return error;
}

static int finish_response(core_http2_response_t *state, int end) {
    if (!end) return 0;
    if (state->has_content_length && !state->no_body && state->received != state->content_length) return -1;
    state->ended=1; return 0;
}

int core_http2_response_headers(core_http2_response_t *state, const core_hpack_headers_t *headers, int end) {
    if (!state || !headers || state->ended || headers->other_pseudo || headers->has_te || headers->status == 101) return -1;
    if (headers->status >= 100 && headers->status < 200) return state->headers || end || headers->has_content_length ? -1 : 0;
    if (!state->headers) {
        if (!headers->status_seen || headers->status < 200 || headers->status > 599) return -1;
        state->headers=1; state->has_content_length=headers->has_content_length; state->content_length=headers->content_length;
        state->no_body=headers->status == 204 || headers->status == 304;
        if (headers->status == 204 && headers->has_content_length) return -1;
    } else if (headers->status_seen || !end || headers->has_content_length) return -1;
    return finish_response(state,end);
}

int core_http2_response_data(core_http2_response_t *state, size_t length, int end) {
    if (!state || !state->headers || state->ended || (state->no_body && length) || (uint64_t)length > UINT64_MAX-state->received) return -1;
    state->received+=(uint64_t)length;
    if (state->has_content_length && state->received > state->content_length) return -1;
    return finish_response(state,end);
}
