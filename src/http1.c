#include "http1.h"
#include <string.h>
#include <strings.h>
#include <limits.h>

static size_t line_length(const uint8_t *data, size_t length) {
    for (size_t i=1;i<length;i++) if (data[i-1] == '\r' && data[i] == '\n') return i+1;
    return 0;
}

static int number(const uint8_t *data, size_t length, unsigned base, uint64_t *value) {
    if (!length) return -1;
    *value=0;
    for (size_t i=0;i<length;i++) {
        unsigned digit=data[i] >= '0' && data[i] <= '9' ? data[i]-'0' : data[i] >= 'a' && data[i] <= 'f' ? data[i]-'a'+10 : data[i] >= 'A' && data[i] <= 'F' ? data[i]-'A'+10 : 255;
        if (digit >= base || *value > (UINT64_MAX-digit)/base) return -1;
        *value=*value*base+digit;
    }
    return 0;
}

static int token(const uint8_t *data, size_t length) {
    if (!length) return 0;
    for (size_t i=0;i<length;i++) {
        unsigned ch=data[i];
        if (!ch || !((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || strchr("!#$%&'*+-.^_`|~",(int)ch))) return 0;
    }
    return 1;
}

static int chunk_extensions(const uint8_t *data, size_t length) {
    size_t offset=0;
    while (offset < length) {
        while (offset < length && (data[offset] == ' ' || data[offset] == '\t')) offset++;
        if (offset == length || data[offset++] != ';') return -1;
        while (offset < length && (data[offset] == ' ' || data[offset] == '\t')) offset++;
        size_t start=offset;
        while (offset < length && token(data+offset,1)) offset++;
        if (start == offset) return -1;
        size_t next=offset;
        while (next < length && (data[next] == ' ' || data[next] == '\t')) next++;
        if (next == length || data[next] != '=') continue;
        offset=next+1;
        while (offset < length && (data[offset] == ' ' || data[offset] == '\t')) offset++;
        if (offset < length && data[offset] == '"') {
            offset++; int closed=0;
            while (offset < length) {
                unsigned byte=data[offset++];
                if (byte == '"') { closed=1; break; }
                if (byte == '\\') { if (offset == length) return -1; byte=data[offset++]; }
                if ((byte < 0x20 && byte != '\t') || byte == 0x7f) return -1;
            }
            if (!closed) return -1;
        } else {
            start=offset;
            while (offset < length && token(data+offset,1)) offset++;
            if (start == offset) return -1;
        }
    }
    return 0;
}

static int contains_token(const uint8_t *data, size_t length, const char *word) {
    while (length) {
        while (length && (*data == ' ' || *data == '\t' || *data == ',')) { data++; length--; }
        size_t take=0; while (take < length && data[take] != ',') take++;
        size_t end=take; while (end && (data[end-1] == ' ' || data[end-1] == '\t')) end--;
        if (end == strlen(word) && !strncasecmp((const char *)data,word,end)) return 1;
        data+=take; length-=take;
    }
    return 0;
}

static int headers(core_http1_response_t *parser, const uint8_t *data, size_t length, core_http1_event_t *event) {
    size_t end=0;
    for (size_t i=3;i<length;i++) if (!memcmp(data+i-3,"\r\n\r\n",4)) { end=i+1; break; }
    if (!end) return length > 65536 ? -1 : 1;
    if (end > 65536) return -1;
    size_t line=line_length(data,end);
    if (line < 14 || (memcmp(data,"HTTP/1.1 ",9) && memcmp(data,"HTTP/1.0 ",9)) || data[9] < '1' || data[9] > '5' || data[10] < '0' || data[10] > '9' || data[11] < '0' || data[11] > '9' || data[12] != ' ') return -1;
    for (size_t i=13;i+2<line;i++) if ((data[i] < 0x20 && data[i] != '\t') || data[i] == 0x7f) return -1;
    int status=(data[9]-'0')*100+(data[10]-'0')*10+data[11]-'0';
    if (status == 101) return -1;
    int seen_length=0,seen_encoding=0,close_connection=data[7] == '0';
    uint64_t content_length=0;
    for (size_t offset=line;offset+2<end;) {
        size_t take=line_length(data+offset,end-offset);
        if (!take || take == 2) break;
        const uint8_t *field=data+offset,*colon=memchr(field,':',take-2);
        if (!colon || !token(field,(size_t)(colon-field))) return -1;
        size_t name=(size_t)(colon-field),value_length=take-2-name-1;
        const uint8_t *value=colon+1;
        while (value_length && (*value == ' ' || *value == '\t')) { value++; value_length--; }
        while (value_length && (value[value_length-1] == ' ' || value[value_length-1] == '\t')) value_length--;
        for (size_t i=0;i<value_length;i++) if ((value[i] < 0x20 && value[i] != '\t') || value[i] == 0x7f) return -1;
        if (name == 14 && !strncasecmp((const char *)field,"Content-Length",name)) {
            uint64_t parsed;
            if (number(value,value_length,10,&parsed) != 0 || (seen_length && parsed != content_length)) return -1;
            content_length=parsed; seen_length=1;
        } else if (name == 17 && !strncasecmp((const char *)field,"Transfer-Encoding",name)) {
            if (seen_encoding || value_length != 7 || strncasecmp((const char *)value,"chunked",7)) return -1;
            seen_encoding=1;
        } else if (name == 10 && !strncasecmp((const char *)field,"Connection",name)) {
            if (contains_token(value,value_length,"close")) close_connection=1;
            else if (data[7] == '0' && contains_token(value,value_length,"keep-alive")) close_connection=0;
        }
        offset+=take;
    }
    if (seen_encoding && seen_length) return -1;
    event->kind=1; event->status=status; event->consumed=end;
    if (status < 200) return 0;
    parser->chunked=seen_encoding; parser->close_connection=close_connection;
    parser->close_delimited=!seen_length && !seen_encoding;
    parser->remaining=seen_length ? content_length : UINT64_MAX;
    parser->state=seen_encoding ? 2 : 1;
    if (!seen_encoding && !seen_length) parser->close_connection=1;
    if (status == 204 || status == 304) { parser->remaining=0; parser->state=1; }
    event->close_connection=parser->close_connection; return 0;
}

int core_http1_next(core_http1_response_t *parser, const uint8_t *data, size_t length, int eof, size_t capacity, core_http1_event_t *event) {
    memset(event,0,sizeof(*event));
    if (!parser->state) { int result=headers(parser,data,length,event); return result == 1 && eof ? -1 : result; }
    if (parser->state == 7) return length ? -1 : 1;
    for (;;) {
        if (parser->state == 1 || parser->state == 3) {
            if (!parser->remaining) {
                if (parser->state == 3) { parser->state=4; continue; }
                parser->state=7; event->kind=3; event->close_connection=parser->close_connection; return 0;
            }
            if (!length) {
                if (eof && parser->state == 1 && parser->close_delimited) { parser->remaining=0; continue; }
                return eof ? -1 : 1;
            }
            if (!capacity) return 1;
            size_t take=length < capacity ? length : capacity;
            if ((uint64_t)take > parser->remaining) take=(size_t)parser->remaining;
            event->kind=2; event->offset=event->consumed; event->length=take; event->consumed+=take;
            if (!parser->close_delimited) parser->remaining-=take;
            return 0;
        }
        if (parser->state == 4) {
            if (length < 2) return eof ? -1 : 1;
            if (memcmp(data,"\r\n",2)) return -1;
            data+=2; length-=2; event->consumed+=2; parser->state=2;
        }
        if (parser->state == 2) {
            size_t line=line_length(data,length);
            if (!line) return eof || length > 1024 ? -1 : 1;
            size_t digits=0;
            while (digits+2 < line && ((data[digits] >= '0' && data[digits] <= '9') || (data[digits] >= 'a' && data[digits] <= 'f') || (data[digits] >= 'A' && data[digits] <= 'F'))) digits++;
            if (number(data,digits,16,&parser->remaining) || chunk_extensions(data+digits,line-2-digits)) return -1;
            data+=line; length-=line; event->consumed+=line;
            parser->state=parser->remaining ? 3 : 5;
        }
        if (parser->state == 5) {
            size_t line=line_length(data,length);
            if (!line) return eof || parser->header_bytes+length > 65536 ? -1 : 1;
            parser->header_bytes+=line;
            if (parser->header_bytes > 65536) return -1;
            if (line > 2) {
                const uint8_t *colon=memchr(data,':',line-2);
                if (!colon || !token(data,(size_t)(colon-data))) return -1;
                size_t name=(size_t)(colon-data);
                if ((name == 14 && !strncasecmp((const char *)data,"Content-Length",name)) || (name == 17 && !strncasecmp((const char *)data,"Transfer-Encoding",name)) ||
                    (name == 7 && !strncasecmp((const char *)data,"Trailer",name))) return -1;
                for (size_t i=(size_t)(colon-data)+1;i+2<line;i++) if ((data[i] < 0x20 && data[i] != '\t') || data[i] == 0x7f) return -1;
            }
            data+=line; length-=line; event->consumed+=line;
            if (line == 2) { parser->state=7; event->kind=3; event->close_connection=parser->close_connection; return 0; }
        }
    }
}
