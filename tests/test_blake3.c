#include "check.h"
#include "blake3.h"
int main(void) {
    puts("VECTORS https://raw.githubusercontent.com/BLAKE3-team/BLAKE3/1.8.2/test_vectors/test_vectors.json");
    const struct { size_t length; const char *hash, *derive; } vectors[] = {
        {0,"af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262","2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d"},
        {1,"2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213","b3e2e340a117a499c6cf2398a19ee0d29cca2bb7404c73063382693bf66cb06c"},
        {63,"e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b","b6451e30b953c206e34644c6803724e9d2725e0893039cfc49584f991f451af3"},
        {64,"4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98","a5c4a7053fa86b64746d4bb688d06ad1f02a18fce9afd3e818fefaa7126bf73e"},
        {65,"de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee","51fd05c3c1cfbc8ed67d139ad76f5cf8236cd2acd26627a30c104dfd9d3ff8a8"},
        {1023,"10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11","74a16c1c3d44368a86e1ca6df64be6a2f64cce8f09220787450722d85725dea5"},
        {1024,"42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7","7356cd7720d5b66b6d0697eb3177d9f8d73a4a5c5e968896eb6a689684302706"},
        {1025,"d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444","effaa245f065fbf82ac186839a249707c3bddf6d3fdda22d1b95a3c970379bcb"},
        {2048,"e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a","7b2945cb4fef70885cc5d78a87bf6f6207dd901ff239201351ffac04e1088a23"},
        {4096,"015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e969","1e0d7f3db8c414c97c6307cbda6cd27ac3b030949da8e23be1a1a924ad2f25b9"}
    };
    const char *context = "BLAKE3 2019-12-27 16:29:52 test vectors context";
    uint8_t data[4096], out[32]; char hex[65], name[80];
    for (size_t i = 0; i < sizeof(data); i++) data[i] = i % 251;
    for (size_t v = 0; v < sizeof(vectors)/sizeof(*vectors); v++) {
        blake3_hash(data, vectors[v].length, out);
        for (int i = 0; i < 32; i++) snprintf(hex + i*2, 3, "%02x", out[i]);
        snprintf(name, sizeof(name), "blake3/hash/%zu", vectors[v].length); CHECK(name, strcmp(hex, vectors[v].hash) == 0);
        blake3_derive_key((const uint8_t *)context, strlen(context), data, vectors[v].length, out);
        for (int i = 0; i < 32; i++) snprintf(hex + i*2, 3, "%02x", out[i]);
        snprintf(name, sizeof(name), "blake3/derive/%zu", vectors[v].length); CHECK(name, strcmp(hex, vectors[v].derive) == 0);
    }
    return test_result();
}
