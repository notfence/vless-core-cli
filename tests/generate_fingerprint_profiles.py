import json
from pathlib import Path


MODES = {
    "hellochrome_120": "FP_CHROME_120", "hellochrome_131": "FP_CHROME_131", "hellochrome_133": "FP_CHROME",
    "hellofirefox_120": "FP_FIREFOX_120", "hellofirefox_148": "FP_FIREFOX", "helloios_13": "FP_IOS_13",
    "helloios_14": "FP_IOS_14", "helloedge_85": "FP_EDGE", "helloedge_106": "FP_EDGE_106",
    "hellosafari_26_3": "FP_SAFARI_26_3", "hello360_7_5": "FP_360_7_5", "hello360_11_0": "FP_360_11_0",
    "helloqq_11_1": "FP_QQ",
}


def render(vectors):
    output = ["#ifndef CORE_TLS_FINGERPRINT_PROFILES_H", "#define CORE_TLS_FINGERPRINT_PROFILES_H", ""]
    output.extend([
        "typedef struct { uint16_t type; const uint8_t *data; size_t length; } tls_profile_extension_t;",
        "typedef struct { fingerprint_mode_t mode; const uint16_t *ciphers; size_t cipher_count;",
        "    const tls_profile_extension_t *extensions; size_t extension_count; int shuffle; } tls_profile_t;", "",
    ])
    payloads = {}
    cipher_lists = {}
    entries = []
    for index, profile in enumerate(vectors["profiles"]):
        ciphers = tuple(profile["ciphers"])
        if ciphers not in cipher_lists:
            name = f"tls_profile_ciphers_{len(cipher_lists)}"
            cipher_lists[ciphers] = name
            output.append(f"static const uint16_t {name}[] = {{" + ",".join(f"0x{n:04x}" for n in ciphers) + "};")
        extensions = []
        for extension in profile["extensions"]:
            payload = bytes.fromhex(extension["data"])
            if extension["type"] == 51:
                payload = b"".join(group.to_bytes(2, "big") for group in extension["groups"])
            if payload and payload not in payloads:
                name = f"tls_profile_data_{len(payloads)}"
                payloads[payload] = name
                output.append(f"static const uint8_t {name}[] = {{" + ",".join(f"0x{n:02x}" for n in payload) + "};")
            data = payloads[payload] if payload else "NULL"
            extensions.append(f"    {{0x{extension['type']:04x},{data},{len(payload)}}},")
        output.append(f"static const tls_profile_extension_t tls_profile_extensions_{index}[] = {{")
        output.extend(extensions)
        output.append("};")
        entries.append(f"    {{{MODES[profile['name']]},{cipher_lists[ciphers]},{len(ciphers)},"
                       f"tls_profile_extensions_{index},{len(extensions)},{int(profile['shuffle'])}}},")
    output.extend(["", "static const tls_profile_t tls_profiles[] = {", *entries, "};", "", "#endif", ""])
    return "\n".join(output)


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1]
    print(render(json.loads((root / "tests/fingerprint_vectors.json").read_text())), end="")
