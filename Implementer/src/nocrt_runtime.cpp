// Minimal freestanding memory primitives used only by the CrtMode=None build.

namespace {
using Size = decltype(sizeof(0));
}

extern "C" int _fltused = 0;

extern "C" void* __cdecl memcpy(void* destination, const void* source, Size count);
extern "C" void* __cdecl memmove(void* destination, const void* source, Size count);
extern "C" void* __cdecl memset(void* destination, int value, Size count);
extern "C" int __cdecl memcmp(const void* left, const void* right, Size count);

#pragma function(memcpy, memmove, memset, memcmp)

extern "C" void* __cdecl memcpy(void* destination, const void* source, Size count) {
    auto* out = static_cast<unsigned char*>(destination);
    const auto* in = static_cast<const unsigned char*>(source);
    for (Size index = 0; index < count; ++index) {
        out[index] = in[index];
    }
    return destination;
}

extern "C" void* __cdecl memmove(void* destination, const void* source, Size count) {
    auto* out = static_cast<unsigned char*>(destination);
    const auto* in = static_cast<const unsigned char*>(source);
    if (out < in) {
        for (Size index = 0; index < count; ++index) {
            out[index] = in[index];
        }
    } else if (out > in) {
        for (Size index = count; index > 0; --index) {
            out[index - 1] = in[index - 1];
        }
    }
    return destination;
}

extern "C" void* __cdecl memset(void* destination, int value, Size count) {
    auto* out = static_cast<unsigned char*>(destination);
    for (Size index = 0; index < count; ++index) {
        out[index] = static_cast<unsigned char>(value);
    }
    return destination;
}

extern "C" int __cdecl memcmp(const void* left, const void* right, Size count) {
    const auto* a = static_cast<const unsigned char*>(left);
    const auto* b = static_cast<const unsigned char*>(right);
    for (Size index = 0; index < count; ++index) {
        if (a[index] != b[index]) {
            return a[index] < b[index] ? -1 : 1;
        }
    }
    return 0;
}
