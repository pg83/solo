namespace {
    static int destructions;

    struct GlibcDlFindObject {
        unsigned long long flags;
        void* mapStart;
        void* mapEnd;
        void* linkMap;
        void* ehFrame;
        void* sframe;
        unsigned long long reserved[6];
    };

    static_assert(sizeof(GlibcDlFindObject) == 96);

    struct Guard {
        Guard(int* value);
        ~Guard();

        int* value;
    };

    static void throwValue();
}

extern "C" void* dlsym(void* handle, const char* name);

Guard::Guard(int* value)
    : value(value)
{
}

Guard::~Guard() {
    ++*value;
}

namespace {
    static void throwValue() {
        throw 41;
    }
}

extern "C" int glibc_test_exception() {
    int destroyed = 0;

    try {
        Guard guard(&destroyed);
        throwValue();
    } catch (int value) {
        return value + destroyed;
    }

    return -1;
}

extern "C" void glibc_test_throw() {
    Guard guard(&destructions);
    throwValue();
}

extern "C" void glibc_test_call(void (*callback)()) {
    Guard guard(&destructions);
    callback();
}

extern "C" int glibc_test_catch(void (*callback)()) {
    try {
        Guard guard(&destructions);
        callback();
    } catch (...) {
        return 44;
    }

    return -1;
}

extern "C" int glibc_test_destructions() {
    return destructions;
}

extern "C" int glibc_test_find_object() {
    using FindObject = int (*)(void* address, GlibcDlFindObject* result);

    auto findObject = reinterpret_cast<FindObject>(dlsym(nullptr, "_dl_find_object"));
    GlibcDlFindObject result{};
    auto address = reinterpret_cast<unsigned long long>(glibc_test_find_object);

    if (!findObject || findObject(reinterpret_cast<void*>(address), &result) != 0) {
        return 1;
    }

    return address < reinterpret_cast<unsigned long long>(result.mapStart) || address >= reinterpret_cast<unsigned long long>(result.mapEnd) || !result.ehFrame;
}
