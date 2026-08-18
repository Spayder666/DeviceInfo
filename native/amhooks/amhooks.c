#include <android/log.h>
#include <dlfcn.h>
#include <jni.h>
#include <stdio.h>
#include <string.h>

#define TAG "AccessMonFrida"
#define META "/data/local/tmp/access_monitor/boot.meta"
#define CORE "/data/local/tmp/access_monitor/libamcore.so"

static void emit_boot(const char *nonce, const char *pkg, const char *via) {
    char line[900];
    snprintf(
        line,
        sizeof(line),
        "{\"identifierId\":\"frida.boot\",\"action\":\"Frida: скрипт загружен\","
        "\"request\":\"%s\",\"response\":\"%s\",\"package\":\"%s\","
        "\"timestamp\":0,\"source\":\"frida\",\"nonce\":\"%s\"}",
        pkg,
        via,
        pkg,
        nonce
    );
    __android_log_print(ANDROID_LOG_WARN, TAG, "%s", line);
}

static jint on_attach(void) {
    char nonce[80] = {0};
    char pkg[160] = {0};
    FILE *f = fopen(META, "r");
    if (f) {
        if (fscanf(f, "%79s %159s", nonce, pkg) < 1) {
            nonce[0] = 0;
        }
        fclose(f);
    }
    emit_boot(nonce, pkg, "jvmti");
    dlerror();
    void *h = dlopen(CORE, RTLD_NOW);
    if (!h) {
        const char *err = dlerror();
        __android_log_print(ANDROID_LOG_WARN, TAG, "dlopen amcore: %s", err ? err : "?");
    }
    return JNI_OK;
}

JNIEXPORT jint JNICALL Agent_OnAttach(JavaVM *vm, char *options, void *reserved) {
    (void)vm;
    (void)options;
    (void)reserved;
    return on_attach();
}

JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM *vm, char *options, void *reserved) {
    (void)vm;
    (void)options;
    (void)reserved;
    return on_attach();
}
