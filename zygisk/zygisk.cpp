#include "zygisk.hpp"

#include <android/log.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "AccessMonZygisk", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "AccessMonZygisk", __VA_ARGS__)

static constexpr const char *kModuleDir = "/data/adb/modules/access_monitor";

static char g_pkg[160];

static std::string jstringToStd(JNIEnv *env, jstring value) {
    if (!env || !value) return {};
    const char *raw = env->GetStringUTFChars(value, nullptr);
    std::string out = raw ? raw : "";
    env->ReleaseStringUTFChars(value, raw);
    return out;
}

static std::string readFdAll(int fd, size_t maxLen = 256) {
    if (fd < 0) return {};
    std::string out;
    out.resize(maxLen);
    ssize_t n = read(fd, out.data(), maxLen);
    if (n <= 0) return {};
    out.resize(static_cast<size_t>(n));
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r' || out.back() == ' ')) {
        out.pop_back();
    }
    return out;
}

static bool sendFd(int sock, int fd) {
    struct msghdr msg{};
    char cmsgbuf[CMSG_SPACE(sizeof(int))];
    memset(cmsgbuf, 0, sizeof(cmsgbuf));
    char dummy = 'F';
    struct iovec iov{&dummy, 1};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg) return false;
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));
    return sendmsg(sock, &msg, 0) >= 0;
}

static int recvFd(int sock) {
    struct msghdr msg{};
    char cmsgbuf[CMSG_SPACE(sizeof(int))];
    memset(cmsgbuf, 0, sizeof(cmsgbuf));
    char dummy = 0;
    struct iovec iov{&dummy, 1};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);
    if (recvmsg(sock, &msg, 0) < 0) return -1;
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg || cmsg->cmsg_type != SCM_RIGHTS) return -1;
    int fd = -1;
    memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
    return fd;
}

static bool copyFdToPath(int fd, const char *path, mode_t mode) {
    if (fd < 0 || !path) return false;
    if (lseek(fd, 0, SEEK_SET) < 0 && errno != ESPIPE) {
        // memfd / pipe: ignore
    }
    int out = open(path, O_CREAT | O_WRONLY | O_TRUNC, mode);
    if (out < 0) return false;
    char buf[8192];
    ssize_t n;
    bool ok = true;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        ssize_t off = 0;
        while (off < n) {
            ssize_t w = write(out, buf + off, static_cast<size_t>(n - off));
            if (w <= 0) {
                ok = false;
                break;
            }
            off += w;
        }
        if (!ok) break;
    }
    close(out);
    chmod(path, mode);
    return ok && n >= 0;
}

static void writeText(const char *path, const std::string &text, mode_t mode) {
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, mode);
    if (fd < 0) return;
    auto *p = text.data();
    size_t left = text.size();
    while (left > 0) {
        ssize_t w = write(fd, p, left);
        if (w <= 0) break;
        p += w;
        left -= static_cast<size_t>(w);
    }
    close(fd);
    chmod(path, mode);
}

static bool isTargetProcess(const std::string &nice, const std::string &target) {
    if (target.empty() || nice.empty()) return false;
    if (nice == target) return true;
    // Main process is usually the package name. Isolated/UI helpers are pkg:name —
    // still the monitored app, but do not inject gadget into them (they crash).
    return false;
}

static int starts_with(const char *p, const char *pre) {
    if (!p || !pre) return 0;
    while (*pre) {
        if (*p++ != *pre++) return 0;
    }
    return 1;
}

static int contains(const char *p, const char *needle) {
    if (!p || !needle || !needle[0]) return 0;
    for (; *p; p++) {
        const char *a = p;
        const char *b = needle;
        while (*a && *b && *a == *b) {
            a++;
            b++;
        }
        if (!*b) return 1;
    }
    return 0;
}

static const char *classify_fs_path(const char *p) {
    if (!p || !p[0]) return nullptr;
    if (contains(p, "/sys/class/net/") && contains(p, "/address")) return "wifi.sysfs_mac";
    if (contains(p, "/proc/cpuinfo")) return "proc.cpuinfo";
    if (contains(p, "/proc/meminfo")) return "proc.meminfo";
    if (contains(p, "/proc/version")) return "proc.version";
    if (starts_with(p, "/system/bin/su") || starts_with(p, "/system/xbin/su") ||
        starts_with(p, "/sbin/su") || starts_with(p, "/su/bin/su") ||
        starts_with(p, "/data/adb") || starts_with(p, "/sbin/.magisk") ||
        (p[0] == 's' && p[1] == 'u' && p[2] == 0)) {
        return "root.su";
    }
    size_t n = 0;
    for (const char *s = p; *s; s++) n++;
    if (n >= 3 && p[n - 3] == '/' && p[n - 2] == 's' && p[n - 1] == 'u') return "root.su";
    if (starts_with(p, "/proc/") || starts_with(p, "/sys/")) return "proc.properties";
    return nullptr;
}

static long long now_ms() {
    struct timeval tv{};
    gettimeofday(&tv, nullptr);
    return (long long) tv.tv_sec * 1000LL + tv.tv_usec / 1000LL;
}

static void emit_fs(const char *id, const char *kind, const char *path) {
    static __thread int reenter = 0;
    if (reenter || !id || !kind || !path || !g_pkg[0]) return;
    char safe[280];
    size_t n = 0;
    for (; *path && n + 1 < sizeof(safe); path++) {
        unsigned char c = (unsigned char) *path;
        safe[n++] = (c < 32 || c == '"' || c == '\\') ? '_' : (char) c;
    }
    safe[n] = 0;
    char line[640];
    snprintf(
        line,
        sizeof(line),
        "{\"identifierId\":\"%s\",\"action\":\"native.%s\",\"request\":\"%s\","
        "\"response\":\"\",\"permission\":\"\",\"package\":\"%s\","
        "\"timestamp\":%lld,\"source\":\"frida\",\"nonce\":\"zygisk-fs\"}",
        id,
        kind,
        safe,
        g_pkg,
        now_ms()
    );
    reenter = 1;
    __android_log_print(ANDROID_LOG_INFO, "AccessMonFrida", "%s", line);
    reenter = 0;
}

static void on_path(const char *path, const char *kind) {
    const char *id = classify_fs_path(path);
    if (id) emit_fs(id, kind, path);
}

static int hook_access(const char *path, int mode) {
    on_path(path, "access");
    return (int) syscall(__NR_faccessat, AT_FDCWD, path, mode, 0);
}

static int hook_faccessat(int dirfd, const char *path, int mode, int flags) {
    on_path(path, "faccessat");
#ifdef __NR_faccessat2
    if (flags != 0) {
        return (int) syscall(__NR_faccessat2, dirfd, path, mode, flags);
    }
#endif
    return (int) syscall(__NR_faccessat, dirfd, path, mode, flags);
}

static bool protect_range(void *addr, size_t len, int prot) {
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) page = 4096;
    uintptr_t start = (uintptr_t) addr & ~((uintptr_t) page - 1);
    uintptr_t end = ((uintptr_t) addr + len + (uintptr_t) page - 1) & ~((uintptr_t) page - 1);
    return mprotect((void *) start, end - start, prot) == 0;
}

static bool within_branch(void *from, void *to, int bits) {
    intptr_t delta = reinterpret_cast<uint8_t *>(to) - reinterpret_cast<uint8_t *>(from);
    intptr_t limit = (intptr_t) 1 << (bits - 1);
    return (delta % 4) == 0 && delta >= -limit && delta < limit;
}

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

static void *alloc_near(void *target) {
    uintptr_t base = reinterpret_cast<uintptr_t>(target) & ~((uintptr_t) 0xFFF);
    const intptr_t step = 0x10000;
    const intptr_t max = (intptr_t) 1 << 25;
    for (intptr_t off = step; off < max; off += step) {
        for (int sign = -1; sign <= 1; sign += 2) {
            uintptr_t addr = (uintptr_t) ((intptr_t) base + sign * off);
            void *p = mmap(
                reinterpret_cast<void *>(addr),
                4096,
                PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                -1,
                0
            );
            if (p == MAP_FAILED) continue;
            if (p == reinterpret_cast<void *>(addr) && within_branch(target, p, 26)) return p;
            munmap(p, 4096);
        }
    }
    return nullptr;
}

#if defined(__aarch64__)
static bool patch_jump(void *target, void *replace) {
    if (!target || !replace) return false;
    void *tramp = alloc_near(target);
    if (!tramp || !within_branch(target, tramp, 28)) {
        if (tramp) munmap(tramp, 4096);
        return false;
    }
    auto *slot = reinterpret_cast<uint32_t *>(tramp);
    slot[0] = 0x58000050;
    slot[1] = 0xD61F0200;
    uintptr_t dest = reinterpret_cast<uintptr_t>(replace);
    memcpy(slot + 2, &dest, sizeof(dest));
    __builtin___clear_cache(reinterpret_cast<char *>(tramp), reinterpret_cast<char *>(tramp) + 16);

    if (!protect_range(target, 4, PROT_READ | PROT_WRITE) &&
        !protect_range(target, 4, PROT_READ | PROT_WRITE | PROT_EXEC)) {
        munmap(tramp, 4096);
        return false;
    }
    intptr_t imm26 = (reinterpret_cast<uint8_t *>(tramp) - reinterpret_cast<uint8_t *>(target)) / 4;
    auto *patch = reinterpret_cast<uint32_t *>(target);
    patch[0] = 0x14000000u | ((uint32_t) imm26 & 0x03FFFFFFu);
    __builtin___clear_cache(reinterpret_cast<char *>(target), reinterpret_cast<char *>(target) + 4);
    protect_range(target, 4, PROT_READ | PROT_EXEC);
    return true;
}
#else
static bool patch_jump(void *, void *) { return false; }
#endif

static void installAccessHooks() {
    void *libc = dlopen("libc.so", RTLD_NOW);
    if (!libc) return;
    void *p_access = dlsym(libc, "access");
    void *p_faccessat = dlsym(libc, "faccessat");
    int ok = 0;
    if (p_access && patch_jump(p_access, reinterpret_cast<void *>(hook_access))) ok++;
    if (p_faccessat && patch_jump(p_faccessat, reinterpret_cast<void *>(hook_faccessat))) ok++;
    LOGI("access hooks installed=%d", ok);
}

class AccessMonitor : public zygisk::ModuleBase {
    zygisk::Api *api = nullptr;
    JNIEnv *env = nullptr;
    bool inject = false;
    int gadgetFd = -1;
    int hooksFd = -1;
    std::string package;
    std::string dataDir;

    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        package = jstringToStd(env, args->nice_name);
        dataDir = jstringToStd(env, args->app_data_dir);

        int dirfd = api->getModuleDir();
        int tfd = dirfd >= 0 ? openat(dirfd, "target", O_RDONLY) : -1;
        std::string target = readFdAll(tfd);
        if (tfd >= 0) close(tfd);
        if (dirfd >= 0) close(dirfd);

        if (!isTargetProcess(package, target)) {
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        int cfd = api->connectCompanion();
        if (cfd < 0) {
            LOGE("companion failed for %s", package.c_str());
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            return;
        }
        gadgetFd = recvFd(cfd);
        hooksFd = recvFd(cfd);
        close(cfd);
        if (gadgetFd >= 0) api->exemptFd(gadgetFd);
        if (hooksFd >= 0) api->exemptFd(hooksFd);
        if (gadgetFd < 0) {
            LOGE("no gadget fd for %s", package.c_str());
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            return;
        }
        inject = true;
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *) override {
        if (!inject) return;
        std::string base = dataDir;
        if (base.empty() && !package.empty()) {
            base = "/data/user/0/" + package.substr(0, package.find(':'));
        }
        if (!package.empty()) {
            std::string pkg = package.substr(0, package.find(':'));
            strncpy(g_pkg, pkg.c_str(), sizeof(g_pkg) - 1);
            g_pkg[sizeof(g_pkg) - 1] = 0;
        }
        if (!base.empty()) {
            mkdir((base + "/cache").c_str(), 0700);
            writeText((base + "/cache/access_monitor_zygisk.log").c_str(), "scheduled=1\n", 0644);
        }
        auto *job = new InjectJob();
        job->gadgetFd = gadgetFd;
        job->hooksFd = hooksFd;
        job->package = package;
        job->dataDir = base;
        gadgetFd = hooksFd = -1;
        pthread_t th{};
        pthread_attr_t attr{};
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&th, &attr, injectThread, job) != 0) {
            LOGE("thread failed, injecting inline");
            doInject(*job);
            if (job->gadgetFd >= 0) close(job->gadgetFd);
            if (job->hooksFd >= 0) close(job->hooksFd);
            delete job;
        }
        pthread_attr_destroy(&attr);
    }

    void preServerSpecialize(zygisk::ServerSpecializeArgs *) override {
        api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

    struct InjectJob {
        int gadgetFd = -1;
        int hooksFd = -1;
        std::string package;
        std::string dataDir;
    };

    static void *injectThread(void *arg) {
        auto *job = static_cast<InjectJob *>(arg);
        usleep(1200 * 1000);
        doInject(*job);
        if (job->gadgetFd >= 0) close(job->gadgetFd);
        if (job->hooksFd >= 0) close(job->hooksFd);
        delete job;
        return nullptr;
    }

    static void doInject(const InjectJob &job) {
        if (job.dataDir.empty()) {
            LOGE("no data dir");
            return;
        }
        std::string cache = job.dataDir + "/cache";
        mkdir(cache.c_str(), 0700);

        std::string hooksPath = cache + "/access_monitor_hooks.js";
        std::string bootPath = cache + "/access_monitor_boot.js";
        std::string gadgetPath = cache + "/libfrida-gadget.so";
        std::string configPath = cache + "/libfrida-gadget.config.so";
        std::string logPath = cache + "/access_monitor_zygisk.log";

        if (job.hooksFd >= 0) {
            copyFdToPath(job.hooksFd, hooksPath.c_str(), 0644);
        }
        struct stat bootSt{};
        const char *scriptPath = (stat(bootPath.c_str(), &bootSt) == 0 && bootSt.st_size > 20)
            ? bootPath.c_str()
            : hooksPath.c_str();
        std::string cfg = std::string("{\"interaction\":{\"type\":\"script\",\"path\":\"") +
            scriptPath + "\"}}";
        writeText(configPath.c_str(), cfg, 0644);

        off_t expected = 0;
        if (job.gadgetFd >= 0) {
            struct stat src{};
            if (fstat(job.gadgetFd, &src) == 0) expected = src.st_size;
        }
        struct stat have{};
        bool needCopy = stat(gadgetPath.c_str(), &have) != 0 || have.st_size != expected || expected < 4096;
        if (needCopy && !copyFdToPath(job.gadgetFd, gadgetPath.c_str(), 0700)) {
            writeText(logPath.c_str(), "copy_gadget=fail\n", 0644);
            LOGE("copy gadget failed");
            return;
        }
        struct stat gst{};
        if (stat(gadgetPath.c_str(), &gst) != 0 || gst.st_size < 4096) {
            writeText(logPath.c_str(), "copy_gadget=empty\n", 0644);
            LOGE("gadget too small");
            return;
        }

        void *handle = dlopen(gadgetPath.c_str(), RTLD_NOW);
        const char *err = handle ? "ok" : dlerror();
        std::string line = std::string("pkg=") + job.package + " dlopen=" + (err ? err : "ok") + "\n";
        writeText(logPath.c_str(), line, 0644);
        if (handle) {
            LOGI("gadget loaded in %s", job.package.c_str());
        } else {
            LOGE("dlopen failed: %s", err ? err : "?");
        }
    }
};

static void companion(int client) {
    int gadget = open((std::string(kModuleDir) + "/libfrida-gadget.so").c_str(), O_RDONLY);
    int hooks = open((std::string(kModuleDir) + "/hooks.js").c_str(), O_RDONLY);
    char status[160];
    snprintf(status, sizeof(status), "companion gadget=%d hooks=%d\n", gadget >= 0, hooks >= 0);
    writeText((std::string(kModuleDir) + "/last_status").c_str(), status, 0644);
    if (gadget >= 0) {
        sendFd(client, gadget);
        close(gadget);
    } else {
        int dummy = open("/dev/null", O_RDONLY);
        sendFd(client, dummy);
        if (dummy >= 0) close(dummy);
        LOGE("companion: gadget missing");
    }
    if (hooks >= 0) {
        sendFd(client, hooks);
        close(hooks);
    } else {
        int dummy = open("/dev/null", O_RDONLY);
        sendFd(client, dummy);
        if (dummy >= 0) close(dummy);
    }
}

REGISTER_ZYGISK_MODULE(AccessMonitor)
REGISTER_ZYGISK_COMPANION(companion)
