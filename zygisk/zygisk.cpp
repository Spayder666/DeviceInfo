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

static int raw_open(const char *path, int flags, mode_t mode) {
    return (int) syscall(__NR_openat, AT_FDCWD, path, flags, mode);
}

static int raw_mkdir(const char *path, mode_t mode) {
    return (int) syscall(__NR_mkdirat, AT_FDCWD, path, mode);
}

static int raw_chmod(const char *path, mode_t mode) {
    return (int) syscall(__NR_fchmodat, AT_FDCWD, path, mode, 0);
}

static int raw_stat(const char *path, struct stat *st) {
#ifdef __NR_newfstatat
    return (int) syscall(__NR_newfstatat, AT_FDCWD, path, st, 0);
#else
    return (int) syscall(__NR_fstatat64, AT_FDCWD, path, st, 0);
#endif
}

static int raw_fstat(int fd, struct stat *st) {
#ifdef __NR_fstat
    return (int) syscall(__NR_fstat, fd, st);
#else
    return fstat(fd, st);
#endif
}

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
    int out = raw_open(path, O_CREAT | O_WRONLY | O_TRUNC, mode);
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
    raw_chmod(path, mode);
    return ok && n >= 0;
}

static void writeText(const char *path, const std::string &text, mode_t mode) {
    int fd = raw_open(path, O_CREAT | O_WRONLY | O_TRUNC, mode);
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
    raw_chmod(path, mode);
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
    if (contains(p, "/sys/class/bluetooth")) return "bt.sysfs_mac";
    if (contains(p, "/sys/class/android_usb") && contains(p, "iserial")) return "sys.usb_serial";
    if (contains(p, "/sys/class/thermal")) return "sys.thermal";
    if (contains(p, "/sys/class/power_supply")) return "hw.battery_capacity";
    if (contains(p, "/sys/devices/system/cpu") && contains(p, "cpufreq")) return "sys.cpu_freq";
    if (contains(p, "/sys/devices/system/cpu")) return "sys.cpu";
    if (contains(p, "/sys/block")) return "sys.block_cid";
    if (contains(p, "/proc/cpuinfo")) return "proc.cpuinfo";
    if (contains(p, "/proc/meminfo")) return "proc.meminfo";
    if (contains(p, "/proc/version")) return "proc.version";
    if (contains(p, "boot_id")) return "proc.boot_id";
    if (contains(p, "/proc/self/auxv")) return "proc.auxv";
    if (contains(p, "/proc/uptime")) return "proc.uptime";
    if (contains(p, "/proc/stat")) return "proc.stat";
    if (contains(p, "/proc/self/mountinfo")) return "proc.mountinfo";
    if (contains(p, "/proc/mounts") || contains(p, "/proc/self/mounts")) return "root.mounts";
    if (contains(p, "/proc/net/arp")) return "proc.net_arp";
    if (contains(p, "/proc/net/route")) return "net.route";
    if (contains(p, "/dev/__properties")) return "proc.properties";
    if (contains(p, "/dev/gnss") || contains(p, "/dev/gps")) return "location.hal";
    if (starts_with(p, "/system/bin/su") || starts_with(p, "/system/xbin/su") ||
        starts_with(p, "/sbin/su") || starts_with(p, "/su/bin/su") ||
        starts_with(p, "/data/adb") || starts_with(p, "/sbin/.magisk") ||
        starts_with(p, "/debug_ramdisk") ||
        (p[0] == 's' && p[1] == 'u' && p[2] == 0)) {
        return "root.su";
    }
    size_t n = 0;
    for (const char *s = p; *s; s++) n++;
    if (n >= 3 && p[n - 3] == '/' && p[n - 2] == 's' && p[n - 1] == 'u') return "root.su";
    if (contains(p, "magisk") || contains(p, "zygisk")) return "root.magisk";
    if (contains(p, "lsposed") || contains(p, "/lspd") || contains(p, "lsplant")) return "root.lsposed";
    if (contains(p, "xposed")) return "root.xposed";
    if (contains(p, "frida") || contains(p, "gadget")) return "root.frida_detect";
    if (contains(p, "/proc/self/maps") || contains(p, "/proc/self/smaps") ||
        contains(p, "/proc/self/status") || contains(p, "/proc/self/task") ||
        contains(p, "/proc/self/mounts") || contains(p, "/proc/net/tcp")) {
        return "root.inject";
    }
    if (starts_with(p, "/proc/") || starts_with(p, "/sys/")) return "proc.properties";
    return nullptr;
}

static long long now_ms() {
    struct timeval tv{};
    gettimeofday(&tv, nullptr);
    return (long long) tv.tv_sec * 1000LL + tv.tv_usec / 1000LL;
}

static void sanitize_path(const char *in, char *out, size_t cap) {
    size_t n = 0;
    for (; in && *in && n + 1 < cap; in++) {
        unsigned char c = (unsigned char) *in;
        out[n++] = (c < 32 || c == '"' || c == '\\') ? '_' : (char) c;
    }
    out[n] = 0;
}

static void emit_fs(const char *id, const char *kind, const char *path) {
    static __thread int reenter = 0;
    if (reenter) return;
    if (!id || !kind || !path || !g_pkg[0]) return;

    static uint32_t last_hash[24];
    static long long last_ms[24];
    static int slot;
    uint32_t h = 2166136261u;
    for (const char *s = path; *s; s++) {
        h ^= (unsigned char) *s;
        h *= 16777619u;
    }
    h ^= (unsigned char) kind[0];
    long long t = now_ms();
    for (int i = 0; i < 24; i++) {
        if (last_hash[i] == h && t - last_ms[i] < 1200) return;
    }
    last_hash[slot] = h;
    last_ms[slot] = t;
    slot = (slot + 1) % 24;

    char safe[360];
    sanitize_path(path, safe, sizeof(safe));
    char line[720];
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
        t
    );
    reenter = 1;
    __android_log_print(ANDROID_LOG_INFO, "AccessMonFrida", "%s", line);
    reenter = 0;
}

static void on_path(const char *path, const char *kind) {
    const char *id = classify_fs_path(path);
    if (id) emit_fs(id, kind, path);
}

using openat_fn = int (*)(int, const char *, int, int);
static openat_fn orig_openat;

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

static int hook_openat(int dirfd, const char *path, int flags, int mode) {
    on_path(path, "openat");
    if (!orig_openat) {
        return (int) syscall(__NR_openat, dirfd, path, flags, mode);
    }
    return orig_openat(dirfd, path, flags, mode);
}

static bool protect_range(void *addr, size_t len, int prot) {
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) page = 4096;
    uintptr_t start = (uintptr_t) addr & ~((uintptr_t) page - 1);
    uintptr_t end = ((uintptr_t) addr + len + (uintptr_t) page - 1) & ~((uintptr_t) page - 1);
    return mprotect((void *) start, end - start, prot) == 0;
}

static bool protect_write(void *addr, size_t len) {
    return protect_range(addr, len, PROT_READ | PROT_WRITE) ||
        protect_range(addr, len, PROT_READ | PROT_WRITE | PROT_EXEC);
}

static void protect_rx(void *addr, size_t len) {
    protect_range(addr, len, PROT_READ | PROT_EXEC);
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
static bool insn_safe_a64(uint32_t insn) {
    if (insn == 0xD503233F || insn == 0xD503247F || insn == 0xD503245F || insn == 0xD503241F) {
        return true;
    }
    uint32_t top = insn >> 24;
    if (top == 0xA9 || top == 0xA8 || top == 0x6D || top == 0x6C) return true;
    return (insn & 0xFF8003FF) == 0xD10003FF;
}

static void *make_orig_a64(void *target) {
    uint32_t first = *reinterpret_cast<uint32_t *>(target);
    if (!insn_safe_a64(first)) return nullptr;
    void *page = mmap(nullptr, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) return nullptr;
    auto *p = reinterpret_cast<uint32_t *>(page);
    p[0] = first;
    p[1] = 0x58000050;
    p[2] = 0xD61F0200;
    uintptr_t back = reinterpret_cast<uintptr_t>(target) + 4;
    memcpy(p + 3, &back, sizeof(back));
    __builtin___clear_cache(reinterpret_cast<char *>(page), reinterpret_cast<char *>(page) + 24);
    return page;
}

static bool patch_jump(void *target, void *replace) {
    if (!target || !replace) return false;
    void *tramp = alloc_near(target);
    if (!tramp || !within_branch(target, tramp, 28)) {
        if (tramp) munmap(tramp, 4096);
        return false;
    }
    auto *slot = reinterpret_cast<uint32_t *>(tramp);
    slot[0] = 0x58000050; // LDR X16, #8
    slot[1] = 0xD61F0200; // BR X16
    uintptr_t dest = reinterpret_cast<uintptr_t>(replace);
    memcpy(slot + 2, &dest, sizeof(dest));
    __builtin___clear_cache(reinterpret_cast<char *>(tramp), reinterpret_cast<char *>(tramp) + 16);

    if (!protect_write(target, 4)) {
        munmap(tramp, 4096);
        return false;
    }
    intptr_t imm26 = (reinterpret_cast<uint8_t *>(tramp) - reinterpret_cast<uint8_t *>(target)) / 4;
    auto *patch = reinterpret_cast<uint32_t *>(target);
    patch[0] = 0x14000000u | ((uint32_t) imm26 & 0x03FFFFFFu);
    __builtin___clear_cache(reinterpret_cast<char *>(target), reinterpret_cast<char *>(target) + 4);
    protect_rx(target, 4);
    return true;
}
#elif defined(__arm__)
static bool patch_jump(void *target, void *replace) {
    if (!target || !replace) return false;
    uintptr_t raw = reinterpret_cast<uintptr_t>(target);
    if (raw & 1) return false;
    void *tramp = alloc_near(target);
    if (!tramp || !within_branch(target, tramp, 26)) {
        if (tramp) munmap(tramp, 4096);
        return false;
    }
    auto *slot = reinterpret_cast<uint32_t *>(tramp);
    slot[0] = 0xE51FF004; // LDR PC, [PC, #-4]
    uintptr_t dest = reinterpret_cast<uintptr_t>(replace);
    memcpy(slot + 1, &dest, sizeof(dest));
    __builtin___clear_cache(reinterpret_cast<char *>(tramp), reinterpret_cast<char *>(tramp) + 8);

    if (!protect_write(target, 4)) {
        munmap(tramp, 4096);
        return false;
    }
    intptr_t imm24 = (reinterpret_cast<uint8_t *>(tramp) - reinterpret_cast<uint8_t *>(target) - 8) / 4;
    auto *patch = reinterpret_cast<uint32_t *>(target);
    patch[0] = 0xEA000000u | ((uint32_t) imm24 & 0x00FFFFFFu);
    __builtin___clear_cache(reinterpret_cast<char *>(target), reinterpret_cast<char *>(target) + 4);
    protect_rx(target, 4);
    return true;
}
#else
static bool patch_jump(void *, void *) { return false; }
#endif

static void installLibcFsHooks(const char *dataDir) {
    void *libc = dlopen("libc.so", RTLD_NOW);
    if (!libc) {
        LOGE("dlopen libc failed");
        return;
    }
    void *p_access = dlsym(libc, "access");
    void *p_faccessat = dlsym(libc, "faccessat");
    void *p_openat = dlsym(libc, "openat");

    int ok = 0;
    if (p_access && patch_jump(p_access, reinterpret_cast<void *>(hook_access))) ok++;
    if (p_faccessat && patch_jump(p_faccessat, reinterpret_cast<void *>(hook_faccessat))) ok++;
#if defined(__aarch64__)
    if (p_openat) {
        void *orig = make_orig_a64(p_openat);
        if (orig && patch_jump(p_openat, reinterpret_cast<void *>(hook_openat))) {
            orig_openat = reinterpret_cast<openat_fn>(orig);
            ok++;
        } else if (orig) {
            munmap(orig, 4096);
        }
    }
#else
    (void) p_openat;
#endif
    LOGI("libc fs hooks installed=%d", ok);
    if (ok > 0 && dataDir && dataDir[0]) {
        std::string marker = std::string(dataDir) + "/cache/access_monitor_native_fs";
        writeText(marker.c_str(), "1\n", 0644);
    }
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

        if (target.empty() || package.empty() || package != target) {
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
        // Do not dlopen gadget on the specialize thread: Frida parses the
        // whole script in its constructor and freezes many apps at startup.
        // Keep this .so mapped (no DLCLOSE) so the delayed thread stays valid.
        std::string base = dataDir;
        if (base.empty() && !package.empty()) {
            base = "/data/user/0/" + package;
        }
        if (!package.empty()) {
            strncpy(g_pkg, package.c_str(), sizeof(g_pkg) - 1);
            g_pkg[sizeof(g_pkg) - 1] = 0;
        }
        if (!base.empty()) {
            raw_mkdir((base + "/cache").c_str(), 0700);
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
            installLibcFsHooks(job->dataDir.c_str());
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
        usleep(350 * 1000);
        installLibcFsHooks(job->dataDir.c_str());
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
        raw_mkdir(cache.c_str(), 0700);

        std::string hooksPath = cache + "/access_monitor_hooks.js";
        std::string gadgetPath = cache + "/libfrida-gadget.so";
        std::string configPath = cache + "/libfrida-gadget.config.so";
        std::string logPath = cache + "/access_monitor_zygisk.log";

        if (job.hooksFd >= 0) {
            copyFdToPath(job.hooksFd, hooksPath.c_str(), 0644);
        }
        std::string cfg = std::string("{\"interaction\":{\"type\":\"script\",\"path\":\"") +
            hooksPath + "\"}}";
        writeText(configPath.c_str(), cfg, 0644);

        off_t expected = 0;
        if (job.gadgetFd >= 0) {
            struct stat src{};
            if (raw_fstat(job.gadgetFd, &src) == 0) expected = src.st_size;
        }
        struct stat have{};
        bool needCopy = raw_stat(gadgetPath.c_str(), &have) != 0 || have.st_size != expected || expected < 4096;
        if (needCopy && !copyFdToPath(job.gadgetFd, gadgetPath.c_str(), 0700)) {
            writeText(logPath.c_str(), "copy_gadget=fail\n", 0644);
            LOGE("copy gadget failed");
            return;
        }
        struct stat gst{};
        if (raw_stat(gadgetPath.c_str(), &gst) != 0 || gst.st_size < 4096) {
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
