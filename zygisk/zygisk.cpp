#include "zygisk.hpp"

#include <android/log.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <string>

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "AccessMonZygisk", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "AccessMonZygisk", __VA_ARGS__)

static constexpr const char *kModuleDir = "/data/adb/modules/access_monitor";

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
        doInject();
        if (gadgetFd >= 0) close(gadgetFd);
        if (hooksFd >= 0) close(hooksFd);
        gadgetFd = hooksFd = -1;
        if (api) api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

    void preServerSpecialize(zygisk::ServerSpecializeArgs *) override {
        api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

    void doInject() {
        std::string base = dataDir;
        if (base.empty() && !package.empty()) {
            base = "/data/user/0/" + package;
        }
        if (base.empty()) {
            LOGE("no data dir");
            return;
        }
        std::string cache = base + "/cache";
        mkdir(cache.c_str(), 0700);

        std::string hooksPath = cache + "/access_monitor_hooks.js";
        std::string gadgetPath = cache + "/libfrida-gadget.so";
        std::string configPath = cache + "/libfrida-gadget.config.so";
        std::string logPath = cache + "/access_monitor_zygisk.log";

        if (hooksFd >= 0) {
            copyFdToPath(hooksFd, hooksPath.c_str(), 0644);
        }
        std::string cfg = std::string("{\"interaction\":{\"type\":\"script\",\"path\":\"") +
            hooksPath + "\"}}";
        writeText(configPath.c_str(), cfg, 0644);
        if (!copyFdToPath(gadgetFd, gadgetPath.c_str(), 0700)) {
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
        std::string line = std::string("pkg=") + package + " dlopen=" + (err ? err : "ok") + "\n";
        writeText(logPath.c_str(), line, 0644);
        if (handle) {
            LOGI("gadget loaded in %s", package.c_str());
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
