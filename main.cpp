// ChatRelay: a LeviLaunchroid native mod.
// Listens on 127.0.0.1:19131 inside the Minecraft process. When the game connects there
// (/wsserver localhost:19131) it opens a TLS connection to the bot hosted online and passes
// the bytes through unchanged, only fixing the Host header so the host can find the bot.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#ifdef RELAY_TEST
#define LOG(...) do { std::fprintf(stderr, "[relay] " __VA_ARGS__); std::fprintf(stderr, "\n"); } while (0)
#else
#include <android/log.h>
#include <jni.h>
#define LOG(...) __android_log_print(ANDROID_LOG_INFO, "ChatRelay", __VA_ARGS__)
#endif

#ifndef RELAY_HOST
#define RELAY_HOST "tiktok-bot-3ayj.onrender.com"
#endif
#ifndef RELAY_PORT
#define RELAY_PORT 443
#endif
#ifndef LOCAL_PORT
#define LOCAL_PORT 19131
#endif

namespace {

// ---------- the online side ----------
struct Remote {
    virtual ~Remote() {}
    virtual bool write(const char* data, int len) = 0;
    virtual int read(char* buf, int cap) = 0;   // <=0 means closed
    virtual void close() = 0;
};

#ifdef RELAY_TEST
struct TcpRemote : Remote {
    int fd = -1;
    bool open(const char* host, int port) {
        fd = ::socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_port = htons(port);
        inet_pton(AF_INET, host, &a.sin_addr);
        return ::connect(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0;
    }
    bool write(const char* d, int n) override {
        while (n > 0) { ssize_t w = ::send(fd, d, n, MSG_NOSIGNAL); if (w <= 0) return false; d += w; n -= static_cast<int>(w); }
        return true;
    }
    int read(char* b, int c) override { return static_cast<int>(::recv(fd, b, c, 0)); }
    void close() override { if (fd >= 0) { ::shutdown(fd, SHUT_RDWR); ::close(fd); fd = -1; } }
};
Remote* openRemote() {
    auto* r = new TcpRemote();
    if (!r->open("127.0.0.1", std::atoi(std::getenv("TEST_REMOTE_PORT")))) { delete r; return nullptr; }
    return r;
}
void detachThread() {}
#else
JavaVM* gVm = nullptr;

// the Android header takes JNIEnv**, other headers take void**: accept both
template <class V>
auto doAttach(V* vm, JNIEnv** e, int) -> decltype(vm->AttachCurrentThread(e, nullptr)) { return vm->AttachCurrentThread(e, nullptr); }
template <class V>
jint doAttach(V* vm, JNIEnv** e, long) { return vm->AttachCurrentThread(reinterpret_cast<void**>(e), nullptr); }

bool clearEx(JNIEnv* env) {
    if (env->ExceptionCheck() == JNI_TRUE) { env->ExceptionClear(); return true; }
    return false;
}

struct JavaTls : Remote {
    jobject sock = nullptr;
    jobject in = nullptr;
    jobject out = nullptr;
    jmethodID inRead = nullptr, outWrite = nullptr, outFlush = nullptr, sockClose = nullptr;
    volatile bool closed = false;

    static JNIEnv* env() {
        JNIEnv* e = nullptr;
        if (gVm->GetEnv(reinterpret_cast<void**>(&e), JNI_VERSION_1_6) == JNI_OK) return e;
        if (doAttach(gVm, &e, 0) != JNI_OK) return nullptr;
        return e;
    }

    bool open(const char* host, int port) {
        JNIEnv* e = env();
        if (!e) return false;
        jclass fc = e->FindClass("javax/net/ssl/SSLSocketFactory");
        if (!fc || clearEx(e)) return false;
        jmethodID getDefault = e->GetStaticMethodID(fc, "getDefault", "()Ljavax/net/SocketFactory;");
        jobject factory = getDefault ? e->CallStaticObjectMethod(fc, getDefault) : nullptr;
        if (!factory || clearEx(e)) return false;
        jclass sfc = e->FindClass("javax/net/SocketFactory");
        jmethodID create = e->GetMethodID(sfc, "createSocket", "(Ljava/lang/String;I)Ljava/net/Socket;");
        jstring jhost = e->NewStringUTF(host);
        jobject s = e->CallObjectMethod(factory, create, jhost, static_cast<jint>(port));
        if (!s || clearEx(e)) return false;
        jclass sc = e->FindClass("java/net/Socket");
        jmethodID getIn = e->GetMethodID(sc, "getInputStream", "()Ljava/io/InputStream;");
        jmethodID getOut = e->GetMethodID(sc, "getOutputStream", "()Ljava/io/OutputStream;");
        sockClose = e->GetMethodID(sc, "close", "()V");
        jmethodID setNoDelay = e->GetMethodID(sc, "setTcpNoDelay", "(Z)V");
        jmethodID setKeep = e->GetMethodID(sc, "setKeepAlive", "(Z)V");
        if (setNoDelay) e->CallVoidMethod(s, setNoDelay, JNI_TRUE);
        if (setKeep) e->CallVoidMethod(s, setKeep, JNI_TRUE);
        clearEx(e);
        jobject i = e->CallObjectMethod(s, getIn);
        jobject o = e->CallObjectMethod(s, getOut);
        if (!i || !o || clearEx(e)) return false;
        sock = e->NewGlobalRef(s);
        in = e->NewGlobalRef(i);
        out = e->NewGlobalRef(o);
        jclass ic = e->FindClass("java/io/InputStream");
        jclass oc = e->FindClass("java/io/OutputStream");
        inRead = e->GetMethodID(ic, "read", "([B)I");
        outWrite = e->GetMethodID(oc, "write", "([BII)V");
        outFlush = e->GetMethodID(oc, "flush", "()V");
        return inRead && outWrite && outFlush && sockClose;
    }

    bool write(const char* data, int len) override {
        JNIEnv* e = env();
        if (!e || closed) return false;
        jbyteArray arr = e->NewByteArray(len);
        e->SetByteArrayRegion(arr, 0, len, reinterpret_cast<const jbyte*>(data));
        e->CallVoidMethod(out, outWrite, arr, 0, static_cast<jint>(len));
        bool bad = clearEx(e);
        if (!bad) { e->CallVoidMethod(out, outFlush); bad = clearEx(e); }
        e->DeleteLocalRef(arr);
        return !bad;
    }
    int read(char* buf, int cap) override {
        JNIEnv* e = env();
        if (!e || closed) return -1;
        jbyteArray arr = e->NewByteArray(cap);
        jint n = e->CallIntMethod(in, inRead, arr);
        if (clearEx(e)) n = -1;
        if (n > 0) e->GetByteArrayRegion(arr, 0, n, reinterpret_cast<jbyte*>(buf));
        e->DeleteLocalRef(arr);
        return n;
    }
    void close() override {
        if (closed) return;
        closed = true;
        JNIEnv* e = env();
        if (e && sock) { e->CallVoidMethod(sock, sockClose); clearEx(e); }
    }
};

Remote* openRemote() {
    auto* r = new JavaTls();
    if (!r->open(RELAY_HOST, RELAY_PORT)) { LOG("could not open TLS to %s", RELAY_HOST); delete r; return nullptr; }
    return r;
}
void detachThread() { if (gVm) gVm->DetachCurrentThread(); }
#endif

// ---------- shared pipe logic ----------
bool sendAll(int fd, const char* d, int n) {
    while (n > 0) {
        ssize_t w = ::send(fd, d, static_cast<size_t>(n), MSG_NOSIGNAL);
        if (w <= 0) return false;
        d += w;
        n -= static_cast<int>(w);
    }
    return true;
}

// replace the value of the Host header so the host can tell which service is meant
std::string fixHost(const std::string& req, const std::string& host) {
    std::string out;
    size_t pos = 0;
    while (pos < req.size()) {
        size_t eol = req.find("\r\n", pos);
        if (eol == std::string::npos) eol = req.size();
        std::string line = req.substr(pos, eol - pos);
        std::string low;
        for (char c : line) low += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (low.rfind("host:", 0) == 0) line = "Host: " + host;
        else if (low.rfind("origin:", 0) == 0) line.clear();
        if (!(low.rfind("origin:", 0) == 0)) { out += line; out += "\r\n"; }
        pos = eol + 2;
    }
    return out;
}

struct Conn {
    int fd;
    Remote* remote;
};

void* downLoop(void* arg) {   // online -> game
    Conn* c = static_cast<Conn*>(arg);
    char buf[16384];
    for (;;) {
        int n = c->remote->read(buf, sizeof(buf));
        if (n <= 0) break;
        if (!sendAll(c->fd, buf, n)) break;
    }
    ::shutdown(c->fd, SHUT_RDWR);
    c->remote->close();
    detachThread();
    return nullptr;
}

void* connThread(void* arg) {
    int fd = static_cast<int>(reinterpret_cast<intptr_t>(arg));
    int one = 1;
    ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    Remote* remote = openRemote();
    if (!remote) { ::close(fd); detachThread(); return nullptr; }
    LOG("game connected, tunnel open");

    // first the HTTP upgrade request
    std::string head;
    char buf[16384];
    bool ok = true;
    while (head.find("\r\n\r\n") == std::string::npos) {
        ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n <= 0 || head.size() > 65536) { ok = false; break; }
        head.append(buf, static_cast<size_t>(n));
    }
    Conn conn{fd, remote};
    pthread_t down;
    bool started = false;
    if (ok) {
        size_t end = head.find("\r\n\r\n") + 4;
        std::string request = fixHost(head.substr(0, end), RELAY_HOST) ;
        std::string rest = head.substr(end);
        ok = remote->write(request.data(), static_cast<int>(request.size()));
        if (ok && !rest.empty()) ok = remote->write(rest.data(), static_cast<int>(rest.size()));
        if (ok) started = pthread_create(&down, nullptr, downLoop, &conn) == 0;
    }
    while (ok && started) {   // game -> online
        ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        if (!remote->write(buf, static_cast<int>(n))) break;
    }
    ::shutdown(fd, SHUT_RDWR);
    remote->close();
    if (started) pthread_join(down, nullptr);
    ::close(fd);
    delete remote;
    LOG("tunnel closed");
    detachThread();
    return nullptr;
}

volatile int gListen = -1;
volatile bool gRun = false;
pthread_t gAcceptThread;

void* acceptLoop(void*) {
    while (gRun) {
        int cfd = ::accept(gListen, nullptr, nullptr);
        if (cfd < 0) { if (!gRun) break; if (errno == EINTR) continue; ::usleep(200000); continue; }
        pthread_t t;
        if (pthread_create(&t, nullptr, connThread, reinterpret_cast<void*>(static_cast<intptr_t>(cfd))) == 0) pthread_detach(t);
        else ::close(cfd);
    }
    detachThread();
    return nullptr;
}

bool startRelay() {
    if (gRun) return true;
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return false;
    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(LOCAL_PORT);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0 || ::listen(fd, 8) != 0) {
        LOG("cannot listen on port %d (errno %d)", LOCAL_PORT, errno);
        ::close(fd);
        return false;
    }
    gListen = fd;
    gRun = true;
    if (pthread_create(&gAcceptThread, nullptr, acceptLoop, nullptr) != 0) { gRun = false; ::close(fd); return false; }
    LOG("relay listening on 127.0.0.1:%d -> %s", LOCAL_PORT, RELAY_HOST);
    return true;
}
void stopRelay() {
    if (!gRun) return;
    gRun = false;
    ::shutdown(gListen, SHUT_RDWR);
    ::close(gListen);
    pthread_join(gAcceptThread, nullptr);
    gListen = -1;
}

}  // namespace

#ifdef RELAY_TEST
extern "C" int relay_test_start() { return startRelay() ? 0 : 1; }
extern "C" void relay_test_stop() { stopRelay(); }
#else
struct ModRegistration {
    void* instance;
    bool (*load)(void*, void*);
    bool (*enable)(void*, void*);
    bool (*disable)(void*, void*);
    bool (*unload)(void*, void*);
};

static bool onLoad(void*, void* context) noexcept {
    if (!context) return false;
    gVm = *reinterpret_cast<JavaVM**>(context);
    return gVm != nullptr;
}
static bool onEnable(void*, void*) noexcept { return startRelay(); }
static bool onDisable(void*, void*) noexcept { stopRelay(); return true; }
static bool onUnload(void*, void*) noexcept { stopRelay(); gVm = nullptr; return true; }

static ModRegistration gReg = { nullptr, &onLoad, &onEnable, &onDisable, &onUnload };

extern "C" __attribute__((visibility("default"))) ModRegistration* PLGetModRegistration() { return &gReg; }
#endif
