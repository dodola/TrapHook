#include <jni.h>
#include <string>
#include <sys/ptrace.h>
#include <unistd.h>
#include <android/log.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include "sigmux.h"
#include <ucontext.h>

#define  LOG_TAG    "testjni"
#define  ALOG(...)  __android_log_print(ANDROID_LOG_INFO,LOG_TAG,__VA_ARGS__)
#define PAGE_START(addr)    (~(PAGE_SIZE - 1) & (addr))
#define SET_BIT0(addr)        (addr | 1)
#define CLEAR_BIT0(addr)    (addr & 0xFFFFFFFE)
#define TEST_BIT0(addr)        (addr & 1)
struct sigmux_registration *volatile r1 = NULL;

//static const char *testdata = "ddddddd";
static const unsigned char break_insn[] = {0xf0, 0x01, 0xf0, 0xe7};
static const unsigned char thumb_break_insn[] = {0x01, 0xde};
static unsigned char origin_insn[4];
static unsigned char origin_thumb_insn[2];
static sigjmp_buf jmp;

void insertTrap(uintptr_t addr);

void resetTrap(uintptr_t addr);

void ptrace_detach(pid_t target) {
    if (ptrace(PTRACE_DETACH, target, NULL, NULL) == -1) {
        ALOG("ptrace(PTRACE_DETACH) failed\n");
    }
}

void ptrace_attach(pid_t target) {
    int waitpidstatus;

    if (ptrace(PTRACE_ATTACH, target, NULL, NULL) == -1) {
        ALOG("ptrace(PTRACE_ATTACH) failed\n %s", strerror(errno));
        return;
    }

    if (waitpid(target, &waitpidstatus, WUNTRACED) != target) {
        ALOG("waitpid(%d) failed\n", target);
        return;
    }
}

JNIEXPORT static int add(int a, int b) {
    return a + b;
}

static void dump_memory(int pid, uintptr_t addr) {
    char code_buffer[64];
    char ascii_buffer[32];
    uintptr_t p, end;
    p = addr & ~3;
    p -= 32;
    if (p > addr) {
        p = 0;
    }
    end = p + 80;
    while (end < p)
        end -= 16;
    while (p < end) {
        char *asc_out = ascii_buffer;
        sprintf(code_buffer, "%08x ", p);
        int i;
        for (i = 0; i < 4; i++) {

            long data = ptrace(PTRACE_PEEKTEXT, pid, (void *) p, NULL);
//            ALOG("%s %d ======", strerror(errno), errno);
            sprintf(code_buffer + strlen(code_buffer), "%08lx ", data);
            int j;
            for (j = 0; j < 4; j++) {
                char val = (data >> (j * 8)) & 0xff;
                if (val >= 0x20 && val < 0x7f) {
                    *asc_out++ = val;
                } else {
                    *asc_out++ = '.';
                }
            }
            p += 4;
        }
        *asc_out = '\0';
        ALOG("%s %s\n", code_buffer, ascii_buffer);
    }
}

int add2(int a, int b) {
    return a * b + 111;
}


extern "C"
JNIEXPORT jint
JNICALL
Java_com_dodola_traphooks_MainActivity_intFromJNI(
        JNIEnv *env,
        jobject) {
    int result = add(1, 2);
    ALOG("%d=====", result);
    return result;
}

static void setJump() {
    if (sigsetjmp(jmp, 1) == 1) {
        ALOG("got longjmp from %p\n", r1);
//        sigmux_unregister(r1);

    }
}


static enum sigmux_action
handle_testreg(struct sigmux_siginfo *siginfo,
               void *handler_data) {
    const char *name = static_cast<const char *>(handler_data);
    ALOG("got signal (testreg) name=%s\n", name);
    if (!strcmp(static_cast<const char *>(handler_data), "add")) {
        struct ucontext *uc = reinterpret_cast<struct ucontext *>(siginfo->context);
        struct sigcontext *sc = reinterpret_cast<struct sigcontext *>(&uc->uc_mcontext);
        sc->arm_pc = reinterpret_cast<unsigned long>(add2);
//        sigmux_longjmp(siginfo, jmp, 1);//跳转别的地方去执行 for signal safe
    }
    return SIGMUX_CONTINUE_EXECUTION;
}

static struct sigmux_registration *
register_testreg(const char *name) {
    struct sigmux_registration *reg;
    sigset_t signals;

    sigemptyset(&signals);
    sigaddset(&signals, SIGTRAP);
    reg = sigmux_register(&signals, handle_testreg, (void *) name, 0);
    if (reg == NULL) {
        ALOG("sigmux_register failed: %s\n", strerror(errno));
    }

    ALOG("registered handler %p for %s\n", reg, name);
    return reg;
}


jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    setJump();
//    int pid = fork();
    uintptr_t addr = (uintptr_t) add;
//    if (pid < 0) {
//
//    } else if (pid == 0) { //.....放弃 ，hin不实用
//        ALOG("-----pid:%d,ppid:%d----", getpid(), getppid());
//        ptrace_attach(getppid());
//        dump_memory(getppid(), addr);
//        bp.addr = reinterpret_cast<void *>(addr);
//        hook_init(&bp);
//        enable_hook(getppid(), &bp);
//        dump_memory(getppid(), addr);
//        ptrace_detach(getppid());
//    } else{}
    insertTrap(addr);

    if (sigmux_init(SIGTRAP) != 0) {
        ALOG("sigmux_init failed: %s\n", strerror(errno));
        return JNI_VERSION_1_4;
    }

    r1 = register_testreg("add");

    return JNI_VERSION_1_4;
}

void insertTrap(uintptr_t addr) {
    mprotect((void *) PAGE_START(CLEAR_BIT0(addr)), PAGE_SIZE * 2, PROT_READ | PROT_WRITE | PROT_EXEC);

    int thumb_mode = ((uintptr_t) addr) & 1;
    if (thumb_mode) {
        addr = ((uintptr_t) addr & ~1);
    }

    if (thumb_mode) {
        memcpy(origin_thumb_insn, reinterpret_cast<const void *>(addr), 2);
        memcpy(reinterpret_cast<void *>(addr), thumb_break_insn, 2);
    } else {
        memcpy(origin_insn, reinterpret_cast<const void *>(addr), 4);
        memcpy(reinterpret_cast<void *>(addr), break_insn, 4);
    }
}

void resetTrap(uintptr_t addr) {
    mprotect((void *) PAGE_START(CLEAR_BIT0(addr)), PAGE_SIZE * 2, PROT_READ | PROT_WRITE | PROT_EXEC);

    int thumb_mode = ((uintptr_t) addr) & 1;
    if (thumb_mode) {
        addr = ((uintptr_t) addr & ~1);
    }

    if (thumb_mode) {
        memcpy(reinterpret_cast<void *>(addr), origin_thumb_insn, 2);
    } else {
        memcpy(reinterpret_cast<void *>(addr), origin_insn, 4);
    }
}
