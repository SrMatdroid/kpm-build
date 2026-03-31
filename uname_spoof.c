#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <common.h>
#include <kputils.h>
#include <linux/uaccess.h>
#include <syscall.h>
#include <linux/string.h>
#include <uapi/asm-generic/unistd.h>

KPM_NAME("uname_spoof");
KPM_VERSION("1.1.0"); // Subimos versión por el nuevo feature
KPM_LICENSE("GPL v3");
KPM_AUTHOR("srmatdroid");
KPM_DESCRIPTION("spoof uname release and build date");

#define __NEW_UTS_LEN 64
// Offset para 'release' (campo 2 de la estructura)
#define UTS_RELEASE_OFFSET (__NEW_UTS_LEN + 1) * 2
// Offset para 'version' (campo 3 de la estructura)
#define UTS_VERSION_OFFSET (__NEW_UTS_LEN + 1) * 3

#define FAKE_RELEASE "5.10.236-android12-9-23456-ga90b2c"
#define FAKE_VERSION "#1 SMP PREEMPT Wed Nov 26 00:00:00 UTC 2025"

static void after_uname(hook_fargs1_t *args, void *udata)
{
    if (args->ret != 0) return;
    
    void __user *uname = (void __user *)syscall_argn(args, 0);
    if (!uname) return;

    // Spoof de la Versión (Kernel Release)
    char fake_rel[] = FAKE_RELEASE;
    compat_copy_to_user((char *)uname + UTS_RELEASE_OFFSET, fake_rel, sizeof(fake_rel));

    // Spoof de la Fecha (Kernel Version)
    char fake_ver[] = FAKE_VERSION;
    compat_copy_to_user((char *)uname + UTS_VERSION_OFFSET, fake_ver, sizeof(fake_ver));
}

static long uname_spoof_init(const char *args, const char *event, void *__user reserved)
{
    hook_err_t err = inline_hook_syscalln(__NR_uname, 1, 0, after_uname, 0);
    if (err) {
        [span_1](start_span)pr_err("uname_spoof: hook failed: %d\n", err);[span_1](end_span)
    } else {
        [span_2](start_span)pr_info("uname_spoof: hook ok\n");[span_2](end_span)
    }
    return 0;
}

static long uname_spoof_control0(const char *args, char *__user out_msg, int outlen)
{
    return 0;
}

static long uname_spoof_exit(void *__user reserved)
{
    inline_unhook_syscalln(__NR_uname, 0, after_uname);
    return 0;
}

KPM_INIT(uname_spoof_init);
KPM_CTL0(uname_spoof_control0);
KPM_EXIT(uname_spoof_exit);
