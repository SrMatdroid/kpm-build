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
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("jose");
KPM_DESCRIPTION("spoof uname build date");

#define __NEW_UTS_LEN 64
#define UTS_VERSION_OFFSET ((__NEW_UTS_LEN + 1) * 3)
#define FAKE_VERSION "#1 SMP PREEMPT Wed Nov 26 00:00:00 UTC 2025"

static void after_uname(hook_fargs1_t *args, void *udata)
{
    if (args->ret != 0) return;
    void __user *uname = (void __user *)syscall_argn(args, 0);
    if (!uname) return;
    char fake[] = FAKE_VERSION;
    compat_copy_to_user((char *)uname + UTS_VERSION_OFFSET, fake, sizeof(fake));
}

static long uname_spoof_init(const char *args, const char *event, void *__user reserved)
{
    hook_err_t err = inline_hook_syscalln(__NR_uname, 1, 0, after_uname, 0);
    if (err) {
        pr_err("uname_spoof: hook failed: %d\n", err);
    } else {
        pr_info("uname_spoof: hook ok\n");
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
