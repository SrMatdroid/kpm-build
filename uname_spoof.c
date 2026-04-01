#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <common.h>
#include <kputils.h>
#include <linux/uaccess.h>
#include <syscall.h>
#include <linux/string.h>
#include <uapi/asm-generic/unistd.h>
#include <kallsyms.h>

KPM_NAME("uname_spoof");
KPM_VERSION("1.2.0");
KPM_LICENSE("GPL v3");
KPM_AUTHOR("srmatdroid");
KPM_DESCRIPTION("spoof uname syscall and proc/version");

#define __NEW_UTS_LEN 64
#define UTS_RELEASE_OFFSET  ((__NEW_UTS_LEN + 1) * 2)
#define UTS_VERSION_OFFSET  ((__NEW_UTS_LEN + 1) * 3)

#define FAKE_RELEASE "5.10.236-android12-9-00003-gfb24cf99ad97"
#define FAKE_VERSION "#1 SMP PREEMPT Wed Nov 26 00:00:00 UTC 2025"
#define FAKE_PROC_VERSION "Linux version " FAKE_RELEASE " (android-build@build) (gcc version 12.2.0) " FAKE_VERSION

static void after_uname(hook_fargs1_t *args, void *udata)
{
    if (args->ret != 0) return;
    void __user *uname = (void __user *)syscall_argn(args, 0);
    if (!uname) return;

    char clean_buffer[__NEW_UTS_LEN + 1];

    memset(clean_buffer, 0, sizeof(clean_buffer));
    strncpy(clean_buffer, FAKE_RELEASE, __NEW_UTS_LEN);
    compat_copy_to_user((char *)uname + UTS_RELEASE_OFFSET, clean_buffer, sizeof(clean_buffer));

    memset(clean_buffer, 0, sizeof(clean_buffer));
    strncpy(clean_buffer, FAKE_VERSION, __NEW_UTS_LEN);
    compat_copy_to_user((char *)uname + UTS_VERSION_OFFSET, clean_buffer, sizeof(clean_buffer));
}

// Hook para proc/version - intercepta seq_printf cuando escribe la versión
static void before_proc_version(hook_fargs4_t *args, void *udata)
{
    // Reemplaza el format string y los argumentos
    // arg0 = seq_file, arg1 = fmt string
    // Sobreescribimos el buffer del seq_file directamente
    void *seq = (void *)args->arg0;
    if (!seq) return;
    // seq_file->buf está al offset 0, seq_file->count al offset 8
    char **buf = (char **)seq;
    if (!buf || !*buf) return;
    strncpy(*buf, FAKE_PROC_VERSION, 255);
}

static void *proc_version_show_addr = 0;

static long uname_spoof_init(const char *args, const char *event, void *__user reserved)
{
    // Hook syscall uname
    hook_err_t err = inline_hook_syscalln(__NR_uname, 1, 0, after_uname, 0);
    if (err) {
        pr_err("uname_spoof: syscall hook failed: %d\n", err);
    } else {
        pr_info("uname_spoof: syscall hook ok\n");
    }

    // Hook proc_version_show
    proc_version_show_addr = (void *)kallsyms_lookup_name("proc_version_show");
    if (!proc_version_show_addr) {
        pr_warn("uname_spoof: proc_version_show not found, /proc/version unchanged\n");
    } else {
        hook_err_t err2 = hook_wrap4(proc_version_show_addr, before_proc_version, 0, 0);
        if (err2) {
            pr_err("uname_spoof: proc_version hook failed: %d\n", err2);
        } else {
            pr_info("uname_spoof: proc_version hook ok\n");
        }
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
    if (proc_version_show_addr) {
        unhook(proc_version_show_addr);
    }
    return 0;
}

KPM_INIT(uname_spoof_init);
KPM_CTL0(uname_spoof_control0);
KPM_EXIT(uname_spoof_exit);
