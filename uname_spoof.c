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
KPM_VERSION("1.3.0");
KPM_LICENSE("GPL v3");
KPM_AUTHOR("srmatdroid");
KPM_DESCRIPTION("Spoof uname syscall, /proc/version and /proc/cmdline");

#define __NEW_UTS_LEN 64
#define UTS_RELEASE_OFFSET  ((__NEW_UTS_LEN + 1) * 2)
#define UTS_VERSION_OFFSET  ((__NEW_UTS_LEN + 1) * 3)

#define FAKE_RELEASE "5.10.236-android12-9-00003-gfb24cf99ad97"
#define FAKE_VERSION "#1 SMP PREEMPT Wed Nov 26 00:00:00 UTC 2025"

#define FAKE_PROC_VERSION \
    "Linux version 5.10.236-android12-9-00003-gfb24cf99ad97 " \
    "(android-build@build44) (gcc version 12.2.0 (GCC)) " \
    "#1 SMP PREEMPT Wed Nov 26 00:00:00 UTC 2025"

// Ajusta este cmdline al tuyo real (consíguelo con: cat /proc/cmdline en stock)
#define FAKE_PROC_CMDLINE \
    "console=ttyMSM0,115200n8 androidboot.hardware=qcom " \
    "androidboot.console=ttyMSM0 lpm_levels.sleep_disabled=1 " \
    "androidboot.selinux=enforcing"

// --- uname syscall hook ---
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

// --- Helper: sobreescribe el buffer del seq_file ya rellenado ---
// Layout de seq_file en kernel 5.10 aarch64:
//   buf   @ +0   (char *)
//   size  @ +8   (size_t)
//   from  @ +16  (size_t)
//   count @ +24  (size_t)
static void patch_seq_file(void *seq, const char *fake)
{
    if (!seq) return;
    char **buf    = (char **)((char *)seq + 0);
    size_t *count = (size_t *)((char *)seq + 24);
    if (!buf || !*buf) return;

    size_t len = strlen(fake);
    memcpy(*buf, fake, len);
    (*buf)[len] = '\n';
    *count = len + 1;
}

// --- /proc/version after hook ---
static void after_proc_version(hook_fargs4_t *args, void *udata)
{
    patch_seq_file((void *)args->arg0, FAKE_PROC_VERSION);
}

// --- /proc/cmdline after hook ---
static void after_proc_cmdline(hook_fargs4_t *args, void *udata)
{
    patch_seq_file((void *)args->arg0, FAKE_PROC_CMDLINE);
}

static void *proc_version_show_addr = 0;
static void *proc_cmdline_show_addr = 0;

static long uname_spoof_init(const char *args, const char *event, void *__user reserved)
{
    // --- Hook syscall uname ---
    hook_err_t err = inline_hook_syscalln(__NR_uname, 1, 0, after_uname, 0);
    if (err) pr_err("uname_spoof: syscall hook failed: %d\n", err);
    else     pr_info("uname_spoof: syscall hook ok\n");

    // --- Hook /proc/version ---
    proc_version_show_addr = (void *)kallsyms_lookup_name("proc_version_show");
    if (!proc_version_show_addr) {
        pr_warn("uname_spoof: proc_version_show not found\n");
    } else {
        // hook_wrap4(addr, before, after, udata)
        hook_err_t e = hook_wrap4(proc_version_show_addr, 0, after_proc_version, 0);
        if (e) pr_err("uname_spoof: proc_version hook failed: %d\n", e);
        else   pr_info("uname_spoof: proc_version hook ok\n");
    }

    // --- Hook /proc/cmdline ---
    // El símbolo varía según vendor kernel, probamos los dos nombres conocidos
    proc_cmdline_show_addr = (void *)kallsyms_lookup_name("proc_cmdline_show");
    if (!proc_cmdline_show_addr)
        proc_cmdline_show_addr = (void *)kallsyms_lookup_name("cmdline_proc_show");

    if (!proc_cmdline_show_addr) {
        pr_warn("uname_spoof: cmdline show symbol not found\n");
    } else {
        hook_err_t e = hook_wrap4(proc_cmdline_show_addr, 0, after_proc_cmdline, 0);
        if (e) pr_err("uname_spoof: cmdline hook failed: %d\n", e);
        else   pr_info("uname_spoof: cmdline hook ok\n");
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
    if (proc_version_show_addr) unhook(proc_version_show_addr);
    if (proc_cmdline_show_addr) unhook(proc_cmdline_show_addr);
    return 0;
}

KPM_INIT(uname_spoof_init);
KPM_CTL0(uname_spoof_control0);
KPM_EXIT(uname_spoof_exit);