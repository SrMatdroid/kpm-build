#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <uapi/asm-generic/unistd.h>

// Librerías de tu framework KPM
#include <compiler.h>
#include <kpmodule.h>
#include <common.h>
#include <kputils.h>
#include <syscall.h>
#include <kallsyms.h>

KPM_NAME("uname_spoof_v2");
KPM_VERSION("1.4.0");
KPM_LICENSE("GPL v3");
KPM_AUTHOR("srmatdroid");
KPM_DESCRIPTION("Spoof uname, /proc/version and /proc/cmdline sin offsets manuales");

#define __NEW_UTS_LEN 64
#define UTS_RELEASE_OFFSET  ((__NEW_UTS_LEN + 1) * 2)
#define UTS_VERSION_OFFSET  ((__NEW_UTS_LEN + 1) * 3)

#define FAKE_RELEASE "5.10.236-android12-9-00003-gfb24cf99ad97"
#define FAKE_VERSION "#1 SMP PREEMPT Wed Nov 26 00:00:00 UTC 2025"

#define FAKE_PROC_VERSION \
    "Linux version 5.10.236-android12-9-00003-gfb24cf99ad97 " \
    "(android-build@build44) (gcc version 12.2.0 (GCC)) " \
    "#1 SMP PREEMPT Wed Nov 26 00:00:00 UTC 2025\n"

#define FAKE_PROC_CMDLINE \
    "console=ttyMSM0,115200n8 androidboot.hardware=qcom " \
    "androidboot.console=ttyMSM0 lpm_levels.sleep_disabled=1 " \
    "androidboot.selinux=enforcing\n"

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

// --- Mejora de parcheo para seq_file ---
static void patch_seq_file_safe(void *seq_ptr, const char *fake_data)
{
    if (!seq_ptr) return;
    
    struct seq_file *m = (struct seq_file *)seq_ptr;
    
    // Verificamos que el buffer exista
    if (m->buf) {
        size_t len = strlen(fake_data);
        // Nos aseguramos de no desbordar el buffer original del kernel
        if (len >= m->size) len = m->size - 1;
        
        memcpy(m->buf, fake_data, len);
        m->count = len; // Forzamos el contador al tamaño de nuestra cadena
    }
}

// --- Hooks de /proc ---
static void after_proc_version(hook_fargs4_t *args, void *udata)
{
    patch_seq_file_safe((void *)args->arg0, FAKE_PROC_VERSION);
}

static void after_proc_cmdline(hook_fargs4_t *args, void *udata)
{
    patch_seq_file_safe((void *)args->arg0, FAKE_PROC_CMDLINE);
}

static void *proc_version_show_addr = 0;
static void *proc_cmdline_show_addr = 0;

static long uname_spoof_init(const char *args, const char *event, void *__user reserved)
{
    // 1. Hook uname
    hook_err_t err = inline_hook_syscalln(__NR_uname, 1, 0, after_uname, 0);
    
    // 2. Hook /proc/version
    proc_version_show_addr = (void *)kallsyms_lookup_name("proc_version_show");
    if (proc_version_show_addr) {
        hook_wrap4(proc_version_show_addr, 0, after_proc_version, 0);
    }

    // 3. Hook /proc/cmdline (Probando ambos nombres comunes)
    proc_cmdline_show_addr = (void *)kallsyms_lookup_name("proc_cmdline_show");
    if (!proc_cmdline_show_addr)
        proc_cmdline_show_addr = (void *)kallsyms_lookup_name("cmdline_proc_show");

    if (proc_cmdline_show_addr) {
        hook_wrap4(proc_cmdline_show_addr, 0, after_proc_cmdline, 0);
    }

    return 0;
}

static long uname_spoof_exit(void *__user reserved)
{
    inline_unhook_syscalln(__NR_uname, 0, after_uname);
    if (proc_version_show_addr) unhook(proc_version_show_addr);
    if (proc_cmdline_show_addr) unhook(proc_cmdline_show_addr);
    return 0;
}

static long uname_spoof_control0(const char *args, char *__user out_msg, int outlen)
{
    return 0;
}

KPM_INIT(uname_spoof_init);
KPM_CTL0(uname_spoof_control0);
KPM_EXIT(uname_spoof_exit);
