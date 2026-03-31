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
KPM_VERSION("1.1.0");
KPM_LICENSE("GPL v3");
KPM_AUTHOR("srmatdroid");
KPM_DESCRIPTION("spoof uname release and build date clean");

#define __NEW_UTS_LEN 64
// Offsets correctos para la estructura new_utsname
#define UTS_RELEASE_OFFSET (__NEW_UTS_LEN + 1) * 1
#define UTS_VERSION_OFFSET (__NEW_UTS_LEN + 1) * 3

#define FAKE_RELEASE "5.10.236-android12-9-23456-ga90b2c"
#define FAKE_VERSION "#1 SMP PREEMPT Wed Nov 26 00:00:00 UTC 2025"

static void after_uname(hook_fargs1_t *args, void *udata)
{
    if (args->ret != 0) return;
    
    void __user *uname = (void __user *)syscall_argn(args, 0);
    if (!uname) return;

    // Buffer temporal para limpiar la memoria original
    char clean_buffer[__NEW_UTS_LEN + 1];

    // --- 1. Spoof del Kernel Release (Borra "Templar") ---
    memset(clean_buffer, 0, sizeof(clean_buffer)); 
    strncpy(clean_buffer, FAKE_RELEASE, __NEW_UTS_LEN);
    compat_copy_to_user((char *)uname + UTS_RELEASE_OFFSET, clean_buffer, sizeof(clean_buffer));

    // --- 2. Spoof de la Versión/Fecha ---
    memset(clean_buffer, 0, sizeof(clean_buffer));
    strncpy(clean_buffer, FAKE_VERSION, __NEW_UTS_LEN);
    compat_copy_to_user((char *)uname + UTS_VERSION_OFFSET, clean_buffer, sizeof(clean_buffer));
}

static long uname_spoof_init(const char *args, const char *event, void *__user reserved)
{
    // Hook a la syscall de uname
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
    // Deshacer el hook al salir
    inline_unhook_syscalln(__NR_uname, 0, after_uname);
    return 0;
}

KPM_INIT(uname_spoof_init);
KPM_CTL0(uname_spoof_control0);
KPM_EXIT(uname_spoof_exit);
