// uname_spoof.kpm
// Hooks sys_newuname and rewrites the kernel build date
// to avoid build time drift detection.
//
// Build: aarch64-linux-gnu-gcc -O2 -nostdlib -shared -fPIC
//        -I/path/to/kpatch-sdk/include
//        -o uname_spoof.kpm uname_spoof.c
//
// Tested target: KernelSU-Next + KPatch-Next (Snapdragon 7s Gen 2 / HyperOS)

#include "kpmodule.h"
#include "kputils.h"
#include "linux/utsname.h"
#include "linux/uaccess.h"
#include "linux/string.h"

KPM_NAME("uname_spoof");
KPM_VERSION("1.0.0");
KPM_AUTHOR("Jose");
KPM_DESCRIPTION("Spoofs uname build date to eliminate time drift anomaly");

// ── Adjust this date to be close to your ro.build.date ──────────────────────
// ro.build.date on your device is 2025-11-26, so use something coherent.
// Format must match kernel utsname convention exactly.
#define FAKE_VERSION "#1 SMP PREEMPT Thu Nov 27 00:00:00 UTC 2025"
// ─────────────────────────────────────────────────────────────────────────────

// sys_newuname signature: long sys_newuname(struct utsname __user *name)
// We hook AFTER the real syscall runs (post-hook) so we can modify
// the userspace buffer that was already filled in.

static void uname_post_handler(hook_fargs2_t *args, void *udata)
{
    // args->ret = return value of sys_newuname (0 = success)
    if (args->ret != 0)
        return;

    // arg0 = struct utsname __user *name
    struct utsname __user *uname_user = (struct utsname __user *)args->arg0;

    struct utsname tmp;

    // Pull the struct out of userspace
    if (compat_copy_from_user(&tmp, uname_user, sizeof(tmp)))
        return;

    // Zero and overwrite the version field only.
    // utsname.version is __NEW_UTS_LEN+1 = 65 bytes.
    // The version field contains: "#1 SMP PREEMPT <date>"
    // The release field contains the kernel version string — leave it alone
    // so other checks (kernel version number) still pass.
    memset(tmp.version, 0, sizeof(tmp.version));
    strncpy(tmp.version, FAKE_VERSION, sizeof(tmp.version) - 1);

    // Write modified struct back to userspace
    compat_copy_to_user(uname_user, &tmp, sizeof(tmp));
}

// Hook descriptor
static struct hook hook_uname = {
    .symbol = "sys_newuname",        // kernel symbol to hook
    .post_handler = uname_post_handler,
};

// ── Module lifecycle ─────────────────────────────────────────────────────────

static long uname_spoof_init(const char *args, const char *event,
                              void *reserved)
{
    long ret = hook_wrap(&hook_uname);
    if (ret) {
        kp_err("uname_spoof: failed to hook sys_newuname (%ld)\n", ret);
        return ret;
    }
    kp_info("uname_spoof: hook installed, fake version: %s\n", FAKE_VERSION);
    return 0;
}

static long uname_spoof_exit(void *reserved)
{
    unhook_wrap(&hook_uname);
    kp_info("uname_spoof: hook removed\n");
    return 0;
}

// Control channel — optional, allows runtime args via kpatch ctl
static long uname_spoof_ctl(const char *args, char *__user res_buf,
                             uint32_t res_buf_len)
{
    return 0;
}

KPM_INIT(uname_spoof_init);
KPM_CTL(uname_spoof_ctl);
KPM_EXIT(uname_spoof_exit);
