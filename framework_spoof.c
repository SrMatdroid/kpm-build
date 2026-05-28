// SPDX-License-Identifier: GPL-3.0-only
// KPM: framework-spoof v1.4.0
// Redirige framework.jar al backup para bypasear Native Detector

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/kallsyms.h>

// --- Declaraciones de la API de KPM (sin necesidad de hook.h) ---
#define KPM_NAME(name)          static const char kpm_name[] = name
#define KPM_VERSION(ver)        static const char kpm_version[] = ver
#define KPM_LICENSE(lic)        MODULE_LICENSE(lic)
#define KPM_AUTHOR(auth)        MODULE_AUTHOR(auth)
#define KPM_DESCRIPTION(desc)   MODULE_DESCRIPTION(desc)

#define KPM_INIT(f)             static int __init _kpm_init(void) { return f(NULL, NULL, NULL); } module_init(_kpm_init)
#define KPM_EXIT(f)             static void __exit _kpm_exit(void) { f(NULL); } module_exit(_kpm_exit)

typedef enum {
    HOOK_NO_ERR = 0,
    HOOK_ERR_GENERAL,
} hook_err_t;

typedef struct {
    unsigned long arg0, arg1, arg2, arg3, arg4, arg5;
} hook_fargs3_t;

extern hook_err_t hook_wrap(void *func, int num_args,
                            void *before, void *after, void *udata);
extern void unhook_func(void *func);
// --------------------------------------------------------------

#define fs_info(fmt, ...) printk(KERN_INFO "[fs] " fmt, ##__VA_ARGS__)
#define fs_err(fmt, ...)  printk(KERN_ERR  "[fs][E] " fmt, ##__VA_ARGS__)
#define fs_warn(fmt, ...) printk(KERN_WARNING "[fs][W] " fmt, ##__VA_ARGS__)

#define BACKUP_PATH "/data/adb/kpm_data/framework_orig.jar"
#define SLOTS 8

struct spoof_slot {
    pid_t pid;
    struct filename *alt;
};

static struct spoof_slot g_slots[SLOTS];
static DEFINE_SPINLOCK(g_slots_lock);

static void save_alt(pid_t pid, struct filename *alt)
{
    unsigned long flags;
    int i;
    spin_lock_irqsave(&g_slots_lock, flags);
    for (i = 0; i < SLOTS; i++) {
        if (!g_slots[i].pid) {
            g_slots[i].pid = pid;
            g_slots[i].alt = alt;
            break;
        }
    }
    spin_unlock_irqrestore(&g_slots_lock, flags);
}

static struct filename *take_alt(pid_t pid)
{
    struct filename *alt = NULL;
    unsigned long flags;
    int i;
    spin_lock_irqsave(&g_slots_lock, flags);
    for (i = 0; i < SLOTS; i++) {
        if (g_slots[i].pid == pid) {
            alt = g_slots[i].alt;
            g_slots[i].pid = 0;
            g_slots[i].alt = NULL;
            break;
        }
    }
    spin_unlock_irqrestore(&g_slots_lock, flags);
    return alt;
}

static struct filename *(*getname_kernel_ptr)(const char *);
static void (*putname_ptr)(struct filename *);

static void resolve_fs_symbols(void)
{
    getname_kernel_ptr = (void *)kallsyms_lookup_name("getname_kernel");
    putname_ptr = (void *)kallsyms_lookup_name("putname");
    if (!getname_kernel_ptr || !putname_ptr)
        fs_warn("getname_kernel o putname no encontrados\n");
}

static void before_do_filp_open(hook_fargs3_t *args, void *udata)
{
    struct filename *pn;
    struct filename *alt;
    (void)udata;

    pn = (struct filename *)(unsigned long)args->arg1;
    if (!pn || !pn->name) return;
    if (!strstr(pn->name, "framework.jar")) return;
    if (!strstr(current->comm, "nativecheck") && !strstr(current->comm, "reveny")) return;

    if (!getname_kernel_ptr) resolve_fs_symbols();
    if (!getname_kernel_ptr) return;

    alt = getname_kernel_ptr(BACKUP_PATH);
    if (IS_ERR(alt)) {
        fs_warn("getname_kernel error: %ld\n", PTR_ERR(alt));
        return;
    }

    save_alt(current->pid, alt);
    args->arg1 = (unsigned long)alt;
    fs_info("redirigido framework.jar para '%s' (pid %d)\n", current->comm, current->pid);
}

static void after_do_filp_open(hook_fargs3_t *args, void *udata)
{
    struct filename *alt;
    (void)args;
    (void)udata;
    alt = take_alt(current->pid);
    if (alt && putname_ptr) putname_ptr(alt);
}

static long kpm_init(const char *args, const char *event, void *reserved)
{
    unsigned long sym;
    hook_err_t err;
    (void)args; (void)event; (void)reserved;

    resolve_fs_symbols();

    sym = kallsyms_lookup_name("do_filp_open");
    if (!sym) {
        fs_err("do_filp_open no encontrado\n");
        return -1;
    }

    err = hook_wrap((void *)sym, 3,
                    (void *)before_do_filp_open,
                    (void *)after_do_filp_open,
                    NULL);
    if (err != HOOK_NO_ERR) {
        fs_err("hook_wrap falló: %d\n", err);
        return -1;
    }

    fs_info("cargado — backup: %s\n", BACKUP_PATH);
    return 0;
}

static long kpm_exit(void *reserved)
{
    unsigned long sym;
    (void)reserved;
    sym = kallsyms_lookup_name("do_filp_open");
    if (sym) unhook_func((void *)sym);
    fs_info("descargado\n");
    return 0;
}

KPM_INIT(kpm_init);
KPM_EXIT(kpm_exit);
