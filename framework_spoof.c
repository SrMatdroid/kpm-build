// SPDX-License-Identifier: GPL-3.0-only
// KPM: framework-spoof v1.3.0
// Redirige framework.jar al backup cuando lo abre Native Detector
// Autor: SrMatdroid

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/kallsyms.h>
#include <linux/version.h>

#include <hook.h>

KPM_NAME("framework-spoof");
KPM_VERSION("1.3.0");
KPM_LICENSE("GPL v3");
KPM_AUTHOR("SrMatdroid");
KPM_DESCRIPTION("Redirige framework.jar al backup para bypasear Native Detector");

#define fs_info(fmt, ...) printk(KERN_INFO "[fs] " fmt, ##__VA_ARGS__)
#define fs_err(fmt, ...)  printk(KERN_ERR  "[fs][E] " fmt, ##__VA_ARGS__)
#define fs_warn(fmt, ...) printk(KERN_WARN "[fs][W] " fmt, ##__VA_ARGS__)

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
    spin_lock_irqsave(&g_slots_lock, flags);
    for (int i = 0; i < SLOTS; i++) {
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
    spin_lock_irqsave(&g_slots_lock, flags);
    for (int i = 0; i < SLOTS; i++) {
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

static struct filename *(*getname_kernel_ptr)(const char *filename);
static void (*putname_ptr)(struct filename *name);

static void resolve_fs_symbols(void)
{
    getname_kernel_ptr = (void *)kallsyms_lookup_name("getname_kernel");
    putname_ptr = (void *)kallsyms_lookup_name("putname");
    if (!getname_kernel_ptr || !putname_ptr)
        fs_warn("getname_kernel o putname no encontrados\n");
}

static void before_do_filp_open(hook_fargs3_t *args, void *udata)
{
    struct filename *pn = (struct filename *)(unsigned long)args->arg1;
    if (!pn || !pn->name)
        return;
    if (!strstr(pn->name, "framework.jar"))
        return;

    if (!strstr(current->comm, "nativecheck") && !strstr(current->comm, "reveny"))
        return;

    if (!getname_kernel_ptr) {
        fs_warn("getname_kernel no disponible\n");
        return;
    }

    struct filename *alt = getname_kernel_ptr(BACKUP_PATH);
    if (IS_ERR(alt)) {
        fs_warn("getname_kernel error: %ld\n", PTR_ERR(alt));
        return;
    }

    save_alt(current->pid, alt);
    args->arg1 = (uint64_t)(unsigned long)alt;
    fs_info("redirigido framework.jar para '%s' (pid %d)\n", current->comm, current->pid);
}

static void after_do_filp_open(hook_fargs3_t *args, void *udata)
{
    struct filename *alt = take_alt(current->pid);
    if (alt && putname_ptr)
        putname_ptr(alt);
}

static long kpm_init(const char *args, const char *event, void *reserved)
{
    resolve_fs_symbols();

    unsigned long sym = kallsyms_lookup_name("do_filp_open");
    if (!sym) {
        fs_err("do_filp_open no encontrado\n");
        return -1;
    }

    hook_err_t err = hook_wrap((void *)sym, 3,
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
    unsigned long sym = kallsyms_lookup_name("do_filp_open");
    if (sym)
        unhook_func((void *)sym);
    fs_info("descargado\n");
    return 0;
}

KPM_INIT(kpm_init);
KPM_EXIT(kpm_exit);
