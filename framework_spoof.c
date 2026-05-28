// SPDX-License-Identifier: GPL-3.0-only
// framework-spoof v1.0 - Redirige framework.jar para Native Detector
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/kallsyms.h>
#include <linux/version.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("SrMatdroid");
MODULE_DESCRIPTION("Redirige framework.jar al backup para bypasear Native Detector");

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

static struct filename *(*getname_kernel_ptr)(const char *);
static void (*putname_ptr)(struct filename *);

static void resolve_fs_symbols(void)
{
    getname_kernel_ptr = (void *)kallsyms_lookup_name("getname_kernel");
    putname_ptr = (void *)kallsyms_lookup_name("putname");
}

// Definimos el tipo del hook manualmente (no depende de hook.h)
typedef struct {
    uint64_t arg0, arg1, arg2, arg3, arg4, arg5;
} hook_fargs3_t;

static unsigned long do_filp_open_addr;
static void *original_code;

// Función antes del open
static void before_do_filp_open(hook_fargs3_t *args)
{
    struct filename *pn = (struct filename *)(unsigned long)args->arg1;
    if (!pn || !pn->name) return;
    if (!strstr(pn->name, "framework.jar")) return;
    if (!strstr(current->comm, "nativecheck") && !strstr(current->comm, "reveny")) return;

    if (!getname_kernel_ptr) {
        resolve_fs_symbols();
        if (!getname_kernel_ptr) return;
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

// Función después del open
static void after_do_filp_open(hook_fargs3_t *args)
{
    struct filename *alt = take_alt(current->pid);
    if (alt && putname_ptr) putname_ptr(alt);
}

// Hook mediante escritura de instrucción de salto (simple)
#include <linux/uaccess.h>
#include <asm/insn.h>

static void install_hook(void)
{
    // Guardar los primeros bytes originales y escribir una instrucción de salto
    // (Implementación muy simplificada; para producción usar kprobes o ftrace)
    // Por simplicidad, usamos kprobes que es más seguro.
}

// En su lugar, usamos kprobes para evitar escribir memoria directamente
#include <linux/kprobes.h>

static struct kprobe kp = {
    .symbol_name = "do_filp_open",
    .pre_handler = (kprobe_pre_handler_t)before_do_filp_open,
    .post_handler = (kprobe_post_handler_t)after_do_filp_open,
};

static int __init fs_init(void)
{
    int ret;
    resolve_fs_symbols();

    ret = register_kprobe(&kp);
    if (ret < 0) {
        fs_err("register_kprobe falló: %d\n", ret);
        return ret;
    }
    fs_info("cargado — backup: %s\n", BACKUP_PATH);
    return 0;
}

static void __exit fs_exit(void)
{
    unregister_kprobe(&kp);
    fs_info("descargado\n");
}

module_init(fs_init);
module_exit(fs_exit);
