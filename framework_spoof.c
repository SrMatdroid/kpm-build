// SPDX-License-Identifier: GPL-3.0-only
// KPM: framework-spoof v1.1.0
// Redirige framework.jar al backup cuando lo abre Native Detector
// Autor: SrMatdroid

#include <compiler.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>

KPM_NAME("framework-spoof");
KPM_VERSION("1.1.0");
KPM_LICENSE("GPL v3");
KPM_AUTHOR("SrMatdroid");
KPM_DESCRIPTION("Redirige framework.jar al backup para bypasear Native Detector");

// printk declarado en log.h (incluido vía hook.h) como puntero a función
// pr_info/pr_err/pr_warn pueden estar o no en log.h — los definimos con prefijo propio
#define fs_info(fmt, ...) printk("[fs] " fmt,    ##__VA_ARGS__)
#define fs_err(fmt, ...)  printk("[fs][E] " fmt, ##__VA_ARGS__)
#define fs_warn(fmt, ...) printk("[fs][W] " fmt, ##__VA_ARGS__)

// unhook_func no está declarado en hook.h de este fork
extern hook_err_t unhook_func(void *func);

// ── Tipos mínimos ─────────────────────────────────────────────────────────────
#define TASK_COMM_LEN  16
#define AT_FDCWD       (-100)
#define MAX_ERRNO      4095UL
#define IS_ERR(p)      ((unsigned long)(p) > (unsigned long)(-(long)MAX_ERRNO))
#define PTR_ERR(p)     ((long)(p))

// forward-declare primero para evitar "declared inside parameter list"
struct task_struct;
struct open_flags;

struct filename {
    const char *name;
    /* resto del struct omitido — solo usamos name */
};

// ── Símbolos del kernel ───────────────────────────────────────────────────────
extern unsigned long    kallsyms_lookup_name(const char *name);
extern char            *strstr(const char *h, const char *n);
extern struct filename *getname_kernel(const char *filename);
extern void             putname(struct filename *name);
extern struct task_struct *get_current(void);
#define current get_current()

// get_task_comm: resolvemos en runtime para evitar problemas de linkage
static void (*kp_get_task_comm)(char *buf, struct task_struct *tsk) = NULL;

// ── Config ────────────────────────────────────────────────────────────────────
#define BACKUP_PATH "/data/adb/kpm_data/framework_orig.jar"

// ── Slot para pasar alt-filename de before a after hook ──────────────────────
#define SLOTS 8
static struct {
    unsigned long task;
    struct filename *alt;
} g_slots[SLOTS];

static volatile int g_lock = 0;

static void slock(void)   { while (__sync_lock_test_and_set(&g_lock, 1)); }
static void sunlock(void) { __sync_lock_release(&g_lock); }

static void save_alt(unsigned long task, struct filename *alt)
{
    slock();
    for (int i = 0; i < SLOTS; i++) {
        if (!g_slots[i].task) {
            g_slots[i].task = task;
            g_slots[i].alt  = alt;
            break;
        }
    }
    sunlock();
}

static struct filename *take_alt(unsigned long task)
{
    struct filename *a = NULL;
    slock();
    for (int i = 0; i < SLOTS; i++) {
        if (g_slots[i].task == task) {
            a = g_slots[i].alt;
            g_slots[i].task = 0;
            g_slots[i].alt  = NULL;
            break;
        }
    }
    sunlock();
    return a;
}

// ── Hooks ─────────────────────────────────────────────────────────────────────
// do_filp_open(int dfd, struct filename *pathname, const struct open_flags *op)
// → 3 argumentos → hook_fargs3_t

static void before_do_filp_open(hook_fargs3_t *args, void *udata)
{
    struct filename *pn = (struct filename *)(unsigned long)args->arg1;
    if (!pn || !pn->name)                         return;
    if (!strstr(pn->name, "framework.jar"))        return;

    char comm[TASK_COMM_LEN] = {0};
    if (kp_get_task_comm)
        kp_get_task_comm(comm, current);

    if (!strstr(comm, "nativecheck") && !strstr(comm, "reveny"))
        return;

    struct filename *alt = getname_kernel(BACKUP_PATH);
    if (IS_ERR(alt)) {
        fs_warn("getname_kernel error: %ld\n", PTR_ERR(alt));
        return;
    }

    save_alt((unsigned long)current, alt);
    args->arg1 = (uint64_t)(unsigned long)alt;
    fs_info("redirigido framework.jar para '%s'\n", comm);
}

static void after_do_filp_open(hook_fargs3_t *args, void *udata)
{
    struct filename *alt = take_alt((unsigned long)current);
    if (alt) putname(alt);
}

// ── Init / Exit ───────────────────────────────────────────────────────────────
static long kpm_init(const char *args, const char *event, void *reserved)
{
    // Resolver get_task_comm en runtime (es inline en sched.h, puede no estar en kallsyms)
    unsigned long sym_comm = kallsyms_lookup_name("get_task_comm");
    if (sym_comm)
        kp_get_task_comm = (void *)sym_comm;
    else
        fs_warn("get_task_comm no en kallsyms — comm check deshabilitado\n");

    unsigned long sym = kallsyms_lookup_name("do_filp_open");
    if (!sym) {
        fs_err("do_filp_open no encontrado en kallsyms\n");
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
    if (sym) unhook_func((void *)sym);
    fs_info("descargado\n");
    return 0;
}

KPM_INIT(kpm_init);
KPM_EXIT(kpm_exit);
