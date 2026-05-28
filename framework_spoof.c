// SPDX-License-Identifier: GPL-3.0-only
// KPM: framework-spoof v1.0.0
// Redirige framework.jar al backup original cuando lo abre Native Detector
// Autor: SrMatdroid

#include <compiler.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>

KPM_NAME("framework-spoof");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v3");
KPM_AUTHOR("SrMatdroid");
KPM_DESCRIPTION("Redirige framework.jar al backup para bypasear Native Detector");

// ── Declaraciones mínimas del kernel ────────────────────────────────────────

#define TASK_COMM_LEN   16
#define AT_FDCWD        (-100)

// IS_ERR / PTR_ERR sin linux/err.h
#define MAX_ERRNO       4095
#define IS_ERR(ptr)     ((unsigned long)(ptr) >= (unsigned long)(-MAX_ERRNO))
#define PTR_ERR(ptr)    ((long)(ptr))

struct open_flags;   // opaco, solo lo pasamos

struct filename {
    const char      *name;
    // resto de campos no nos importan
};

// Funciones del kernel que usamos (resueltas en runtime por KP)
extern char *strstr(const char *haystack, const char *needle);
extern int   strncpy_from_user(char *dst, const char __user *src, long count);
extern void  get_task_comm(char *buf, struct task_struct *tsk);
extern struct task_struct *current_task;
#define current ((struct task_struct *)current_task)

extern struct filename *getname_kernel(const char *filename);
extern void             putname(struct filename *name);

// ── Config ──────────────────────────────────────────────────────────────────

#define BACKUP_PATH "/data/adb/kpm_data/framework_orig.jar"

// ── Hook ────────────────────────────────────────────────────────────────────

static struct file *(*orig_do_filp_open)(int dfd,
                                          struct filename *pathname,
                                          const struct open_flags *op) = NULL;

static struct file *hook_do_filp_open(int dfd,
                                       struct filename *pathname,
                                       const struct open_flags *op)
{
    if (!pathname || !pathname->name)
        goto original;

    if (!strstr(pathname->name, "framework.jar"))
        goto original;

    {
        char comm[TASK_COMM_LEN] = { 0 };
        get_task_comm(comm, current);

        if (!strstr(comm, "nativecheck") && !strstr(comm, "reveny"))
            goto original;

        struct filename *alt = getname_kernel(BACKUP_PATH);
        if (IS_ERR(alt)) {
            pr_warn("[framework-spoof] getname_kernel error: %ld\n", PTR_ERR(alt));
            goto original;
        }

        struct file *f = orig_do_filp_open(AT_FDCWD, alt, op);
        putname(alt);

        if (IS_ERR(f)) {
            pr_warn("[framework-spoof] backup inaccesible, usando jar modificado\n");
            goto original;
        }

        pr_info("[framework-spoof] redirigido framework.jar para '%s'\n", comm);
        return f;
    }

original:
    return orig_do_filp_open(dfd, pathname, op);
}

// ── Init / Exit ─────────────────────────────────────────────────────────────

static long kpm_init(const char *args, const char *event, void *reserved)
{
    void *sym = (void *)kallsyms_lookup_name("do_filp_open");
    if (!sym) {
        pr_err("[framework-spoof] do_filp_open no encontrado en kallsyms\n");
        return -1;
    }

    hook_err_t err = hook_wrap(sym,
                               (void *)hook_do_filp_open,
                               (void **)&orig_do_filp_open);
    if (err != HOOK_NO_ERR) {
        pr_err("[framework-spoof] hook_wrap falló: %d\n", err);
        return -1;
    }

    pr_info("[framework-spoof] cargado — backup: %s\n", BACKUP_PATH);
    return 0;
}

static long kpm_exit(void *reserved)
{
    if (orig_do_filp_open) {
        void *sym = (void *)kallsyms_lookup_name("do_filp_open");
        if (sym) unhook_func(sym);
    }
    pr_info("[framework-spoof] descargado\n");
    return 0;
}

KPM_INIT(kpm_init);
KPM_EXIT(kpm_exit);
