// SPDX-License-Identifier: GPL-3.0-only
// KPM: framework-spoof
// Redirige /system/framework/framework.jar al backup original
// cuando el proceso es Native Detector (com.reveny.nativecheck)
// Autor: SrMatdroid

#include <compiler.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/string.h>

KPM_NAME("framework-spoof");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v3");
KPM_AUTHOR("SrMatdroid");
KPM_DESCRIPTION("Redirige framework.jar al original para bypasear Native Detector");

// Ruta del backup extraído antes de instalar el mod de Koarios
#define BACKUP_PATH "/data/adb/kpm_data/framework_orig.jar"

// Firma de do_filp_open (kernel 5.10)
static struct file *(*orig_do_filp_open)(int dfd, struct filename *pathname,
                                          const struct open_flags *op) = NULL;

// Comprueba si el proceso actual es Native Detector
static bool is_target_process(void)
{
    char comm[TASK_COMM_LEN] = { 0 };
    get_task_comm(comm, current);
    // comm es "nativecheck" (truncado a 15 chars desde com.reveny.nativecheck)
    return (strstr(comm, "nativecheck") != NULL ||
            strstr(comm, "reveny") != NULL);
}

static struct file *hook_do_filp_open(int dfd, struct filename *pathname,
                                       const struct open_flags *op)
{
    if (!pathname || !pathname->name)
        goto original;

    // Filtra rápido antes de comprobar el proceso (optimización)
    if (!strstr(pathname->name, "framework.jar"))
        goto original;

    if (!is_target_process())
        goto original;

    {
        struct filename *alt = getname_kernel(BACKUP_PATH);
        if (IS_ERR(alt)) {
            pr_warn("[framework-spoof] getname_kernel falló: %ld\n", PTR_ERR(alt));
            goto original;
        }

        struct file *f = orig_do_filp_open(AT_FDCWD, alt, op);
        putname(alt);

        if (IS_ERR(f)) {
            pr_warn("[framework-spoof] backup no accesible, usando original modificado\n");
            goto original;
        }

        pr_info("[framework-spoof] pid %d (%s): redirigido framework.jar → backup\n",
                current->pid, current->comm);
        return f;
    }

original:
    return orig_do_filp_open(dfd, pathname, op);
}

static long kpm_init(const char *args, const char *event, void *reserved)
{
    void *target = (void *)kallsyms_lookup_name("do_filp_open");
    if (!target) {
        pr_err("[framework-spoof] do_filp_open no encontrado en kallsyms\n");
        return -ENOENT;
    }

    hook_err_t err = hook_wrap(target,
                               (void *)hook_do_filp_open,
                               (void **)&orig_do_filp_open);
    if (err != HOOK_NO_ERR) {
        pr_err("[framework-spoof] hook_wrap error: %d\n", err);
        return -EFAULT;
    }

    pr_info("[framework-spoof] cargado — backup: %s\n", BACKUP_PATH);
    return 0;
}

static long kpm_exit(void *reserved)
{
    if (orig_do_filp_open) {
        unhook_func((void *)kallsyms_lookup_name("do_filp_open"));
        pr_info("[framework-spoof] descargado\n");
    }
    return 0;
}

KPM_INIT(kpm_init);
KPM_EXIT(kpm_exit);

