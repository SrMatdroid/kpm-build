// selinux_context_hide.c
// KPM: intercept SELinux context validation for root-related types
// License: GPL-3.0

#include <compiler.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/err.h>
#include <linux/string.h>
#include <linux/cred.h>
#include <asm/current.h>
#include <uapi/asm-generic/errno.h>

KPM_NAME("selinux-context-hide");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v3");
KPM_DESCRIPTION("Hide KSU/Magisk SELinux contexts from untrusted apps");
KPM_AUTHOR("SrMatdroid");

// Tipos a ocultar - exactamente como aparecen en la policy
static const char *hidden_types[] = {
    "u:r:ksu:s0",
    "u:r:ksu_file:s0",
    "u:r:magisk:s0",
    "u:r:magisk_file:s0",
    "u:r:magisk_daemon:s0",
    NULL
};

// Firma: int selinux_setprocattr(const char *name, void *value, size_t size)
// En kernel 5.10 el hook es sobre security_setprocattr
static int (*orig_security_setprocattr)(const char *lsm, const char *name,
                                         void *value, size_t size) = NULL;

static int hook_security_setprocattr(const char *lsm, const char *name,
                                      void *value, size_t size)
{
    // Solo interceptar escrituras a "current"
    if (!name || strcmp(name, "current") != 0)
        goto original;

    if (!value || size == 0)
        goto original;

    // Comprobar si el caller es una app no privilegiada (uid >= 10000)
    uid_t uid = current_uid().val;
    if (uid < 10000)
        goto original;

    // Buscar si el contexto que se intenta escribir contiene tipos root
    const char *ctx = (const char *)value;

    for (int i = 0; hidden_types[i] != NULL; i++) {
        // Comparación parcial: el contexto puede tener categorías adicionales
        // ej: "u:r:ksu:s0:c512,c768" también debe ser interceptado
        const char *type = hidden_types[i];
        size_t type_len = strlen(type);

        if (size >= type_len && strncmp(ctx, type, type_len) == 0) {
            // Devolver EINVAL: "este tipo no existe en la policy"
            return -EINVAL;
        }
    }

original:
    return orig_security_setprocattr(lsm, name, value, size);
}

static long selinux_hide_init(const char *args, const char *event,
                               void *__user reserved)
{
    int ret = 0;

    // Resolver símbolo - en GKI 5.10 está exportado
    void *sym = kallsyms_lookup_name("security_setprocattr");
    if (!sym) {
        pr_err("[selinux-hide] No se encontró security_setprocattr\n");
        return -ENOENT;
    }

    ret = hook_func(sym, (void *)hook_security_setprocattr,
                    (void **)&orig_security_setprocattr);
    if (ret) {
        pr_err("[selinux-hide] hook_func falló: %d\n", ret);
        return ret;
    }

    pr_info("[selinux-hide] Hook instalado en security_setprocattr @ %px\n", sym);
    return 0;
}

static long selinux_hide_exit(void *__user reserved)
{
    if (orig_security_setprocattr) {
        unhook_func((void *)hook_security_setprocattr);
        pr_info("[selinux-hide] Hook eliminado\n");
    }
    return 0;
}

KPM_INIT(selinux_hide_init);
KPM_EXIT(selinux_hide_exit);