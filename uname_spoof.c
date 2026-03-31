#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <common.h>
#include <kputils.h>
#include <linux/string.h>

KPM_NAME("uname_spoof");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("srmat");
KPM_DESCRIPTION("spoof uname build date");

static long uname_spoof_init(const char *args, const char *event, void *__user reserved)
{
    pr_info("uname_spoof: loaded\n");
    return 0;
}

static long uname_spoof_control0(const char *args, char *__user out_msg, int outlen)
{
    return 0;
}

static long uname_spoof_exit(void *__user reserved)
{
    return 0;
}

KPM_INIT(uname_spoof_init);
KPM_CTL0(uname_spoof_control0);
KPM_EXIT(uname_spoof_exit);
