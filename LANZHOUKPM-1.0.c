#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <kallsyms.h>
#include <common.h>
#include <log.h>
#include <kputils.h>
#include <linux/sched.h>
#include <linux/cred.h>



//为了安全性 此源码未包含部分非核心内容 token 密钥等








void *memcpy(void *dst, const void *src, unsigned long n) {
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    for (unsigned long i = 0; i < n; i++) d[i] = s[i];
    return dst;
}
void *memset(void *dst, int c, unsigned long n) {
    unsigned char *d = (unsigned char *)dst;
    for (unsigned long i = 0; i < n; i++) d[i] = (unsigned char)c;
    return dst;
}

KPM_NAME("LanZhouKPM");

KPM_VERSION("v2026");

KPM_LICENSE("gpl 2.0");

KPM_AUTHOR("Lanzhou");

KPM_DESCRIPTION("telegram:@LANZHOUKPM");

static unsigned long g_hk[20];

static int           g_hk_argc[20];

static unsigned char g_hk_err[20];


static unsigned int  g_on;
static unsigned long long g_unlock_at;
static unsigned long long g_last_bad;
static unsigned int  g_unloading;
static unsigned long g_blocked;
static unsigned int  g_module_protect;
static unsigned long g_module_blocked;
static unsigned int  g_adb_alert;
static char          g_adb_alert_comm[16];
static unsigned long long g_on_at;
static unsigned long long g_kt_ptr;
static unsigned int  g_narrow;
static unsigned char g_hk_armed[20];
#define BD_OBS_SLOTS 16
static struct { char comm[16]; unsigned long long last; } g_obs[BD_OBS_SLOTS];
typedef char *(*gtc_t)(char *, unsigned long, void *);
typedef unsigned long (*cfu_t)(void *, const void *, unsigned long);
static gtc_t kf_gtc;
static cfu_t kf_cfu;
typedef struct file *(*gtexe_t)(struct task_struct *);
typedef void (*fput_t)(struct file *);
typedef char *(*fpath_t)(struct file *, char *, int);
static gtexe_t kf_getexe;
static fput_t  kf_fput;
static fpath_t kf_fpath;
static void *get_cur(void){void *t;__asm__("mrs %0,sp_el0":"=r"(t));return t;}
static inline void bd_mb(void){ __asm__ __volatile__("dmb ish" ::: "memory"); }
static inline void bd_store_release(unsigned int *p, unsigned int v){ bd_mb(); *(volatile unsigned int *)p = v; }
static inline unsigned int bd_load_acquire(unsigned int *p){ unsigned int v = *(volatile unsigned int *)p; bd_mb(); return v; }
static inline long long bd_now(void){
    if (!g_kt_ptr) return 0;
    return ((long long (*)(void))g_kt_ptr)();
}
static inline int bd_on(void){ return bd_load_acquire(&g_on) != 0; }
#define BD_DRAIN_NS (5ULL * 1000000000ULL)
static inline int bd_active(void){
    if (!bd_on()) return 0;
    if (g_kt_ptr && g_on_at && (long long)(bd_now() - g_on_at) < (long long)BD_DRAIN_NS) return 0;
    return 1;
}
#define BD_UNLOCK_TTL_NS (10ULL * 1000000000ULL)
static inline int bd_unlocked(void){
    long long d;
    if (!g_kt_ptr || !g_unlock_at) return 0;
    d = (long long)(bd_now() - g_unlock_at);
    return d >= 0 && d < (long long)BD_UNLOCK_TTL_NS;
}
static inline int bd_iserr(const void *p){ return (unsigned long)p >= (unsigned long)-4095UL; }
static inline int bd_is_kthread(void *t){
    if (!t || task_struct_offset.mm_offset < 0) return 0;
    return *(void **)((unsigned char *)t + task_struct_offset.mm_offset) == 0;
}
static inline unsigned int bd_task_uid(void *t){
    void *cred;
    if (!t || task_struct_offset.real_cred_offset < 0) return ~0u;
    cred = *(void **)((unsigned char *)t + task_struct_offset.real_cred_offset);
    if (!cred || cred_offset.uid_offset < 0) return ~0u;
    return *(unsigned int *)((unsigned char *)cred + cred_offset.uid_offset);
}
typedef struct {
    const char *comm;
    const char *exe_base;
    const unsigned int uids[4];
} wl_t;
static const wl_t wl_table[] = {
    {"init","init",{0}},
    {"ueventd","init",{0}},
    {"vold","vold",{0}},
    {"rmt_storage","rmt_storage",{0,1001,9999}},
    {"qcrilNrd","qcrilNrd",{1001}},
    {"qcrild","qcrild",{1001}},
    {"rild","rild",{1001}},
    {"qmipriod","qmipriod",{1001}},
    {"ipacm-diag","ipacm-diag",{1001}},
    {"ssgqmigd","ssgqmigd",{1001}},
    {"dpmQmiMgr","dpmQmiMgr",{1000}},
    {"diag-router","diag-router",{1000}},
    {"diagcommd","diagcommd",{1000}},
    {"netd","netd",{0}},
    {"qseecomd","qseecomd",{1000}},
    {"vendor.qti.hardware.qseecom@1.0-service","vendor.qti.hardware.qseecom@1.0-service",{1000}},
    {"efsd","efsd",{0,1000,1001}},
    {"qcks","qcks",{0,1000,1001}},
    {"efsks","efsks",{0,1000,1001}},
    {"ks","ks",{0,1000,1001}},
    {"tloc_daemon","tloc_daemon",{0,1000,1001}},
    {"slim_daemon","slim_daemon",{0,1000,1001}},
    {"msm_irqbalance","msm_irqbalance",{0,1000}},
    {"ssr_setup","ssr_setup",{0,1000,1001}},
    {"ssr_diag","ssr_diag",{0,1000,1001}},
    {"thermal-engine","thermal-engine",{0}},
    {"mi_thermald","mi_thermald",{0}},
    {"android.hardware.thermal@2.0-service.qti","android.hardware.thermal@2.0-service.qti",{0}},
    {"MI_RIC","MI_RIC",{0}},
};
#define WLCNT (int)(sizeof(wl_table)/sizeof(wl_table[0]))
static int bd_path_ok(const char *p){
    if (p[0]=='/'&&p[1]=='s'&&p[2]=='y'&&p[3]=='s'&&p[4]=='t'&&p[5]=='e'&&p[6]=='m'&&p[7]=='/') return 1;
    if (p[0]=='/'&&p[1]=='v'&&p[2]=='e'&&p[3]=='n'&&p[4]=='d'&&p[5]=='o'&&p[6]=='r'&&p[7]=='/') return 1;
    if (p[0]=='/'&&p[1]=='a'&&p[2]=='p'&&p[3]=='e'&&p[4]=='x'&&p[5]=='/') return 1;
    if (p[0]=='/'&&p[1]=='s'&&p[2]=='y'&&p[3]=='s'&&p[4]=='t'&&p[5]=='e'&&p[6]=='m'&&p[7]=='_'&&p[8]=='e'&&p[9]=='x'&&p[10]=='t'&&p[11]=='/') return 1;
    if (p[0]=='/'&&p[1]=='p'&&p[2]=='r'&&p[3]=='o'&&p[4]=='d'&&p[5]=='u'&&p[6]=='c'&&p[7]=='t'&&p[8]=='/') return 1;
    if (p[0]=='/'&&p[1]=='o'&&p[2]=='d'&&p[3]=='m'&&p[4]=='/') return 1;
    if (p[0]=='/'&&p[1]=='i'&&p[2]=='n'&&p[3]=='i'&&p[4]=='t'&&(p[5]==0||p[5]==' '||p[5]=='(')) return 1;
    return 0;
}
static int bd_uid_ok(const unsigned int *u, unsigned int uid){
    int i;
    for (i = 0; i < 4; i++) {
        if (u[i] == uid) return 1;
    }
    return 0;
}
static int bd_str_eq(const char *a, const char *b){
    while (*a && *b && *a == *b) { a++; b++; }
    return *b == 0 && (*a == 0 || *a == ' ');
}
static int bd_exe_name(char *out, int out_sz){
    struct task_struct *t = (struct task_struct *)get_cur();
    struct file *f;
    char buf[256]; char *p;
    int i, j, start;
    if (!kf_getexe || !kf_fput || !kf_fpath || !t || bd_is_kthread(t)) return 0;
    f = kf_getexe(t);
    if (!f) return 0;
    memset(buf, 0, sizeof(buf));
    p = kf_fpath(f, buf, sizeof(buf));
    kf_fput(f);
    if (!p || bd_iserr(p)) return 0;
    if (!bd_path_ok(p)) return 0;
    start = 0;
    for (i = 0; p[i]; i++) if (p[i] == '/') start = i + 1;
    j = 0;
    while (p[start + j] && j < out_sz - 1) { out[j] = p[start + j]; j++; }
    out[j] = 0;
    return j > 0;
}
static int is_sys(void)
{
    void *t = get_cur();
    char comm[16], exe[64];
    unsigned int uid, uid_known;
    int i, j;
    if (bd_is_kthread(t)) return 1;
    uid = bd_task_uid(t);
    uid_known = (uid != ~0u);
    if (bd_exe_name(exe, sizeof(exe))) {
        for (i = 0; i < WLCNT; i++) {
            const wl_t *w = &wl_table[i];
            if ((!uid_known || bd_uid_ok(w->uids, uid)) && bd_str_eq(exe, w->exe_base)) return 1;
        }
    }
    if (!kf_gtc) return 0;
    kf_gtc(comm, 16, t);
    for (i = 0; i < WLCNT; i++) {
        const wl_t *w = &wl_table[i];
        j = 0;
        while (w->comm[j] && comm[j] && w->comm[j] == comm[j]) j++;
        if (w->comm[j] != 0) continue;
        if (uid_known && !bd_uid_ok(w->uids, uid)) continue;
        if (kf_getexe && (!bd_exe_name(exe, sizeof(exe)) || !bd_str_eq(exe, w->exe_base))) continue;
        return 1;
    }
    return 0;
}
static void bd_observe(const char *layer){
    void *t = get_cur();
    char c[16];
    unsigned long long now, last;
    unsigned long h;
    int i, s, same;
    if (bd_task_uid(t) != 0) return;
    if (kf_gtc) kf_gtc(c, 16, t);
    else { c[0] = '?'; c[1] = 0; }
    now = bd_now();
    h = 2166136261UL;
    for (i = 0; c[i]; i++) { h ^= (unsigned char)c[i]; h *= 16777619UL; }
    s = (int)(h & (BD_OBS_SLOTS - 1));
    last = *(volatile unsigned long long *)&g_obs[s].last;
    same = 1;
    for (i = 0; i < 16; i++) { if (c[i] != g_obs[s].comm[i]) { same = 0; break; } }
    if (same && g_kt_ptr && (long long)(now - last) < 2000000000LL) return;
    for (i = 0; i < 16; i++) g_obs[s].comm[i] = c[i];
    *(volatile unsigned long long *)&g_obs[s].last = now;
    logke("[bd] observed: %s layer=%s\n", c, layer);
}
typedef struct {
    const unsigned char pfx[28];
    unsigned char plen;
    unsigned char exact;
    unsigned char mod_only;
    unsigned char chk_flags;
    unsigned char set_comm;
    const char *layer;
} prule_t;
#define BD_CREATE_FLAGS (0x40u | 0x400000u)
static const prule_t openat_rules[] = {
    {{0x2f,0x64,0x65,0x76,0x2f,0x75,0x66,0x73,0x2d,0x62,0x73,0x67},12,0,0,0,0,"ufs-bsg"},
    {{0x2f,0x64,0x65,0x76,0x2f,0x62,0x73,0x67},8,0,0,0,0,"bsg"},
    {{0x2f,0x64,0x65,0x76,0x2f,0x73,0x67},7,0,0,0,0,"sg"},
    {{0x2f,0x70,0x72,0x6f,0x63,0x2f,0x73,0x79,0x73,0x72,0x71,0x2d},12,0,0,0,0,"sysrq"},
    {{0x2f,0x63,0x6f,0x6e,0x66,0x69,0x67,0x2f,0x75,0x73,0x62},11,0,0,0,0,"usb-gadget"},
    {{0x2f,0x73,0x79,0x73,0x2f,0x63,0x6c,0x61,0x73,0x73,0x2f,0x61,0x6e,0x64,0x72,0x6f,0x69,0x64,0x5f,0x75,0x73,0x62},22,0,0,0,0,"android-usb"},
    {{0x2f,0x64,0x65,0x76,0x2f,0x73,0x6f,0x63,0x6b,0x65,0x74,0x2f,0x70,0x72,0x6f,0x70},16,0,0,0,0,"prop-socket"},
    {{0x2f,0x64,0x61,0x74,0x61,0x2f,0x61,0x64,0x62,0x2f,0x6b,0x70,0x61,0x74,0x63,0x68},16,0,0,0,0,"kpatch-write"},
    {{0x2f,0x64,0x61,0x74,0x61,0x2f,0x61,0x64,0x62,0x2f,0x73,0x65,0x72,0x76,0x69,0x63,0x65,0x2e,0x64,0x2f},20,0,1,1,1,"mod-serviced"},
    {{0x2f,0x64,0x61,0x74,0x61,0x2f,0x61,0x64,0x62,0x2f,0x70,0x6f,0x73,0x74,0x2d,0x66,0x73,0x2d,0x64,0x61,0x74,0x61,0x2e,0x64,0x2f},25,0,1,1,1,"mod-postfs"},
    {{0x2f,0x64,0x61,0x74,0x61,0x2f,0x61,0x64,0x62,0x2f,0x6d,0x6f,0x64,0x75,0x6c,0x65,0x73,0x2f},18,0,1,1,1,"mod-modules"},
    {{0x2f,0x64,0x61,0x74,0x61,0x2f,0x61,0x64,0x62,0x2f,0x6d,0x6f,0x64,0x75,0x6c,0x65,0x73,0x5f,0x75,0x70,0x64,0x61,0x74,0x65,0x2f},25,0,1,1,1,"mod-modules"},
    {{0x2f,0x64,0x65,0x76,0x2f,0x62,0x6c,0x6f,0x63,0x6b},10,0,0,0,0,"block-open"},
};
static const prule_t magisk_rules[] = {
    {{0x2f,0x64,0x61,0x74,0x61,0x2f,0x61,0x64,0x62,0x2f,0x6d,0x6f,0x64,0x75,0x6c,0x65,0x73,0x2f},18,0,1,0,1,"mod-mkdir"},
    {{0x2f,0x64,0x61,0x74,0x61,0x2f,0x61,0x64,0x62,0x2f,0x6d,0x6f,0x64,0x75,0x6c,0x65,0x73,0x5f,0x75,0x70,0x64,0x61,0x74,0x65,0x2f},25,0,1,0,1,"mod-mkdir"},
    {{0x2f,0x64,0x61,0x74,0x61,0x2f,0x61,0x64,0x62,0x2f,0x73,0x65,0x72,0x76,0x69,0x63,0x65,0x2e,0x64,0x2f},20,0,1,0,1,"mod-serviced-mkdir"},
    {{0x2f,0x64,0x61,0x74,0x61,0x2f,0x61,0x64,0x62,0x2f,0x70,0x6f,0x73,0x74,0x2d,0x66,0x73,0x2d,0x64,0x61,0x74,0x61,0x2e,0x64,0x2f},25,0,1,0,1,"mod-postfs-mkdir"},
    {{0x2f,0x64,0x61,0x74,0x61,0x2f,0x61,0x64,0x62,0x2f,0x6b,0x70,0x61,0x74,0x63,0x68},16,0,1,0,0,"magisk-kpatch-mkdir"},
};
#define NRULES(a) (int)(sizeof(a)/sizeof((a)[0]))
static const prule_t *pmatch(const char *k, const prule_t *rules, int n, unsigned long flags) {
    int i, j;
    for (i = 0; i < n; i++) {
        const prule_t *r = &rules[i];
        for (j = 0; j < r->plen; j++)
            if ((unsigned char)k[j] != r->pfx[j]) break;
        if (j < r->plen) continue;
        if (r->exact && k[r->plen] != 0) continue;
        if (r->mod_only && !g_module_protect) continue;
        if (r->chk_flags && !(flags & BD_CREATE_FLAGS)) continue;
        return r;
    }
    return 0;
}
static void bd_zero_after_nul(char *k)
{
    int z = 0;
    while (z < 31 && k[z]) z++;
    for (; z < 32; z++) k[z] = 0;
}
static void blkopen_cb(hook_fargs3_t *f, void *u)
{
    (void)u;
    if (!bd_active()) return;
    if (is_sys()) return;
    f->skip_origin = 1;
    f->ret = (uint64_t)(-1);
    g_blocked++;
    bd_observe("blkdev-open");
}
static void blkwatch_cb(hook_fargs3_t *f, void *u)
{
    (void)u; (void)f;
    if (!bd_active()) return;
    if (is_sys()) return;
    bd_observe("blkdev-write");
}
static void blkioctl_cb(hook_fargs3_t *f, void *u)
{
    (void)u; (void)f;
    if (!bd_active()) return;
    if (is_sys()) return;
    bd_observe("blkdev-ioctl");
}
static void ufs_cb(hook_fargs3_t *f, void *u)
{
    struct pt_regs { unsigned long r[31]; unsigned long sp, pc, ps; } *regs;
    const char *up; char k[32];
    const prule_t *r;
    (void)u;
    if (!bd_active()) return;
    if (is_sys()) return;
    if (!kf_cfu) return;
    regs = (void *)(unsigned long)f->arg0;
    if (!regs) return;
    up = (const char *)regs->r[1];
    if (!up) return;
    memset(k, 0, sizeof(k));
    if (kf_cfu(k, up, 31)) return;
    bd_zero_after_nul(k);
    r = pmatch(k, openat_rules, NRULES(openat_rules), regs->r[2]);
    if (!r) return;
    f->skip_origin = 1;
    f->ret = (uint64_t)(-1);
    if (r->mod_only) {
        g_module_blocked++; g_adb_alert = 1;
        { void *t = get_cur(); char c2[16];
          if (kf_gtc) { kf_gtc(c2, 16, t); if (r->set_comm) kf_gtc(g_adb_alert_comm, 16, t); logke("[bd] BLOCKED: %s layer=%s\n", c2, r->layer); }
          else { logke("[bd] BLOCKED: ? layer=%s\n", r->layer); } }
    } else {
        g_blocked++;
        { void *t = get_cur(); char c2[16];
          if (kf_gtc) { kf_gtc(c2, 16, t); logke("[bd] BLOCKED: %s layer=%s\n", c2, r->layer); }
          else { logke("[bd] BLOCKED: ? layer=%s\n", r->layer); } }
    }
}
static void kmod_cb(hook_fargs3_t *f, void *u)
{

    void *t; char comm[16];
    (void)u;
    if (!bd_active()) return;
    if (is_sys()) return;
    f->skip_origin = 1;
    f->ret = (uint64_t)(-1);
    g_blocked++;
    t = get_cur();
    if (kf_gtc) { kf_gtc(comm, 16, t); logke("[bd] BLOCKED: %s layer=kmod\n", comm); }
    else { logke("[bd] BLOCKED: ? layer=kmod\n"); }
}
static void kill_cb(hook_fargs1_t *f, void *u)
{
    struct pt_regs {
        unsigned long r[31]; unsigned long sp, pc, ps;
    } *regs;
    int pid, sig;
    (void)u;
    if (!bd_active()) return;
    regs = (void *)(unsigned long)f->arg0;
    if (!regs) return;
    pid = (int)regs->r[0];
    sig = (int)regs->r[1];
    if (pid != 1 && pid != -1) return;
    if (sig != 9 && sig != 15 && sig != 19) return;
    if (is_sys()) return;
    f->skip_origin = 1;
    f->ret = (uint64_t)(-1);
    g_blocked++;
    logke("[bd] BLOCKED: kill/tkill(%d,%d)\n", pid, sig);
}
static void tgkill_cb(hook_fargs1_t *f, void *u)
{
    struct pt_regs {
        unsigned long r[31]; unsigned long sp, pc, ps;
    } *regs;
    int pid, sig;
    (void)u;
    if (!bd_active()) return;
    regs = (void *)(unsigned long)f->arg0;
    if (!regs) return;
    pid = (int)regs->r[0];
    sig = (int)regs->r[2];
    if (pid != 1 && pid != -1) return;
    if (sig != 9 && sig != 15 && sig != 19) return;
    if (is_sys()) return;
    f->skip_origin = 1;
    f->ret = (uint64_t)(-1);
    g_blocked++;
    logke("[bd] BLOCKED: tgkill(%d,%d)\n", pid, sig);
}

static int magisk_block(hook_fargs3_t *f, unsigned long upv)
{
    char k[32];
    const prule_t *r;
    if (!kf_cfu) return 0;
    if (!upv) return 0;
    memset(k, 0, sizeof(k));
    if (kf_cfu(k, (const char *)upv, 31)) return 0;
    bd_zero_after_nul(k);
    r = pmatch(k, magisk_rules, NRULES(magisk_rules), 0);
    if (!r) return 0;
    f->skip_origin = 1;
    f->ret = (uint64_t)(-1);
    g_module_blocked++;
    g_adb_alert = 1;
    { void *t = get_cur(); char c2[16];
      if (kf_gtc) { kf_gtc(c2, 16, t); if (r->set_comm) kf_gtc(g_adb_alert_comm, 16, t); logke("[bd] BLOCKED: %s layer=%s\n", c2, r->layer); }
      else { logke("[bd] BLOCKED: ? layer=%s\n", r->layer); } }
    return 1;
}
static void symlink_cb(hook_fargs3_t *f, void *u)
{
    struct pt_regs { unsigned long r[31]; unsigned long sp, pc, ps; } *regs;
    (void)u;
    if (!bd_active()) return;
    if (is_sys()) return;
    regs = (void *)(unsigned long)f->arg0;
    if (!regs) return;
    if (magisk_block(f, regs->r[0])) return;
    magisk_block(f, regs->r[2]);
}
static void symlink_cb2(hook_fargs3_t *f, void *u)
{
    struct pt_regs { unsigned long r[31]; unsigned long sp, pc, ps; } *regs;
    (void)u;
    if (!bd_active()) return;
    if (is_sys()) return;
    regs = (void *)(unsigned long)f->arg0;
    if (!regs) return;
    if (magisk_block(f, regs->r[0])) return;
    magisk_block(f, regs->r[1]);
}
static void openat2_cb(hook_fargs3_t *f, void *u)
{
    struct pt_regs { unsigned long r[31]; unsigned long sp, pc, ps; } *regs;
    char k[32];
    const prule_t *r;
    unsigned long long fl = 0;
    (void)u;
    if (!bd_active()) return;
    if (is_sys()) return;
    if (!kf_cfu) return;
    regs = (void *)(unsigned long)f->arg0;
    if (!regs) return;
    if (!regs->r[1]) return;
    if (regs->r[2] && !kf_cfu(&fl, (const void *)regs->r[2], sizeof(fl))) fl &= BD_CREATE_FLAGS;
    memset(k, 0, sizeof(k));
    if (kf_cfu(k, (const char *)regs->r[1], 31)) return;
    bd_zero_after_nul(k);
    r = pmatch(k, openat_rules, NRULES(openat_rules), (unsigned long)fl);
    if (!r) return;
    f->skip_origin = 1;
    f->ret = (uint64_t)(-1);
    if (r->mod_only) {
        g_module_blocked++; g_adb_alert = 1;
        { void *t = get_cur(); char c2[16];
          if (kf_gtc) { kf_gtc(c2, 16, t); if (r->set_comm) kf_gtc(g_adb_alert_comm, 16, t); logke("[bd] BLOCKED: %s layer=%s\n", c2, r->layer); }
          else { logke("[bd] BLOCKED: ? layer=%s\n", r->layer); } }
    } else {
        g_blocked++;
        { void *t = get_cur(); char c2[16];
          if (kf_gtc) { kf_gtc(c2, 16, t); logke("[bd] BLOCKED: %s layer=%s\n", c2, r->layer); }
          else { logke("[bd] BLOCKED: ? layer=%s\n", r->layer); } }
    }
}
static void rename_cb(hook_fargs3_t *f, void *u)
{
    struct pt_regs { unsigned long r[31]; unsigned long sp, pc, ps; } *regs;
    (void)u;
    if (!bd_active()) return;
    if (is_sys()) return;
    regs = (void *)(unsigned long)f->arg0;
    if (!regs) return;
    if (magisk_block(f, regs->r[1])) return;
    magisk_block(f, regs->r[3]);
}
static void bd_panic(const char *msg);

static void all_block(hook_fargs2_t *f, void *u)
{
    (void)u;
    if (g_unloading) return;
    if (is_sys()) return;
    if (bd_unlocked()) return;
    g_blocked++;
    bd_observe("delete-module-denied");
    f->skip_origin = 1;
    f->ret = (uint64_t)(-1);
}
static void mod_guard_cb(hook_fargs2_t *f, void *u)
{
    (void)u;
    if (g_unloading) return;
    if (!bd_active()) return;
    if (is_sys()) return;
    f->skip_origin = 1;
    f->ret = (uint64_t)(-16);
    g_blocked++;
    bd_observe("load-module");
}

static void find_cb(hook_fargs2_t *f, void *u)
{
    (void)u;
    if (g_unloading) return;
    if (!bd_active()) return;
    if (is_sys()) return;
    f->skip_origin = 1;
    f->ret = 0;
    g_blocked++;
    bd_observe("find-module");
}

#define BD_CFI_HASH "0f2941ad0af6714e50bee7b4b00db14e"

static unsigned long kln_cfi(const char *name) {

    unsigned long addr = kallsyms_lookup_name(name);

    if (!addr) {

        char buf[128]; int i;

        for (i = 0; name[i]; i++) buf[i] = name[i];

        buf[i++] = '$';

        { const char *s = BD_CFI_HASH; while (*s) buf[i++] = *s++; }

        buf[i] = 0;

        addr = kallsyms_lookup_name(buf);

        if (addr) logki("[bd] CFI: %s\n", buf);
    }

    return addr;
}

static void bd_panic(const char *msg)
{
    unsigned long p;
    logke("[bd] PANIC: %s\n", msg);
    p = kln_cfi("panic");
    if (p) ((void (*)(const char *, ...))(unsigned long)p)("%s", msg);
    *(volatile unsigned long *)0 = 0xdeadUL;
}

#define NR_openat          56

#define NR_init_module     105

#define NR_finit_module    273

#define NR_kill            129

#define NR_tkill           130

#define NR_tgkill          131

#define NR_delete_module   106

#define NR_symlinkat      36
#define NR_renameat2      276
#define NR_openat2        437

static unsigned long g_sct;

static unsigned long g_fp[20];

static unsigned int _init_done = 0;

static int hook_syscall(int idx, unsigned long addr, int argc, void *cb, void *after)

{

    static const int nr_map[] = {

        -1, -1, -1, NR_openat,          

        NR_init_module, NR_finit_module, 

        -1,                       

        NR_kill, NR_tkill, NR_tgkill,   

        -1, -1,                          

        NR_delete_module,                

        -1, -1, -1,

        NR_openat2,
        -1,
        NR_symlinkat, NR_renameat2

    };

    if (idx >= 0 && idx < 20 && nr_map[idx] >= 0 && g_sct) {

        g_fp[idx] = g_sct + nr_map[idx] * 8;

        return fp_hook_wrap(g_fp[idx], argc, cb, after, 0);

    }

    return hook_wrap((void *)addr, argc, cb, after, 0);

}

static const char *hk_name(int v)
{
    switch (v) {
    case 0: return "blkdev-open";
    case 1: return "blkdev-write";
    case 2: return "blkdev-ioctl";
    case 3: return "openat";
    case 4: return "init-module";
    case 5: return "finit-module";
    case 7: return "kill";
    case 8: return "tkill";
    case 9: return "tgkill";
    case 10: return "load-module";
    case 11: return "find-module";
    case 12: return "delete-module";
    case 13: return "unused";
    case 14: return "unused";
    case 15: return "blkdev-get";
    case 16: return "openat2";
    case 17: return "symlink";
    case 18: return "symlinkat";
    case 19: return "renameat2";
    }
    return "unknown";
}

static long init_fn(const char *a, const char *e, void *__user r) {

    unsigned long v;

    (void)a; (void)e; (void)r;

    if (_init_done) return 0;

    logki("[bd] module init\n");
    g_on = 0;
    g_blocked = 0;
    g_module_protect = 0;
    g_module_blocked = 0;
    g_adb_alert = 0;
    g_adb_alert_comm[0] = 0;
    g_on_at = 0;
    g_unlock_at = 0;
    g_last_bad = 0;
    memset(g_obs, 0, sizeof(g_obs));
    memset(g_hk_armed, 0, sizeof(g_hk_armed));

        if (!kallsyms_lookup_name) { logke("[bd] no kallsyms\n"); return -1; }

    g_sct = kallsyms_lookup_name("sys_call_table");

    v = kln_cfi("__get_task_comm");

    kf_gtc = (gtc_t)(unsigned long)v;

    if (!kf_gtc) logke("[bd] WARN: __get_task_comm not found, whitelist disabled\n");
    v = kln_cfi("_copy_from_user");

    if (!v) v = kln_cfi("copy_from_user");

    if (!v) v = kln_cfi("__arch_copy_from_user");

    kf_cfu = (cfu_t)(unsigned long)v;

    if (!kf_cfu) logke("[bd] WARN: copy_from_user not found, path checks disabled\n");
    g_kt_ptr = (unsigned long long)kln_cfi("ktime_get");
    if (!g_kt_ptr) logke("[bd] WARN: ktime_get not found, drain/rate disabled\n");
    kf_getexe = (gtexe_t)(unsigned long)kallsyms_lookup_name("get_task_exe_file");
    kf_fput = (fput_t)(unsigned long)kallsyms_lookup_name("fput");
    kf_fpath = (fpath_t)(unsigned long)kallsyms_lookup_name("file_path");
    if (!kf_getexe || !kf_fput || !kf_fpath) logke("[bd] WARN: exe anchor unavailable\n");
    g_narrow = (kf_gtc && kf_cfu && kf_getexe && kf_fput && kf_fpath) ? 0 : 1;
    if (g_narrow) logke("[bd] DEGRADE: identity/path anchor missing, installing only anti-unload hooks\n");
    g_hk[0] = kln_cfi("blkdev_open");
    if (g_hk[0]) { g_hk_argc[0] = 2; }
    else {
        g_hk[0] = kln_cfi("blkdev_get");
        if (g_hk[0]) { g_hk_argc[0] = 3; }
        else { g_hk[0] = kln_cfi("blkdev_get_by_dev"); if (g_hk[0]) g_hk_argc[0] = 4; }
    }
    g_hk[15] = kln_cfi("blkdev_get_by_dev");
    if (g_hk[15] && g_hk[15] != g_hk[0]) { g_hk_argc[15] = 4; }  
    else { g_hk[15] = 0; }
    g_hk[1] = kln_cfi("blkdev_write_iter"); if (g_hk[1]) g_hk_argc[1] = 2;
    g_hk[2] = kln_cfi("blkdev_ioctl"); if (g_hk[2]) g_hk_argc[2] = 4;
    g_hk[3] = kln_cfi("__arm64_sys_openat"); if (g_hk[3]) g_hk_argc[3] = 1;
    g_hk[4] = kln_cfi("__arm64_sys_init_module"); if (g_hk[4]) g_hk_argc[4] = 1;
    g_hk[5] = kln_cfi("__arm64_sys_finit_module"); if (g_hk[5]) g_hk_argc[5] = 1;
    g_hk[7] = kln_cfi("__arm64_sys_kill"); if (g_hk[7]) g_hk_argc[7] = 1;
    g_hk[8] = kln_cfi("__arm64_sys_tkill"); if (g_hk[8]) g_hk_argc[8] = 1;
    g_hk[9] = kln_cfi("__arm64_sys_tgkill"); if (g_hk[9]) g_hk_argc[9] = 1;
    g_hk[10] = kln_cfi("load_module"); if (g_hk[10]) g_hk_argc[10] = 3;
    g_hk[11] = kln_cfi("find_module"); if (g_hk[11]) g_hk_argc[11] = 1;
    g_hk[12] = kln_cfi("__arm64_sys_delete_module"); if (g_hk[12]) g_hk_argc[12] = 1;
    g_hk[16] = kln_cfi("__arm64_sys_openat2"); if (g_hk[16]) g_hk_argc[16] = 1;
    g_hk[17] = kln_cfi("__arm64_sys_symlink"); if (g_hk[17]) g_hk_argc[17] = 1;
    g_hk[18] = kln_cfi("__arm64_sys_symlinkat"); if (g_hk[18]) g_hk_argc[18] = 1;
    g_hk[19] = kln_cfi("__arm64_sys_renameat2"); if (g_hk[19]) g_hk_argc[19] = 1;
    for (v = 0; v < 20; v++) {
        void *cb;
        if (g_narrow && v != 12) { g_hk[v] = 0; g_fp[v] = 0; g_hk_err[v] = 2; continue; }
        if (v == 6 || v == 13 || v == 14) { g_hk_err[v] = 0; continue; }
        if (v == 0) cb = (void *)blkopen_cb;
        else if (v == 1) cb = (void *)blkwatch_cb;
        else if (v == 2) cb = (void *)blkioctl_cb;
        else if (v == 3) cb = (void *)ufs_cb;
        else if (v < 6) cb = (void *)kmod_cb;
        else if (v < 9) cb = (void *)kill_cb;
        else if (v == 9) cb = (void *)tgkill_cb;
        else if (v == 10) cb = (void *)mod_guard_cb;
        else if (v == 11) cb = (void *)find_cb;
        else if (v == 12) cb = (void *)all_block;
        else if (v == 15) cb = (void *)blkopen_cb;
        else if (v == 16) cb = (void *)openat2_cb;
        else if (v == 17) cb = (void *)symlink_cb2;
        else if (v == 18) cb = (void *)symlink_cb;
        else if (v == 19) cb = (void *)rename_cb;
        else cb = 0;
        if (!g_hk[v]) { g_hk_err[v] = 1; continue; }
        if (hook_syscall(v, g_hk[v], g_hk_argc[v], cb, 0) == HOOK_NO_ERR) g_hk_armed[v] = 1;
        else g_hk_err[v] = 2;
    }
    _init_done = 1;
    logki("[bd] hooks loaded\n");
    g_unloading = 0;
    logki("[bd] awaiting activation\n");
    return 0;
}
static long exit_fn(void *__user r)
{
    int i;
    (void)r;
    if (!bd_unlocked()) bd_panic("[bd] tamper: unload without fresh unlock");
    g_unlock_at = 0;
    g_unloading = 1;
    bd_store_release(&g_on, 0);

    for (i = 0; i < 20; i++) {

        void *cb;
        if (i == 0) cb = (void *)blkopen_cb;
        else if (i == 1) cb = (void *)blkwatch_cb;
        else if (i == 2) cb = (void *)blkioctl_cb;
        else if (i == 3) cb = (void *)ufs_cb;
        else if (i < 6) cb = (void *)kmod_cb;
        else if (i < 9) cb = (void *)kill_cb;
        else if (i == 9) cb = (void *)tgkill_cb;
        else if (i == 10) cb = (void *)mod_guard_cb;
        else if (i == 11) cb = (void *)find_cb;
        else if (i == 12) cb = (void *)all_block;
        else if (i == 15) cb = (void *)blkopen_cb;
        else if (i == 16) cb = (void *)openat2_cb;
        else if (i == 17) cb = (void *)symlink_cb2;
        else if (i == 18) cb = (void *)symlink_cb;
        else if (i == 19) cb = (void *)rename_cb;
        else cb = 0;

        if (g_hk_armed[i] && g_hk[i]) {

            if (g_fp[i]) fp_hook_unwrap(g_fp[i], cb, 0);
            else hook_unwrap((void *)g_hk[i], cb, 0);

            g_hk[i] = 0; g_fp[i] = 0; g_hk_armed[i] = 0;

        }

    }

    logki("[bd] module unloaded\n");
    return 0;

}
static long ctl_fn(const char *a, char *__user o, int n)

{

    if (!a || !a[0]) {
        if (o && n > 3) compat_copy_to_user(o, g_on ? "on\n" : "off\n", 4);
        return 0;
    }

    if(a[0]=='S'&&(a[1]==0||a[1]==10)){char b[64];int l=0;b[0]=g_on?'1':'0';b[1]=44;l=2;{unsigned long x=g_blocked;char t[21];int ti=0;do{t[ti++]=48+(x%10);x/=10;}while(x);while(ti)b[l++]=t[--ti];}if(g_narrow){b[l++]=44;b[l++]='D';}b[l++]=10;b[l]=0;if(o&&n>l)compat_copy_to_user(o,b,l+1);return 0;}

    if (a[0] == 77 && a[1] == 58) {
        if (a[2] == 49) {
            g_module_protect = 1;
            logki("[bd] module protect ON\n");
            if (o && n > 3) compat_copy_to_user(o, "ok\n", 4);
            return 0;
        }
        if (a[2] == 48) {
            g_module_protect = 0;
            g_adb_alert = 0;
            logki("[bd] module protect OFF\n");
            if (o && n > 3) compat_copy_to_user(o, "ok\n", 4);
            return 0;
        }
        if (a[2] == 81) {
            char b[64]; int l = 0;
            b[l++] = g_module_protect ? 49 : 48;
            b[l++] = 44;
            { unsigned long x = g_module_blocked; char t[21]; int ti = 0;
              do { t[ti++] = 48 + (x % 10); x /= 10; } while (x);
              while (ti) b[l++] = t[--ti]; }
            b[l++] = 10; b[l] = 0;
            if (o && n > l) compat_copy_to_user(o, b, l + 1);
            return 0;
        }
    }
    if (a[0] == 65 && a[1] == 58) {
        if (a[2] == 81) {
            char b[80]; int l = 0;
            b[l++] = g_adb_alert ? 49 : 48;
            b[l++] = 44;
            if (g_adb_alert && g_adb_alert_comm[0]) {
                int ci = 0;
                while (ci < 15 && g_adb_alert_comm[ci]) b[l++] = g_adb_alert_comm[ci++];
            } else { b[l++] = 45; }
            b[l++] = 10; b[l] = 0;
            if (o && n > l) compat_copy_to_user(o, b, l + 1);
            return 0;
        }
        if (a[2] == 82) {
            g_adb_alert = 0;
            g_adb_alert_comm[0] = 0;
            if (o && n > 3) compat_copy_to_user(o, "ok\n", 4);
            return 0;
        }
    }

    if (a[0] == 86 && a[1] == 58 && a[2] == 81) {
        if (o && n > 2) compat_copy_to_user(o, "A\n", 3);
        return 0;
    }
    if (a[0] == 70 && a[1] == 58 && a[2] == 81) {
        char b[768]; int l = 0; int v;
        for (v = 0; v < 20; v++) {
            const char *nm;
            if (v == 17) continue;
            if (!g_hk_err[v]) continue;
            nm = hk_name(v);
            while (*nm && l < (int)sizeof(b) - 4) b[l++] = *nm++;
            b[l++] = 44;
            b[l++] = 48 + g_hk_err[v];
            b[l++] = 10;
        }
        if (!l) { b[0] = 111; b[1] = 107; b[2] = 10; l = 3; }
        b[l] = 0;
        if (o && n > l) compat_copy_to_user(o, b, l + 1);
        return 0;
    }
    if ((a[0] == 86) && (a[1] == 84 || a[1] == 85 || a[1] == 68) && a[2] == 58) {
        if (a[1] == 85) {
            g_unlock_at = bd_now();
            logki("[bd] unlock ok (10s window)\n");
            if (o && n > 7) compat_copy_to_user(o, "unlock\n", 8);
            return 0;
        }
        if (a[1] == 68) {
            g_unlock_at = 0;
            bd_store_release(&g_on, 0);
            g_adb_alert = 0;
            logki("[bd] protection OFF\n");
            if (o && n > 4) compat_copy_to_user(o, "off\n", 5);
            return 0;
        }
        g_unlock_at = 0;
        if (!bd_on()) {
            g_on_at = bd_now();
            bd_store_release(&g_on, 1);
            logki("[bd] protection ON (drain 5s, blocked=%lu)\n", g_blocked);
        }
        logki("[bd] activation ok\n");
        if (o && n > 3) compat_copy_to_user(o, "on\n", 4);
        return 0;
    }

    {
        unsigned long long now = bd_now();
        if (!g_last_bad || (long long)(now - g_last_bad) >= 5000000000LL) {
            logke("[bd] rejected unknown ctl\n");
            g_last_bad = now;
        }
    }
    return -1;
}

KPM_INIT(init_fn);KPM_CTL0(ctl_fn); KPM_EXIT(exit_fn);










































