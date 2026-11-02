/*
 * sched_fuzz_exec -- guest-side executor for the differential scheduler fuzzer,
 * PID 1 in a QEMU initramfs. Runs each program in /programs (one op per line,
 * programs separated by "===") and prints a trace for the host oracle.
 *
 * Ops:
 *   W  <id>                   spawn busy worker
 *   WB <id>                   spawn blocked worker (pause loop)
 *   A  <id> <pol> <rt> <dl> <pd> <nice> <flags>   sched_setattr (us; flags hex)
 *   R  <id> <rt> <pd>         admit worker as SCHED_DEADLINE+RECLAIM (GRUB)
 *   K  <id>                   kill worker
 *   H  <cpu> <0|1>            cpu hotplug online/offline
 *   D  <cpu> <rt> <pd>        fair_server debugfs write
 *   F  <ms>                   CFS fork/exit churn for <ms>
 *   P  <cpu>                  re-apply the cpuset partition settings of <cpu>
 *   O  <id> <rt> <pd>         DL overrun: admit small-runtime DL, wait ~1.5 periods
 *   M  <id>                   move worker into the cpu-controller cgroup cg
 *   X                         futex-PI boost
 *   Y  <cpu>                  background hotplug churner
 *   G  <cpu>                  background fair_server writer
 *   C  <id> <cpu>             move worker into <cpu>'s exclusive partition
 *   U  <id>                   move worker back to the root cgroup
 *   T  <id>                   SCHED_FIFO busy task under RLIMIT_RTTIME, reaped
 *   E  <id> [<rt> <pd> <n>]   cycle the worker through DL and OTHER <n> times
 *   S                         sample dl_bw->total_bw ledger
 *   Z  <us>                   sleep
 * Y/G keep running in the background for the rest of the program.
 *
 * Records parsed by the host: ##PROG/##PROG_END <n>, base_bw, STEP, SIGMA,
 * SIGMA_SUMMARY, A (A/R/O/E) and MOVE (C/U/M) return codes keyed by step=,
 * ##OP_SKIPPED, final_expected/final_admitted (sigma at the boundary),
 * final_bw, ##LEDGER_REBASE_FAILED, ##FUZZ_DONE.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/resource.h>

#ifndef __NR_sched_setattr
#define __NR_sched_setattr 314
#endif
#define MAXW 32

struct sa { uint32_t size, policy; uint64_t flags; int32_t nice;
            uint32_t prio; uint64_t runtime, deadline, period; };

static int seta(pid_t p, struct sa *a){ return syscall(__NR_sched_setattr,p,a,0); }

static pid_t worker[MAXW];

#define MAXBG 8
#define T_WAIT_US        70000
#define T_POLL_US         1000
static pid_t bgproc[MAXBG];
static int nbg;

/* A cpu-keyed op naming a cpu the machine does not have is skipped. */
static int cpu_exists(int cpu){
    static long nconf = -1;
    if(nconf < 0){ nconf = sysconf(_SC_NPROCESSORS_CONF); if(nconf < 1) nconf = 1; }
    return cpu >= 0 && cpu < nconf;
}
static int sg_curstep;
static int cpu_gate(int cpu, char op){
    if(cpu_exists(cpu)) return 1;
    printf("##OP_SKIPPED op=%c cpu=%d step=%d reason=no_such_cpu\n",
           op, cpu, sg_curstep);
    fflush(stdout);
    return 0;
}

static long read_total_bw(void){
    FILE *f=fopen("/sys/kernel/debug/sched/debug","r"); if(!f) return -1;
    char line[256]; long v=-1;
    while(fgets(line,sizeof line,f)){
        char *p=strstr(line,"dl_bw->total_bw");
        if(p){ p=strchr(p,':'); if(p) v=strtol(p+1,NULL,10); break; }
    }
    fclose(f); return v;
}

/* Shadow state sigma, one transition per op. The host re-derives it with
 * sigma_step_cbs() and cross-checks it against these records. */
#define SG_KEEP_PARAMS 0x10ULL
#define SG_KEEP_POLICY 0x08ULL
#define SG_TOL         1024L      /* same derivation as fuzz_kernel.py LEDGER_TOL */
#ifndef SG_SETTLE_US
/* per-op settle before observing, in microseconds */
#define SG_SETTLE_US 0
#endif

static long sg_A[MAXW];      /* per-slot reserved bandwidth (0 if not admitted) */
/* 1 while the slot is admitted (its sg_A may round to 0) */
static unsigned char sg_adm[MAXW];
/* per-slot root domain: 0 = the default one, c = cpu c's exclusive partition */
static int  sg_D[MAXW];
static long sg_base;         /* baseline total_bw for this program */
/* a perturber ran: the next observation re-anchors the baseline */
static int  sg_susp;
static int  sg_checked, sg_suspended_n, sg_viol;
static int  sg_anchored;
/* a Y/G churner is running: the rest of the program is suspended */
static int  sg_churn;

/* kernel to_ratio(): (runtime_ns << 20) / period_ns, from microsecond args */
static long sg_to_ratio(unsigned long rt_us, unsigned long pd_us){
    if(!pd_us) return 0;
    return (long)(((unsigned long long)rt_us * 1000ULL) << 20) /
           (long)((unsigned long long)pd_us * 1000ULL);
}
static void sg_reset(long base){
    for(int i=0;i<MAXW;i++){ sg_A[i]=0; sg_adm[i]=0; sg_D[i]=0; }
    sg_base=base; sg_susp=0; sg_anchored=0; sg_churn=0;
    sg_checked=sg_suspended_n=sg_viol=0;
}
static long sg_expected(void){
    long t=sg_base;
    for(int i=0;i<MAXW;i++) if(sg_D[i]==0) t+=sg_A[i];
    return t;
}
static long sg_admitted_now(void){
    long t=0;
    for(int i=0;i<MAXW;i++) if(sg_D[i]==0) t+=sg_A[i];
    return t;
}
static void sg_setdom(int i,int dom){ if(i>=0 && i<MAXW) sg_D[i]=dom; }
static void sg_admit(int i, unsigned long rt_us, unsigned long pd_us){
    if(i>=0 && i<MAXW){ sg_A[i]=sg_to_ratio(rt_us,pd_us); sg_adm[i]=1; }
}
static void sg_release(int i){ if(i>=0 && i<MAXW){ sg_A[i]=0; sg_adm[i]=0; } }

/* Per-op verdict: prints the SIGMA record. Unused with -DSG_BOUNDARY_ONLY. */
static long __attribute__((unused)) sg_verify(int step, char op, unsigned settle_us){
    if(settle_us) usleep(settle_us);
    long obs = read_total_bw();
    if(sg_churn){
        sg_suspended_n++;
        printf("SIGMA i=%d op=%c state=suspended observed=%ld\n", step, op, obs);
        return obs;
    }
    if(sg_susp){
        /* re-anchor the baseline on this observation, which is not judged */
        long adm=0; for(int i=0;i<MAXW;i++) if(sg_D[i]==0) adm+=sg_A[i];
        sg_base = obs - adm;
        sg_susp = 0; sg_anchored = 1;
        sg_suspended_n++;
        printf("SIGMA i=%d op=%c state=anchor observed=%ld rebased=%ld\n",
               step, op, obs, sg_base);
        return obs;
    }
    long exp = sg_expected();
    long d = obs - exp;
    sg_checked++;
    if(d > SG_TOL || d < -SG_TOL) sg_viol++;
    printf("SIGMA i=%d op=%c state=checked expected=%ld observed=%ld delta=%ld%s\n",
           step, op, exp, obs, d, sg_anchored ? " anchored=1" : "");
    return obs;
}
static void wtext(const char *path,const char *val){
    int fd=open(path,O_WRONLY|O_CLOEXEC); if(fd<0) return;
    if(write(fd,val,strlen(val))<0){} close(fd);
}
static int wtext_rc(const char *path,const char *val){
    int fd=open(path,O_WRONLY|O_CLOEXEC); if(fd<0) return -errno;
    ssize_t n=write(fd,val,strlen(val)); int e=errno; close(fd);
    return n<0 ? -e : 0;
}
static pid_t spawn(int blocked){
    pid_t p=fork();
    if(p==0){
        if(blocked){ for(;;) pause(); }
        else { volatile uint64_t x=0; for(;;) for(int i=0;i<5000;i++) x+=i; }
    }
    usleep(3000);
    return p;
}
static void kill_all(void){
    for(int i=0;i<MAXW;i++) if(worker[i]>0){ kill(worker[i],SIGKILL);
        waitpid(worker[i],NULL,0); worker[i]=0; }
}

static void bg_hotplug(int cpu){
    char p[64]; snprintf(p,sizeof p,"/sys/devices/system/cpu/cpu%d/online",cpu);
    for(;;){ wtext(p,"0\n"); usleep(6000); wtext(p,"1\n"); usleep(6000); }
}
static void bg_fairwrite(int cpu){
    char pr[96],rn[96];
    snprintf(pr,sizeof pr,"/sys/kernel/debug/sched/fair_server/cpu%d/period",cpu);
    snprintf(rn,sizeof rn,"/sys/kernel/debug/sched/fair_server/cpu%d/runtime",cpu);
    const char *rv[]={"100000\n","300000\n","1\n","50000\n"};
    const char *pv[]={"1000000\n","2000000\n","1000000000\n","500000\n"};
    int i=0; for(;;){ wtext(pr,pv[i&3]); wtext(rn,rv[i&3]); i++; }
}
static void spawn_bg(void(*fn)(int),int arg){
    if(nbg>=MAXBG) return;
    pid_t p=fork();
    if(p==0){ fn(arg); _exit(0); }
    if(p>0) bgproc[nbg++]=p;
}
static void kill_bg(void){
    for(int i=0;i<nbg;i++) if(bgproc[i]>0){ kill(bgproc[i],SIGKILL);
        waitpid(bgproc[i],NULL,0); bgproc[i]=0; }
    nbg=0;
    for(int c=1;c<=3;c++){ char p[64];             /* restore CPUs online */
        snprintf(p,sizeof p,"/sys/devices/system/cpu/cpu%d/online",c);
        wtext(p,"1\n"); }
}

static void fork_churn(int ms){
    struct timespec t0; clock_gettime(CLOCK_MONOTONIC,&t0);
    for(;;){
        struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t);
        long el=(t.tv_sec-t0.tv_sec)*1000 + (t.tv_nsec-t0.tv_nsec)/1000000;
        if(el>=ms) break;
        pid_t p=fork();
        if(p==0) _exit(0);
        else if(p>0) waitpid(p,NULL,0);
        else usleep(1000);
    }
}

/* P: re-apply the settings setup_partitions() wrote for <cpu>. */
static void partition_cpu(int cpu){
    static int mounted=0;
    if(!mounted){ mkdir("/sys/fs/cgroup",0755);
        mount("none","/sys/fs/cgroup","cgroup2",0,NULL);
        wtext("/sys/fs/cgroup/cgroup.subtree_control","+cpuset\n"); mounted=1; }
    char dir[64],path[160],val[16];
    snprintf(dir,sizeof dir,"/sys/fs/cgroup/iso%d",cpu); mkdir(dir,0755);
    snprintf(val,sizeof val,"%d\n",cpu);
    snprintf(path,sizeof path,"%s/cpuset.cpus",dir); wtext(path,val);
    snprintf(path,sizeof path,"%s/cpuset.cpus.exclusive",dir); wtext(path,val);
    snprintf(path,sizeof path,"%s/cpuset.cpus.partition",dir); wtext(path,"root\n");
}

/* Create the partitions iso<c> that C uses; at init, before base_bw is read. */
static void setup_partitions(void){
    mkdir("/sys/fs/cgroup",0755);
    mount("none","/sys/fs/cgroup","cgroup2",0,NULL);
    wtext("/sys/fs/cgroup/cgroup.subtree_control","+cpuset\n");
    long ncpu=sysconf(_SC_NPROCESSORS_ONLN); if(ncpu<1) ncpu=1;
    for(int cpu=1; cpu<ncpu; cpu++){
        char dir[64],path[160],val[16];
        snprintf(dir,sizeof dir,"/sys/fs/cgroup/iso%d",cpu); mkdir(dir,0755);
        snprintf(val,sizeof val,"%d\n",cpu);
        snprintf(path,sizeof path,"%s/cpuset.cpus",dir); wtext(path,val);
        snprintf(path,sizeof path,"%s/cpuset.cpus.exclusive",dir); wtext(path,val);
        snprintf(path,sizeof path,"%s/cpuset.cpus.partition",dir); wtext(path,"root\n");
    }
}

static int move_to_partition(pid_t pid,int cpu){
    char path[96],v[24];
    snprintf(v,sizeof v,"%d\n",(int)pid);
    snprintf(path,sizeof path,"/sys/fs/cgroup/iso%d/cgroup.procs",cpu);
    return wtext_rc(path,v);
}
static int move_to_root(pid_t pid){
    char v[24]; snprintf(v,sizeof v,"%d\n",(int)pid);
    return wtext_rc("/sys/fs/cgroup/cgroup.procs",v);
}

static int cgroup_move(pid_t pid){
    static int ready=0;
    if(!ready){ mkdir("/sys/fs/cgroup",0755);
        mount("none","/sys/fs/cgroup","cgroup2",0,NULL);
        wtext("/sys/fs/cgroup/cgroup.subtree_control","+cpu\n");
        mkdir("/sys/fs/cgroup/cg",0755); ready=1; }
    char v[24]; snprintf(v,sizeof v,"%d\n",(int)pid);
    return wtext_rc("/sys/fs/cgroup/cg/cgroup.procs",v);
}

/* X: a high-prio waiter (this process) PI-boosts a low-prio forked holder. */
#ifndef FUTEX_LOCK_PI
#define FUTEX_LOCK_PI   6
#define FUTEX_UNLOCK_PI 7
#endif
#ifndef __NR_futex
#define __NR_futex 202
#endif
static int futex(int *u,int op){ return syscall(__NR_futex,u,op,0,NULL,NULL,0); }
static void pi_boost_burst(void){
    int *w=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    if(w==MAP_FAILED) return;
    *w=0;
    pid_t holder=fork();
    if(holder==0){ struct sa a; memset(&a,0,sizeof a); a.size=sizeof a; a.policy=0; a.nice=19;
        seta(0,&a);
        if(futex(w,FUTEX_LOCK_PI)==0){ usleep(15000); futex(w,FUTEX_UNLOCK_PI); }
        _exit(0); }
    usleep(4000);
    struct sa hi; memset(&hi,0,sizeof hi); hi.size=sizeof hi; hi.policy=1; hi.prio=50;
    seta(0,&hi);
    if(futex(w,FUTEX_LOCK_PI)==0) futex(w,FUTEX_UNLOCK_PI);
    struct sa lo; memset(&lo,0,sizeof lo); lo.size=sizeof lo; lo.policy=0; seta(0,&lo);
    waitpid(holder,NULL,0); munmap(w,4096);
}

/* ledger at boot; run_program() re-establishes it between programs */
static long boot_base = -1;
#define REBASE_TOL 65536L          /* 1/16 of one CPU */

/* Rewrite sched_rt_runtime_us as is (the default 950000 if unreadable). */
static void rewrite_rt_runtime(void){
    char buf[64]; memset(buf,0,sizeof buf);
    int fd=open("/proc/sys/kernel/sched_rt_runtime_us",O_RDONLY);
    int n = fd>=0 ? (int)read(fd,buf,sizeof buf-1) : 0;
    if(fd>=0) close(fd);
    wtext("/proc/sys/kernel/sched_rt_runtime_us", n>0 ? buf : "950000\n");
}

static void run_program(int n, char *text){
    kill_all();
    kill_bg();
    long base=read_total_bw();
    if(boot_base >= 0){
        long drift = base - boot_base; if(drift<0) drift = -drift;
        if(drift > REBASE_TOL){
            rewrite_rt_runtime();
            long now = read_total_bw();
            long left = now - boot_base; if(left<0) left = -left;
            printf("##LEDGER_REBASED was=%ld boot_base=%ld now=%ld\n",
                   base, boot_base, now);
            if(left > REBASE_TOL){
                printf("##LEDGER_REBASE_FAILED base=%ld boot_base=%ld drift=%ld "
                       "-- powering off\n", now, boot_base, now-boot_base);
                fflush(stdout); sync(); reboot(RB_POWER_OFF); for(;;) pause();
            }
            base = now;
        }
    }
    printf("##PROG %d\nbase_bw=%ld\n", n, base);
    sg_reset(base);
    char *save=NULL;
    int stepno=0;
    for(char *line=strtok_r(text,"\n",&save); line; line=strtok_r(NULL,"\n",&save)){
        char op=line[0];
        sg_curstep=stepno;
        if(op=='W'){
            int blocked=(line[1]=='B'); int id;
            if(sscanf(line+ (blocked?2:1)," %d",&id)==1 && id>=0 && id<MAXW){
                if(worker[id]>0) {} else worker[id]=spawn(blocked);
            }
        } else if(op=='A'){
            int id,pol,nice; unsigned long rt,dl,pd; unsigned long long fl;
            if(sscanf(line+1," %d %d %lu %lu %lu %d %llx",
                      &id,&pol,&rt,&dl,&pd,&nice,&fl)==7 && id>=0&&id<MAXW&&worker[id]>0){
                struct sa a; memset(&a,0,sizeof a); a.size=sizeof a;
                a.policy=pol; a.flags=fl; a.nice=nice;
                a.runtime=rt*1000ULL; a.deadline=dl*1000ULL; a.period=pd*1000ULL;
                errno=0; int rc=seta(worker[id],&a); int e=errno;
                if(rc==0 && !(fl & SG_KEEP_POLICY) && !(fl & SG_KEEP_PARAMS)){
                    if(pol==6) sg_admit(id, rt, pd);   /* became DL: reserve */
                    else       sg_release(id);         /* left DL: must release */
                } else if(rc==0 && (fl & SG_KEEP_POLICY) && !(fl & SG_KEEP_PARAMS)
                          && sg_adm[id]){
                    /* KEEP_POLICY: stays DL with the given parameters */
                    sg_admit(id, rt, pd);
                }
                printf("A id=%d rc=%d errno=%d step=%d\n", id,rc,e,stepno);
            }
        } else if(op=='R'){
            int id; unsigned long rt,pd;
            if(sscanf(line+1," %d %lu %lu",&id,&rt,&pd)==3 && id>=0&&id<MAXW&&worker[id]>0){
                struct sa a; memset(&a,0,sizeof a); a.size=sizeof a;
                a.policy=6; a.flags=0x02 /*SCHED_FLAG_RECLAIM*/;
                a.runtime=rt*1000ULL; a.deadline=pd*1000ULL; a.period=pd*1000ULL;
                errno=0; int rc=seta(worker[id],&a); int e=errno;
                if(rc==0) sg_admit(id, rt, pd);
                printf("A id=%d rc=%d errno=%d step=%d\n", id,rc,e,stepno); }
        } else if(op=='K'){
            int id; if(sscanf(line+1," %d",&id)==1 && id>=0&&id<MAXW&&worker[id]>0){
                kill(worker[id],SIGKILL); waitpid(worker[id],NULL,0); worker[id]=0;
                sg_release(id);
                sg_setdom(id,0); }
        } else if(op=='H'){
            int cpu,on; if(sscanf(line+1," %d %d",&cpu,&on)==2){
                char p[64]; snprintf(p,sizeof p,
                    "/sys/devices/system/cpu/cpu%d/online",cpu);
                wtext(p,on?"1\n":"0\n");
                /* an offlined cpu's slots return to domain 0 */
                if(!on) for(int j=0;j<MAXW;j++) if(sg_D[j]==cpu) sg_D[j]=0;
                if(cpu_gate(cpu,'H')) sg_susp=1; }
        } else if(op=='F'){
            int ms; if(sscanf(line+1," %d",&ms)==1) fork_churn(ms%5000);
            sg_susp=1;
        } else if(op=='P'){
            int cpu;
            if(sscanf(line+1," %d",&cpu)==1 && cpu>0 && cpu_gate(cpu,'P')){
                partition_cpu(cpu);
                sg_susp=1; }
        } else if(op=='O'){
            int id; unsigned long rt,pd;
            if(sscanf(line+1," %d %lu %lu",&id,&rt,&pd)==3 && id>=0&&id<MAXW&&worker[id]>0){
                struct sa a; memset(&a,0,sizeof a); a.size=sizeof a; a.policy=6;
                a.runtime=rt*1000ULL; a.deadline=pd*1000ULL; a.period=pd*1000ULL;
                errno=0; int rc=seta(worker[id],&a); int e=errno;
                if(rc==0){
                    sg_admit(id, rt, pd);
                    unsigned long us=(pd*3UL)/2;
                    struct timespec t={us/1000000UL,(us%1000000UL)*1000UL};
                    nanosleep(&t,NULL); }
                printf("A id=%d rc=%d errno=%d step=%d\n", id,rc,e,stepno); }
        } else if(op=='M'){
            int id; if(sscanf(line+1," %d",&id)==1 && id>=0&&id<MAXW&&worker[id]>0)
                { int rc=cgroup_move(worker[id]);
                  /* cg is in the root partition */
                  if(rc==0) sg_setdom(id,0);
                  printf("MOVE id=%d cpu=0 rc=%d step=%d\n",
                         id,rc,stepno); }
        } else if(op=='X'){ pi_boost_burst(); }
        else if(op=='D'){
            unsigned long a1,rt,pd;
            if(sscanf(line+1," %lu %lu %lu",&a1,&rt,&pd)==3){
                int cpu=(int)a1;
                char path[80],v[32];
                snprintf(path,sizeof path,"/sys/kernel/debug/sched/fair_server/cpu%d/period",cpu);
                snprintf(v,sizeof v,"%lu\n",pd); wtext(path,v);
                snprintf(path,sizeof path,"/sys/kernel/debug/sched/fair_server/cpu%d/runtime",cpu);
                snprintf(v,sizeof v,"%lu\n",rt); wtext(path,v);
                if(cpu_gate(cpu,'D')) sg_susp=1; }
        } else if(op=='Y'){
            int cpu;
            if(sscanf(line+1," %d",&cpu)==1 && cpu>0 && cpu_gate(cpu,'Y')){
                spawn_bg(bg_hotplug,cpu);
                sg_susp=1; sg_churn=1; }
        } else if(op=='G'){
            int cpu;
            if(sscanf(line+1," %d",&cpu)==1 && cpu>0 && cpu_gate(cpu,'G')){
                spawn_bg(bg_fairwrite,cpu);
                sg_susp=1; sg_churn=1; }
        } else if(op=='T'){
            int id; if(sscanf(line+1," %d",&id)==1 && id>=0 && id<MAXW){
                if(worker[id]>0){ kill(worker[id],SIGKILL); waitpid(worker[id],NULL,0); }
                sg_release(id); sg_setdom(id,0);
                worker[id]=spawn(0);
                if(worker[id]>0){
                    /* RLIMIT_RTTIME is in microseconds */
                    struct rlimit rl={ .rlim_cur=10000, .rlim_max=20000 };
                    prlimit(worker[id],RLIMIT_RTTIME,&rl,NULL);
                    struct sa f; memset(&f,0,sizeof f); f.size=sizeof f;
                    f.policy=1; f.prio=50; seta(worker[id],&f);
                    pid_t r=0;
                    for(long w=0; r==0 && w<T_WAIT_US; w+=T_POLL_US){
                        r=waitpid(worker[id],NULL,WNOHANG);
                        if(r==0) usleep(T_POLL_US);
                    }
                    if(r<=0){ kill(worker[id],SIGKILL); waitpid(worker[id],NULL,0); }
                }
                worker[id]=0; }
        } else if(op=='C'){
            int id,cpu; if(sscanf(line+1," %d %d",&id,&cpu)==2
                           && id>=0 && id<MAXW && worker[id]>0
                           && cpu>=1 && cpu<=3)
                { int rc=move_to_partition(worker[id],cpu);
                  if(rc==0) sg_setdom(id,cpu);
                  printf("MOVE id=%d cpu=%d rc=%d step=%d\n",
                         id,cpu,rc,stepno); }
        } else if(op=='U'){
            int id; if(sscanf(line+1," %d",&id)==1 && id>=0 && id<MAXW && worker[id]>0)
                { int rc=move_to_root(worker[id]);
                  if(rc==0) sg_setdom(id,0);
                  printf("MOVE id=%d cpu=0 rc=%d step=%d\n",
                         id,rc,stepno); }
        } else if(op=='E'){
            int id; if(sscanf(line+1," %d",&id)==1 && id>=0 && id<MAXW && worker[id]>0){
                struct sa d; memset(&d,0,sizeof d); d.size=sizeof d; d.policy=6;
                unsigned long e_rt=2000, e_pd=50000; int e_n=3;
                { unsigned long a,b; int c;
                  int nf=sscanf(line+1," %*d %lu %lu %d",&a,&b,&c);
                  if(nf>=2 && a>0 && b>0){ e_rt=a; e_pd=b; }
                  if(nf>=3 && c>0 && c<=16) e_n=c; }
                d.runtime=e_rt*1000ULL; d.deadline=d.period=e_pd*1000ULL;
                struct sa o; memset(&o,0,sizeof o); o.size=sizeof o; o.policy=0;
                int rc=0; int e=0;
                for(int k=0;k<e_n;k++){ seta(worker[id],&d);
                    errno=0; rc=seta(worker[id],&o); e=errno; }
                /* net effect only: a failed final drop re-anchors */
                if(rc==0) sg_release(id); else sg_susp=1;
                printf("A id=%d rc=%d errno=%d step=%d\n", id,rc,e,stepno); }
        } else if(op=='S'){
            printf("bw=%ld\n", read_total_bw());
        } else if(op=='Z'){
            unsigned long us; if(sscanf(line+1," %lu",&us)==1) usleep(us%500000);
        }
#ifdef SG_BOUNDARY_ONLY
        /* boundary build: sigma stepped per op, judged only at the end */
        (void)0;
        stepno++;
#else
        long obs = sg_verify(stepno, op, SG_SETTLE_US);
        printf("STEP i=%d op=%c bw=%ld\n", stepno, op, obs);
        stepno++;
#endif
    }
    if(nbg>0) usleep(900000);   /* let the background churners run before teardown */
    kill_bg();
    kill_all();
    usleep(50000);
    printf("SIGMA_SUMMARY prog=%d steps=%d checked=%d suspended=%d out_of_spec=%d\n",
           n, stepno, sg_checked, sg_suspended_n, sg_viol);
    printf("final_expected=%ld final_admitted=%ld\n",
           sg_expected(), sg_admitted_now());
    printf("final_bw=%ld\n##PROG_END %d\n", read_total_bw(), n);
    fflush(stdout);
}

int main(void){
    mkdir("/proc",0755); mkdir("/sys",0755);
    mount("proc","/proc","proc",0,NULL);
    mount("sysfs","/sys","sysfs",0,NULL);
    mkdir("/sys/kernel/debug",0755);
    mount("debugfs","/sys/kernel/debug","debugfs",0,NULL);
    setup_partitions();
    printf("\n=== sched_fuzz_exec: differential scheduler fuzzing ===\n");
    fflush(stdout);

    boot_base = read_total_bw();
    printf("##BOOT_BASE %ld\n", boot_base);
    fflush(stdout);

    FILE *f=fopen("/programs","r");
    if(!f){ printf("##NO_PROGRAMS\n"); goto off; }
    char buf[8192]; int n=0; size_t len=0; buf[0]=0;
    char line[512];
    while(fgets(line,sizeof line,f)){
        if(strncmp(line,"===",3)==0){
            if(len){ run_program(n++,buf); buf[0]=0; len=0; }
        } else {
            size_t l=strlen(line);
            if(len+l<sizeof buf){ memcpy(buf+len,line,l); len+=l; buf[len]=0; }
        }
    }
    if(len) run_program(n++,buf);
    fclose(f);
    printf("\n##FUZZ_DONE programs=%d\n", n);
off:
    fflush(stdout); sync(); reboot(RB_POWER_OFF); for(;;) pause();
}
