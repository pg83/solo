/*
 * ABI probe: compiled once against glibc headers and once against the
 * vendored musl headers, never linked or run. Every probe is a tentative
 * char-array definition whose symbol size in the object file encodes the
 * probed value, so dev/abi_diff.py can read the numbers back from the two
 * object files and diff them.
 *
 * Offsets are biased by 1 and values by 4096 (zero-sized arrays are invalid
 * and some constants are small negatives); the reader subtracts the bias.
 */

#include <arpa/inet.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <ftw.h>
#include <getopt.h>
#include <glob.h>
#include <grp.h>
#include <ifaddrs.h>
#include <langinfo.h>
#include <limits.h>
#include <locale.h>
#include <mqueue.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <pwd.h>
#include <regex.h>
#include <sched.h>
#include <semaphore.h>
#include <setjmp.h>
#include <signal.h>
#include <spawn.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/file.h>
#include <sys/inotify.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/times.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>
#include <utmpx.h>
#include <wchar.h>
#include <wctype.h>

#define PROBE_SIZE(tag, ...) char probe_size_##tag[sizeof(__VA_ARGS__)];
#define PROBE_OFFSET(tag, type, member) char probe_offset_##tag[offsetof(type, member) + 1];
#define PROBE_VALUE(tag, ...) char probe_value_##tag[(__VA_ARGS__) + 4096];

/* fundamental widths */
PROBE_SIZE(wchar_t, wchar_t)
PROBE_SIZE(wint_t, wint_t)
PROBE_SIZE(time_t, time_t)
PROBE_SIZE(off_t, off_t)
PROBE_SIZE(ino_t, ino_t)
PROBE_SIZE(dev_t, dev_t)
PROBE_SIZE(nlink_t, nlink_t)
PROBE_SIZE(blkcnt_t, blkcnt_t)
PROBE_SIZE(fsblkcnt_t, fsblkcnt_t)
PROBE_SIZE(clock_t, clock_t)
PROBE_SIZE(clockid_t, clockid_t)
PROBE_SIZE(suseconds_t, suseconds_t)
PROBE_SIZE(socklen_t, socklen_t)
PROBE_SIZE(nfds_t, nfds_t)
PROBE_SIZE(mbstate_t, mbstate_t)
PROBE_SIZE(wctype_t, wctype_t)
PROBE_SIZE(wctrans_t, wctrans_t)
PROBE_SIZE(locale_t, locale_t)
PROBE_SIZE(mqd_t, mqd_t)

/* stdio */
#ifdef __GLIBC__
PROBE_SIZE(FILE, FILE)
#endif
PROBE_SIZE(fpos_t, fpos_t)
PROBE_VALUE(BUFSIZ, BUFSIZ)
PROBE_VALUE(EOF, EOF)
PROBE_VALUE(FILENAME_MAX, FILENAME_MAX)
PROBE_VALUE(FOPEN_MAX, FOPEN_MAX)
PROBE_VALUE(L_tmpnam, L_tmpnam)
PROBE_VALUE(TMP_MAX, TMP_MAX)
PROBE_VALUE(_IOFBF, _IOFBF)
PROBE_VALUE(_IOLBF, _IOLBF)
PROBE_VALUE(_IONBF, _IONBF)

/* filesystem structures */
PROBE_SIZE(struct_stat, struct stat)
PROBE_OFFSET(stat_st_ino, struct stat, st_ino)
PROBE_OFFSET(stat_st_mode, struct stat, st_mode)
PROBE_OFFSET(stat_st_uid, struct stat, st_uid)
PROBE_OFFSET(stat_st_size, struct stat, st_size)
PROBE_OFFSET(stat_st_mtim, struct stat, st_mtim)
PROBE_SIZE(struct_statvfs, struct statvfs)
PROBE_OFFSET(statvfs_f_blocks, struct statvfs, f_blocks)
PROBE_OFFSET(statvfs_f_fsid, struct statvfs, f_fsid)
PROBE_SIZE(struct_statfs, struct statfs)
PROBE_OFFSET(statfs_f_blocks, struct statfs, f_blocks)
PROBE_SIZE(struct_dirent, struct dirent)
PROBE_OFFSET(dirent_d_ino, struct dirent, d_ino)
PROBE_OFFSET(dirent_d_off, struct dirent, d_off)
PROBE_OFFSET(dirent_d_reclen, struct dirent, d_reclen)
PROBE_OFFSET(dirent_d_type, struct dirent, d_type)
PROBE_OFFSET(dirent_d_name, struct dirent, d_name)
PROBE_SIZE(struct_flock, struct flock)
PROBE_OFFSET(flock_l_start, struct flock, l_start)
PROBE_SIZE(struct_utsname, struct utsname)
PROBE_OFFSET(utsname_release, struct utsname, release)

/* regex, glob, fnmatch, ftw */
PROBE_SIZE(regex_t, regex_t)
PROBE_SIZE(regmatch_t, regmatch_t)
PROBE_VALUE(REG_EXTENDED, REG_EXTENDED)
PROBE_VALUE(REG_ICASE, REG_ICASE)
PROBE_VALUE(REG_NEWLINE, REG_NEWLINE)
PROBE_VALUE(REG_NOSUB, REG_NOSUB)
PROBE_VALUE(REG_NOTBOL, REG_NOTBOL)
PROBE_VALUE(REG_NOTEOL, REG_NOTEOL)
PROBE_VALUE(REG_NOMATCH, REG_NOMATCH)
PROBE_VALUE(REG_ESPACE, REG_ESPACE)
PROBE_VALUE(REG_BADPAT, REG_BADPAT)
PROBE_SIZE(glob_t, glob_t)
PROBE_OFFSET(glob_gl_pathc, glob_t, gl_pathc)
PROBE_OFFSET(glob_gl_pathv, glob_t, gl_pathv)
PROBE_OFFSET(glob_gl_offs, glob_t, gl_offs)
PROBE_VALUE(GLOB_APPEND, GLOB_APPEND)
PROBE_VALUE(GLOB_DOOFFS, GLOB_DOOFFS)
PROBE_VALUE(GLOB_ERR, GLOB_ERR)
PROBE_VALUE(GLOB_MARK, GLOB_MARK)
PROBE_VALUE(GLOB_NOCHECK, GLOB_NOCHECK)
PROBE_VALUE(GLOB_NOESCAPE, GLOB_NOESCAPE)
PROBE_VALUE(GLOB_NOSORT, GLOB_NOSORT)
#ifdef GLOB_TILDE
PROBE_VALUE(GLOB_TILDE, GLOB_TILDE)
#endif
#ifdef GLOB_BRACE
PROBE_VALUE(GLOB_BRACE, GLOB_BRACE)
#endif
PROBE_VALUE(FNM_NOESCAPE, FNM_NOESCAPE)
PROBE_VALUE(FNM_PATHNAME, FNM_PATHNAME)
PROBE_VALUE(FNM_PERIOD, FNM_PERIOD)
#ifdef FNM_CASEFOLD
PROBE_VALUE(FNM_CASEFOLD, FNM_CASEFOLD)
#endif
#ifdef FNM_LEADING_DIR
PROBE_VALUE(FNM_LEADING_DIR, FNM_LEADING_DIR)
#endif
PROBE_SIZE(struct_FTW, struct FTW)
PROBE_VALUE(FTW_F, FTW_F)
PROBE_VALUE(FTW_D, FTW_D)
PROBE_VALUE(FTW_DNR, FTW_DNR)
PROBE_VALUE(FTW_NS, FTW_NS)
PROBE_VALUE(FTW_SL, FTW_SL)
PROBE_VALUE(FTW_PHYS, FTW_PHYS)
PROBE_VALUE(FTW_MOUNT, FTW_MOUNT)
PROBE_VALUE(FTW_CHDIR, FTW_CHDIR)
PROBE_VALUE(FTW_DEPTH, FTW_DEPTH)

/* signals */
PROBE_SIZE(sigset_t, sigset_t)
PROBE_SIZE(siginfo_t, siginfo_t)
PROBE_OFFSET(siginfo_si_signo, siginfo_t, si_signo)
PROBE_OFFSET(siginfo_si_code, siginfo_t, si_code)
PROBE_OFFSET(siginfo_si_pid, siginfo_t, si_pid)
PROBE_OFFSET(siginfo_si_addr, siginfo_t, si_addr)
PROBE_OFFSET(siginfo_si_value, siginfo_t, si_value)
PROBE_OFFSET(siginfo_si_status, siginfo_t, si_status)
PROBE_SIZE(struct_sigaction, struct sigaction)
PROBE_OFFSET(sigaction_sa_mask, struct sigaction, sa_mask)
PROBE_OFFSET(sigaction_sa_flags, struct sigaction, sa_flags)
PROBE_SIZE(struct_sigevent, struct sigevent)
PROBE_OFFSET(sigevent_sigev_notify, struct sigevent, sigev_notify)
PROBE_SIZE(stack_t, stack_t)
PROBE_SIZE(ucontext_t, ucontext_t)
PROBE_OFFSET(ucontext_uc_mcontext, ucontext_t, uc_mcontext)
PROBE_SIZE(mcontext_t, mcontext_t)
PROBE_SIZE(jmp_buf, jmp_buf)
PROBE_SIZE(sigjmp_buf, sigjmp_buf)
PROBE_VALUE(SIGBUS, SIGBUS)
PROBE_VALUE(SIGCHLD, SIGCHLD)
PROBE_VALUE(SIGCONT, SIGCONT)
PROBE_VALUE(SIGIO, SIGIO)
PROBE_VALUE(SIGPWR, SIGPWR)
PROBE_VALUE(SIGSTKFLT, SIGSTKFLT)
PROBE_VALUE(SIGSTOP, SIGSTOP)
PROBE_VALUE(SIGSYS, SIGSYS)
PROBE_VALUE(SIGTSTP, SIGTSTP)
PROBE_VALUE(SIGURG, SIGURG)
PROBE_VALUE(SIGUSR1, SIGUSR1)
PROBE_VALUE(SIGUSR2, SIGUSR2)
PROBE_VALUE(SIGWINCH, SIGWINCH)
PROBE_VALUE(SA_NOCLDSTOP, SA_NOCLDSTOP)
PROBE_VALUE(SA_NOCLDWAIT, SA_NOCLDWAIT)
PROBE_VALUE(SA_NODEFER, SA_NODEFER)
PROBE_VALUE(SA_ONSTACK, SA_ONSTACK)
PROBE_VALUE(SA_RESETHAND, SA_RESETHAND)
PROBE_VALUE(SA_RESTART, SA_RESTART)
PROBE_VALUE(SA_SIGINFO, SA_SIGINFO)
PROBE_VALUE(SIG_BLOCK, SIG_BLOCK)
PROBE_VALUE(SIG_SETMASK, SIG_SETMASK)
PROBE_VALUE(SIG_UNBLOCK, SIG_UNBLOCK)
PROBE_VALUE(_NSIG, _NSIG)

/* threads and synchronization */
PROBE_SIZE(pthread_t, pthread_t)
PROBE_SIZE(pthread_attr_t, pthread_attr_t)
PROBE_SIZE(pthread_mutex_t, pthread_mutex_t)
PROBE_SIZE(pthread_mutexattr_t, pthread_mutexattr_t)
PROBE_SIZE(pthread_cond_t, pthread_cond_t)
PROBE_SIZE(pthread_condattr_t, pthread_condattr_t)
PROBE_SIZE(pthread_rwlock_t, pthread_rwlock_t)
PROBE_SIZE(pthread_rwlockattr_t, pthread_rwlockattr_t)
PROBE_SIZE(pthread_barrier_t, pthread_barrier_t)
PROBE_SIZE(pthread_barrierattr_t, pthread_barrierattr_t)
PROBE_SIZE(pthread_once_t, pthread_once_t)
PROBE_SIZE(pthread_key_t, pthread_key_t)
PROBE_SIZE(pthread_spinlock_t, pthread_spinlock_t)
PROBE_SIZE(sem_t, sem_t)
PROBE_VALUE(PTHREAD_MUTEX_NORMAL, PTHREAD_MUTEX_NORMAL)
PROBE_VALUE(PTHREAD_MUTEX_RECURSIVE, PTHREAD_MUTEX_RECURSIVE)
PROBE_VALUE(PTHREAD_MUTEX_ERRORCHECK, PTHREAD_MUTEX_ERRORCHECK)
PROBE_VALUE(PTHREAD_MUTEX_DEFAULT, PTHREAD_MUTEX_DEFAULT)
PROBE_VALUE(PTHREAD_CREATE_DETACHED, PTHREAD_CREATE_DETACHED)
PROBE_VALUE(PTHREAD_PROCESS_SHARED, PTHREAD_PROCESS_SHARED)
PROBE_SIZE(posix_spawnattr_t, posix_spawnattr_t)
PROBE_SIZE(posix_spawn_file_actions_t, posix_spawn_file_actions_t)
PROBE_SIZE(struct_sched_param, struct sched_param)
PROBE_SIZE(cpu_set_t, cpu_set_t)

/* sockets */
PROBE_SIZE(struct_sockaddr, struct sockaddr)
PROBE_SIZE(struct_sockaddr_in, struct sockaddr_in)
PROBE_SIZE(struct_sockaddr_in6, struct sockaddr_in6)
PROBE_SIZE(struct_sockaddr_un, struct sockaddr_un)
PROBE_SIZE(struct_sockaddr_storage, struct sockaddr_storage)
PROBE_SIZE(struct_msghdr, struct msghdr)
PROBE_OFFSET(msghdr_msg_iov, struct msghdr, msg_iov)
PROBE_OFFSET(msghdr_msg_control, struct msghdr, msg_control)
PROBE_OFFSET(msghdr_msg_flags, struct msghdr, msg_flags)
PROBE_SIZE(struct_cmsghdr, struct cmsghdr)
PROBE_SIZE(struct_iovec, struct iovec)
PROBE_SIZE(struct_linger, struct linger)
PROBE_SIZE(struct_ip_mreq, struct ip_mreq)
PROBE_SIZE(struct_ipv6_mreq, struct ipv6_mreq)
PROBE_SIZE(struct_addrinfo, struct addrinfo)
PROBE_OFFSET(addrinfo_ai_addrlen, struct addrinfo, ai_addrlen)
PROBE_OFFSET(addrinfo_ai_addr, struct addrinfo, ai_addr)
PROBE_OFFSET(addrinfo_ai_canonname, struct addrinfo, ai_canonname)
PROBE_OFFSET(addrinfo_ai_next, struct addrinfo, ai_next)
PROBE_SIZE(struct_hostent, struct hostent)
PROBE_OFFSET(hostent_h_addr_list, struct hostent, h_addr_list)
PROBE_SIZE(struct_servent, struct servent)
PROBE_SIZE(struct_ifreq, struct ifreq)
PROBE_SIZE(struct_if_nameindex, struct if_nameindex)
PROBE_SIZE(struct_ifaddrs, struct ifaddrs)
PROBE_SIZE(struct_pollfd, struct pollfd)
PROBE_VALUE(SOL_SOCKET, SOL_SOCKET)
PROBE_VALUE(SO_ERROR, SO_ERROR)
PROBE_VALUE(SO_KEEPALIVE, SO_KEEPALIVE)
PROBE_VALUE(SO_LINGER, SO_LINGER)
PROBE_VALUE(SO_PEERCRED, SO_PEERCRED)
PROBE_VALUE(SO_RCVBUF, SO_RCVBUF)
PROBE_VALUE(SO_RCVTIMEO, SO_RCVTIMEO)
PROBE_VALUE(SO_REUSEADDR, SO_REUSEADDR)
PROBE_VALUE(SO_REUSEPORT, SO_REUSEPORT)
PROBE_VALUE(SO_SNDBUF, SO_SNDBUF)
PROBE_VALUE(SO_SNDTIMEO, SO_SNDTIMEO)
PROBE_VALUE(SOCK_CLOEXEC, SOCK_CLOEXEC)
PROBE_VALUE(SOCK_NONBLOCK, SOCK_NONBLOCK)
PROBE_VALUE(SOMAXCONN, SOMAXCONN)
PROBE_VALUE(MSG_CMSG_CLOEXEC, MSG_CMSG_CLOEXEC)
PROBE_VALUE(MSG_DONTWAIT, MSG_DONTWAIT)
PROBE_VALUE(MSG_ERRQUEUE, MSG_ERRQUEUE)
PROBE_VALUE(MSG_NOSIGNAL, MSG_NOSIGNAL)
PROBE_VALUE(TCP_CORK, TCP_CORK)
PROBE_VALUE(TCP_KEEPCNT, TCP_KEEPCNT)
PROBE_VALUE(TCP_KEEPIDLE, TCP_KEEPIDLE)
PROBE_VALUE(TCP_KEEPINTVL, TCP_KEEPINTVL)
PROBE_VALUE(TCP_NODELAY, TCP_NODELAY)
PROBE_VALUE(AI_ADDRCONFIG, AI_ADDRCONFIG)
PROBE_VALUE(AI_CANONNAME, AI_CANONNAME)
PROBE_VALUE(AI_NUMERICHOST, AI_NUMERICHOST)
PROBE_VALUE(AI_NUMERICSERV, AI_NUMERICSERV)
PROBE_VALUE(AI_PASSIVE, AI_PASSIVE)
PROBE_VALUE(AI_V4MAPPED, AI_V4MAPPED)
PROBE_VALUE(EAI_AGAIN, EAI_AGAIN)
PROBE_VALUE(EAI_BADFLAGS, EAI_BADFLAGS)
PROBE_VALUE(EAI_FAIL, EAI_FAIL)
PROBE_VALUE(EAI_FAMILY, EAI_FAMILY)
PROBE_VALUE(EAI_MEMORY, EAI_MEMORY)
PROBE_VALUE(EAI_NONAME, EAI_NONAME)
PROBE_VALUE(EAI_OVERFLOW, EAI_OVERFLOW)
PROBE_VALUE(EAI_SERVICE, EAI_SERVICE)
PROBE_VALUE(EAI_SOCKTYPE, EAI_SOCKTYPE)
PROBE_VALUE(EAI_SYSTEM, EAI_SYSTEM)
PROBE_VALUE(NI_NAMEREQD, NI_NAMEREQD)
PROBE_VALUE(NI_NUMERICHOST, NI_NUMERICHOST)
#ifdef NI_MAXHOST
PROBE_VALUE(NI_MAXHOST, NI_MAXHOST)
#endif

/* fcntl and files */
PROBE_VALUE(O_APPEND, O_APPEND)
PROBE_VALUE(O_ASYNC, O_ASYNC)
PROBE_VALUE(O_CLOEXEC, O_CLOEXEC)
PROBE_VALUE(O_CREAT, O_CREAT)
PROBE_VALUE(O_DIRECT, O_DIRECT)
PROBE_VALUE(O_DIRECTORY, O_DIRECTORY)
PROBE_VALUE(O_DSYNC, O_DSYNC)
PROBE_VALUE(O_EXCL, O_EXCL)
#ifdef O_LARGEFILE
PROBE_VALUE(O_LARGEFILE, O_LARGEFILE)
#endif
PROBE_VALUE(O_NOATIME, O_NOATIME)
PROBE_VALUE(O_NOCTTY, O_NOCTTY)
PROBE_VALUE(O_NOFOLLOW, O_NOFOLLOW)
PROBE_VALUE(O_NONBLOCK, O_NONBLOCK)
PROBE_VALUE(O_PATH, O_PATH)
PROBE_VALUE(O_SYNC, O_SYNC)
PROBE_VALUE(O_TMPFILE, O_TMPFILE)
PROBE_VALUE(O_TRUNC, O_TRUNC)
PROBE_VALUE(F_DUPFD_CLOEXEC, F_DUPFD_CLOEXEC)
PROBE_VALUE(F_GETFD, F_GETFD)
PROBE_VALUE(F_GETFL, F_GETFL)
PROBE_VALUE(F_GETLK, F_GETLK)
PROBE_VALUE(F_SETFD, F_SETFD)
PROBE_VALUE(F_SETFL, F_SETFL)
PROBE_VALUE(F_SETLK, F_SETLK)
PROBE_VALUE(F_SETLKW, F_SETLKW)
#ifdef F_OFD_SETLK
PROBE_VALUE(F_OFD_SETLK, F_OFD_SETLK)
#endif
#ifdef F_ADD_SEALS
PROBE_VALUE(F_ADD_SEALS, F_ADD_SEALS)
#endif
#ifdef F_GETPIPE_SZ
PROBE_VALUE(F_GETPIPE_SZ, F_GETPIPE_SZ)
#endif
PROBE_VALUE(AT_FDCWD, AT_FDCWD)
PROBE_VALUE(AT_EMPTY_PATH, AT_EMPTY_PATH)
PROBE_VALUE(AT_REMOVEDIR, AT_REMOVEDIR)
PROBE_VALUE(AT_SYMLINK_FOLLOW, AT_SYMLINK_FOLLOW)
PROBE_VALUE(AT_SYMLINK_NOFOLLOW, AT_SYMLINK_NOFOLLOW)
PROBE_VALUE(SEEK_DATA, SEEK_DATA)
PROBE_VALUE(SEEK_HOLE, SEEK_HOLE)
PROBE_VALUE(DT_BLK, DT_BLK)
PROBE_VALUE(DT_CHR, DT_CHR)
PROBE_VALUE(DT_DIR, DT_DIR)
PROBE_VALUE(DT_FIFO, DT_FIFO)
PROBE_VALUE(DT_LNK, DT_LNK)
PROBE_VALUE(DT_REG, DT_REG)
PROBE_VALUE(DT_SOCK, DT_SOCK)
PROBE_VALUE(LOCK_EX, LOCK_EX)
PROBE_VALUE(LOCK_NB, LOCK_NB)
PROBE_VALUE(LOCK_SH, LOCK_SH)
PROBE_VALUE(LOCK_UN, LOCK_UN)
PROBE_VALUE(UTIME_NOW, UTIME_NOW)
PROBE_VALUE(UTIME_OMIT, UTIME_OMIT)
PROBE_VALUE(POSIX_FADV_DONTNEED, POSIX_FADV_DONTNEED)
PROBE_VALUE(POSIX_FADV_RANDOM, POSIX_FADV_RANDOM)

/* memory */
PROBE_VALUE(MAP_ANONYMOUS, MAP_ANONYMOUS)
PROBE_VALUE(MAP_FIXED, MAP_FIXED)
#ifdef MAP_FIXED_NOREPLACE
PROBE_VALUE(MAP_FIXED_NOREPLACE, MAP_FIXED_NOREPLACE)
#endif
PROBE_VALUE(MAP_GROWSDOWN, MAP_GROWSDOWN)
PROBE_VALUE(MAP_HUGETLB, MAP_HUGETLB)
PROBE_VALUE(MAP_LOCKED, MAP_LOCKED)
PROBE_VALUE(MAP_NORESERVE, MAP_NORESERVE)
PROBE_VALUE(MAP_POPULATE, MAP_POPULATE)
PROBE_VALUE(MAP_STACK, MAP_STACK)
PROBE_VALUE(MADV_DONTNEED, MADV_DONTNEED)
PROBE_VALUE(MADV_FREE, MADV_FREE)
PROBE_VALUE(MREMAP_MAYMOVE, MREMAP_MAYMOVE)
PROBE_VALUE(MS_ASYNC, MS_ASYNC)
PROBE_VALUE(MS_INVALIDATE, MS_INVALIDATE)
PROBE_VALUE(MS_SYNC, MS_SYNC)

/* processes, time, resources */
PROBE_SIZE(struct_timespec, struct timespec)
PROBE_SIZE(struct_timeval, struct timeval)
PROBE_SIZE(struct_itimerval, struct itimerval)
PROBE_SIZE(struct_itimerspec, struct itimerspec)
PROBE_SIZE(struct_tm, struct tm)
PROBE_OFFSET(tm_tm_year, struct tm, tm_year)
PROBE_OFFSET(tm_tm_gmtoff, struct tm, tm_gmtoff)
PROBE_SIZE(struct_rusage, struct rusage)
PROBE_OFFSET(rusage_ru_maxrss, struct rusage, ru_maxrss)
PROBE_SIZE(struct_rlimit, struct rlimit)
PROBE_SIZE(struct_tms, struct tms)
PROBE_VALUE(CLOCK_BOOTTIME, CLOCK_BOOTTIME)
PROBE_VALUE(CLOCK_MONOTONIC, CLOCK_MONOTONIC)
PROBE_VALUE(CLOCK_MONOTONIC_COARSE, CLOCK_MONOTONIC_COARSE)
PROBE_VALUE(CLOCK_MONOTONIC_RAW, CLOCK_MONOTONIC_RAW)
PROBE_VALUE(CLOCK_PROCESS_CPUTIME_ID, CLOCK_PROCESS_CPUTIME_ID)
PROBE_VALUE(CLOCK_REALTIME_COARSE, CLOCK_REALTIME_COARSE)
PROBE_VALUE(CLOCK_TAI, CLOCK_TAI)
PROBE_VALUE(CLOCK_THREAD_CPUTIME_ID, CLOCK_THREAD_CPUTIME_ID)
PROBE_VALUE(TIMER_ABSTIME, TIMER_ABSTIME)
PROBE_VALUE(RLIMIT_AS, RLIMIT_AS)
PROBE_VALUE(RLIMIT_CORE, RLIMIT_CORE)
PROBE_VALUE(RLIMIT_MEMLOCK, RLIMIT_MEMLOCK)
PROBE_VALUE(RLIMIT_NOFILE, RLIMIT_NOFILE)
PROBE_VALUE(RLIMIT_NPROC, RLIMIT_NPROC)
PROBE_VALUE(RLIMIT_RSS, RLIMIT_RSS)
PROBE_VALUE(RLIMIT_STACK, RLIMIT_STACK)
PROBE_VALUE(WCONTINUED, WCONTINUED)
PROBE_VALUE(WNOHANG, WNOHANG)
PROBE_VALUE(WUNTRACED, WUNTRACED)
PROBE_VALUE(EFD_CLOEXEC, EFD_CLOEXEC)
PROBE_VALUE(EFD_NONBLOCK, EFD_NONBLOCK)
PROBE_VALUE(EFD_SEMAPHORE, EFD_SEMAPHORE)
PROBE_VALUE(TFD_CLOEXEC, TFD_CLOEXEC)
PROBE_VALUE(TFD_NONBLOCK, TFD_NONBLOCK)
PROBE_VALUE(TFD_TIMER_ABSTIME, TFD_TIMER_ABSTIME)
PROBE_VALUE(IN_CLOEXEC, IN_CLOEXEC)
PROBE_VALUE(IN_NONBLOCK, IN_NONBLOCK)
PROBE_SIZE(struct_inotify_event, struct inotify_event)
PROBE_SIZE(struct_signalfd_siginfo, struct signalfd_siginfo)
PROBE_SIZE(struct_epoll_event, struct epoll_event)
PROBE_OFFSET(epoll_event_data, struct epoll_event, data)
PROBE_VALUE(EPOLLET, EPOLLET)
PROBE_VALUE(EPOLLEXCLUSIVE, EPOLLEXCLUSIVE)
PROBE_VALUE(EPOLLONESHOT, EPOLLONESHOT)
PROBE_VALUE(EPOLLRDHUP, EPOLLRDHUP)
PROBE_VALUE(EPOLL_CLOEXEC, EPOLL_CLOEXEC)
PROBE_VALUE(POLLRDHUP, POLLRDHUP)

/* sysv ipc */
PROBE_SIZE(struct_ipc_perm, struct ipc_perm)
PROBE_SIZE(struct_shmid_ds, struct shmid_ds)
PROBE_SIZE(struct_semid_ds, struct semid_ds)
PROBE_SIZE(struct_msqid_ds, struct msqid_ds)
PROBE_SIZE(struct_sembuf, struct sembuf)
PROBE_VALUE(IPC_CREAT, IPC_CREAT)
PROBE_VALUE(IPC_EXCL, IPC_EXCL)
PROBE_VALUE(IPC_NOWAIT, IPC_NOWAIT)
PROBE_VALUE(IPC_RMID, IPC_RMID)
PROBE_VALUE(IPC_SET, IPC_SET)
PROBE_VALUE(IPC_STAT, IPC_STAT)
PROBE_VALUE(SEM_UNDO, SEM_UNDO)
PROBE_SIZE(struct_mq_attr, struct mq_attr)

/* terminal */
PROBE_SIZE(struct_termios, struct termios)
PROBE_OFFSET(termios_c_lflag, struct termios, c_lflag)
PROBE_OFFSET(termios_c_cc, struct termios, c_cc)
PROBE_SIZE(struct_winsize, struct winsize)
PROBE_VALUE(NCCS, NCCS)
PROBE_VALUE(TCSADRAIN, TCSADRAIN)
PROBE_VALUE(TCSAFLUSH, TCSAFLUSH)
PROBE_VALUE(TCSANOW, TCSANOW)

/* users, accounting */
PROBE_SIZE(struct_passwd, struct passwd)
PROBE_OFFSET(passwd_pw_uid, struct passwd, pw_uid)
PROBE_OFFSET(passwd_pw_dir, struct passwd, pw_dir)
PROBE_OFFSET(passwd_pw_shell, struct passwd, pw_shell)
PROBE_SIZE(struct_group, struct group)
PROBE_OFFSET(group_gr_gid, struct group, gr_gid)
PROBE_OFFSET(group_gr_mem, struct group, gr_mem)
PROBE_SIZE(struct_utmpx, struct utmpx)
PROBE_OFFSET(utmpx_ut_type, struct utmpx, ut_type)
PROBE_OFFSET(utmpx_ut_line, struct utmpx, ut_line)
PROBE_OFFSET(utmpx_ut_user, struct utmpx, ut_user)
PROBE_OFFSET(utmpx_ut_host, struct utmpx, ut_host)
PROBE_OFFSET(utmpx_ut_tv, struct utmpx, ut_tv)

/* locale, langinfo */
PROBE_VALUE(LC_ALL, LC_ALL)
PROBE_VALUE(LC_COLLATE, LC_COLLATE)
PROBE_VALUE(LC_CTYPE, LC_CTYPE)
PROBE_VALUE(LC_MESSAGES, LC_MESSAGES)
PROBE_VALUE(LC_MONETARY, LC_MONETARY)
PROBE_VALUE(LC_NUMERIC, LC_NUMERIC)
PROBE_VALUE(LC_TIME, LC_TIME)
PROBE_SIZE(struct_lconv, struct lconv)
PROBE_VALUE(ABDAY_1, ABDAY_1)
PROBE_VALUE(CODESET, CODESET)
PROBE_VALUE(D_T_FMT, D_T_FMT)
PROBE_VALUE(RADIXCHAR, RADIXCHAR)
PROBE_VALUE(YESEXPR, YESEXPR)

/* dlfcn */
PROBE_SIZE(Dl_info, Dl_info)
PROBE_VALUE(RTLD_GLOBAL, RTLD_GLOBAL)
PROBE_VALUE(RTLD_LAZY, RTLD_LAZY)
PROBE_VALUE(RTLD_LOCAL, RTLD_LOCAL)
PROBE_VALUE(RTLD_NODELETE, RTLD_NODELETE)
PROBE_VALUE(RTLD_NOLOAD, RTLD_NOLOAD)
PROBE_VALUE(RTLD_NOW, RTLD_NOW)

/* sysconf/pathconf indices and limits */
PROBE_VALUE(_SC_ARG_MAX, _SC_ARG_MAX)
PROBE_VALUE(_SC_CLK_TCK, _SC_CLK_TCK)
PROBE_VALUE(_SC_GETPW_R_SIZE_MAX, _SC_GETPW_R_SIZE_MAX)
PROBE_VALUE(_SC_IOV_MAX, _SC_IOV_MAX)
PROBE_VALUE(_SC_NPROCESSORS_CONF, _SC_NPROCESSORS_CONF)
PROBE_VALUE(_SC_NPROCESSORS_ONLN, _SC_NPROCESSORS_ONLN)
PROBE_VALUE(_SC_OPEN_MAX, _SC_OPEN_MAX)
PROBE_VALUE(_SC_PAGESIZE, _SC_PAGESIZE)
PROBE_VALUE(_SC_PHYS_PAGES, _SC_PHYS_PAGES)
PROBE_VALUE(_SC_THREAD_STACK_MIN, _SC_THREAD_STACK_MIN)
PROBE_VALUE(_PC_NAME_MAX, _PC_NAME_MAX)
PROBE_VALUE(_PC_PATH_MAX, _PC_PATH_MAX)
PROBE_VALUE(HOST_NAME_MAX, HOST_NAME_MAX)
PROBE_VALUE(IOV_MAX, IOV_MAX)
PROBE_VALUE(LOGIN_NAME_MAX, LOGIN_NAME_MAX)
PROBE_VALUE(NAME_MAX, NAME_MAX)
PROBE_VALUE(PATH_MAX, PATH_MAX)
PROBE_VALUE(PIPE_BUF, PIPE_BUF)
PROBE_VALUE(TTY_NAME_MAX, TTY_NAME_MAX)

/* errno spot checks */
PROBE_VALUE(EAGAIN, EAGAIN)
PROBE_VALUE(EDEADLOCK, EDEADLOCK)
PROBE_VALUE(ENOTSUP, ENOTSUP)
PROBE_VALUE(EWOULDBLOCK, EWOULDBLOCK)

/* getopt */
PROBE_SIZE(struct_option, struct option)
