#!/usr/bin/env bash

###################
#    This script generates kernel and NFS with busybox and 6r00tkit and start the it with qemu
#    Copyright (C) 2023  Maurice Lambert

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
###################

export BUILDS="${PWD}"
export BUSYBOX_BUILD="${PWD}/busybox"
export INITRAMFS_BUILD="${PWD}/initramfs"

export GROOTKIT_DIR="${PWD}/6r00tkit"

export KERNEL_VERSION="6.6.8"
export KERNEL="${PWD}/linux-${KERNEL_VERSION}"
export NFS_DIR="/nfs"

if [ ! -d "${BUSYBOX_BUILD}" ]; then
    git clone git://git.busybox.net/busybox
fi

if [ ! -d "${BUSYBOX_BUILD}/_install" ]; then
    cd "${BUSYBOX_BUILD}"
    make defconfig
    make
    make install
    cd "${BUILDS}"
fi

if [ ! -d "${BUILDS}/my_init_loop" ]; then
    mkdir "${BUILDS}/my_init_loop"
fi

if [ ! -f "${BUILDS}/my_init_loop/main.c" ]; then
    cat > "${BUILDS}/my_init_loop/main.c" <<END
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

int main() {
    printf("MY INIT\n");
    while (1) {
        pid_t pid = fork();
        int status = 0;
        if (pid) {
            waitpid(pid, &status, 0);
            printf("Respawn\n");
            pid = 0;
        } else {
            char *tab[] = {"/bin/sh", NULL};
            execv("/bin/sh", tab);
        }
    }
}
END
fi

mkdir -p "${INITRAMFS_BUILD}"
cd "${INITRAMFS_BUILD}"
mkdir -p root bin sbin etc proc sys dev usr/bin usr/sbin
cd "${BUILDS}"

cp -a "${BUSYBOX_BUILD}/_install/"* "${INITRAMFS_BUILD}"
gcc "${BUILDS}/my_init_loop/main.c" -o "${INITRAMFS_BUILD}/init_loop"

mkdir -p "${INITRAMFS_BUILD}/lib/x86_64-linux-gnu/"
mkdir -p "${INITRAMFS_BUILD}/lib64"
cp /lib/x86_64-linux-gnu/libc.so.6 "${INITRAMFS_BUILD}/lib/x86_64-linux-gnu/"
cp /lib/x86_64-linux-gnu/libm.so.6 ${INITRAMFS_BUILD}/lib/x86_64-linux-gnu/
cp /lib/x86_64-linux-gnu/libresolv.so.2 "${INITRAMFS_BUILD}/lib/x86_64-linux-gnu/"
cp /lib64/ld-linux-x86-64.so.2 "${INITRAMFS_BUILD}/lib64"

cat > "${INITRAMFS_BUILD}/init" <<END
#!/bin/sh
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev
cat <<!
Boot took $(cut -d' ' -f1 /proc/uptime) seconds
!
/init_loop
END
chmod +x "${INITRAMFS_BUILD}/init"

sudo apt install libelf-dev

if [ ! -d "${KERNEL}" ]; then
    wget "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${KERNEL_VERSION}.tar.xz"
    tar -xvJf "linux-${KERNEL_VERSION}.tar.xz"
fi

if [ ! -f "${KERNEL}/arch/x86/boot/bzImage" ]; then
    cd "${KERNEL}"
    make prepare
    make defconfig
    make
    cd "${BUILDS}"
fi

if [ ! -d "${GROOTKIT_DIR}" ]; then
    git clone https://github.com/mauricelambert/6r00tkit.git
fi

if [ ! -f "${GROOTKIT_DIR}/6r00tkit.ko" ]; then
    cd "${GROOTKIT_DIR}"
    make -C "${KERNEL}" M=$(pwd) modules
    cd "${BUILDS}"
fi

cp "${GROOTKIT_DIR}/6r00tkit.ko" "${INITRAMFS_BUILD}/root/"

cd "${INITRAMFS_BUILD}"
find . -print0 | cpio --null -ov --format=newc | gzip -9 > "${INITRAMFS_BUILD}.cpio.gz"
cd "${BUILDS}"

sudo apt install nfs-kernel-server
sudo mkdir "${NFS_DIR}"
sudo mount --bind "${INITRAMFS_BUILD}" "${NFS_DIR}/"
sudo echo "${NFS_DIR}         *(rw,insecure,sync,no_subtree_check,crossmnt,fsid=0)" > /etc/exports
sudo systemctl start nfs-kernel-server.service

qemu-system-x86_64 -kernel "${KERNEL}/arch/x86/boot/bzImage" -append "init=/init root=/dev/nfs nfsroot=10.0.2.2:${NFS_DIR},vers=3 rw ip=10.0.2.15::10.0.2.1:255.255.255.0 console=ttyS0 raid=noautodetect noapic" -nographic