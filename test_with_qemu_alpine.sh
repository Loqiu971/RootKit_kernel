#!/usr/bin/env bash

###################
#    This script generates kernel and file system with docker and alpine to test 6r00tkit and start the it with qemu
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
export DISK="disk.img"
export ROOTFS="/tmp/my-rootfs"
export DOCKER_ROOTFS="/my-rootfs"

export PASSWD="toor"

export GROOTKIT_DIR="${PWD}/6r00tkit"

export KERNEL_VERSION="6.6.8"
export KERNEL="${PWD}/linux-${KERNEL_VERSION}"

truncate -s 450M "${DISK}"
/sbin/parted -s "./${DISK}" mktable msdos
/sbin/parted -s "./${DISK}" mkpart primary ext4 1 "100%"
/sbin/parted -s "./${DISK}" set 1 boot on

sudo losetup -Pf "${DISK}"
export DEV="$(losetup -l | awk 'NR==2{print $1}')"

sudo mkfs.ext4 "${DEV}p1"
mkdir -p "${ROOTFS}"
sudo mount "${DEV}p1" "${ROOTFS}"

sudo docker run -itd --name alpine-6r00tkit -v "${ROOTFS}:${DOCKER_ROOTFS}" alpine
sudo docker exec alpine-6r00tkit /bin/sh -c "apk add openrc util-linux build-base"
sudo docker exec alpine-6r00tkit /bin/sh -c "ln -s agetty /etc/init.d/agetty.ttyS0;echo ttyS0 > /etc/securetty;rc-update add agetty.ttyS0 default;rc-update add root default"
sudo docker exec alpine-6r00tkit /bin/sh -c "passwd <<END
${PASSWD}
${PASSWD}
END"
sudo docker exec alpine-6r00tkit /bin/sh -c 'rc-update add devfs boot;rc-update add procfs boot;rc-update add sysfs boot'
# sudo docker exec /bin/bash -c "tar c /{bin,etc,lib,root,sbin,usr} | tar x -C '${DOCKER_ROOTFS}'"
# sudo docker exec /bin/bash -c "mkdir '${DOCKER_ROOTFS}/'{dev,proc,run,sys,var}"
sudo docker exec alpine-6r00tkit /bin/sh -c "for d in bin etc lib root sbin usr; do tar c \"/\$d\" | tar x -C ${DOCKER_ROOTFS}; done"
sudo docker exec alpine-6r00tkit /bin/sh -c "for dir in dev proc run sys var; do mkdir \"${DOCKER_ROOTFS}/\${dir}\"; done"
sudo docker rm -f alpine-6r00tkit

sudo echo "Welcome on Alpine Linux to test 6r00tkit with kernel version ${KERNEL_VERSION} !" >> "${ROOTFS}/etc/issue"
sudo mkdir -p "${ROOTFS}/boot/grub"
sudo cp "${KERNEL}/arch/x86/boot/bzImage" "${ROOTFS}/boot/vmlinuz"
sudo cat > "${ROOTFS}/boot/grub/grub.cfg" <<END
serial
terminal_output serial
set root=(hd0,1)
menuentry "Linux6r00tkit" { linux /boot/vmlinuz root=/dev/sda1 console=ttyS0 }
END
sudo grub-install --directory=/usr/lib/grub/i386-pc --boot-directory="${ROOTFS}/boot" "${DEV}"

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

sudo cp "${GROOTKIT_DIR}/6r00tkit.ko" "${ROOTFS}/root/"

sudo umount "${ROOTFS}"
sudo losetup -d "${DEV}"

qemu-system-x86_64 -hda "${DISK}" -nographic