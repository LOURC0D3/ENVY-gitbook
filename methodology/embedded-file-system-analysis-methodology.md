# Embedded File System Analysis Methodology

## 1. Overview

***

This document is from the BoB 12th NVR Vulnerability Analysis project team.I will explain the methodology developed by ENVY (Kim Chang-in, Pak Myeong-hun, Shin Myung-jin, Yang Kang-min, and Lee Yoo-kyung).

It was created based on the ability to read and write shellscripts, so it is recommended for those who are familiar with the description.

### 1.1. **necessity**

In order to proceed with the vulnerability analysis of embedded devices, it is essential to analyze the file system of the device in detail. Accordingly, effective results can be obtained by systematically analyzing the file system using this methodology and then performing vulnerability analysis based on this information.

### 1.2. /etc/inittab

The file is a file that sets the boot method at Linux startup, and after acquiring shell, you must review the file to see which scripts or binaries are executed.

```bash
::sysinit:/etc/init.d/rcS

::respawn:-/bin/sh

# Stuff to do when restarting the init process
::restart:/sbin/init

# Stuff to do before rebooting
::ctrlaltdel:/sbin/reboot
::shutdown:/bin/umount -a -r
::shutdown:/sbin/swapoff -a
```

## 2. Analysis of startup scripts

***

### 2.1. init script

By analyzing the script, you can understand which services are enabled and how embedded devices are executed. In most cases, scripts described in `/etc/inittab` are executed to activate various functions.

In the process of analyzing an embedded file system, it is easier to analyze if you review the script and organize the functions to be executed.

The functions deemed particularly important will be explained from 2.2.

### 2.2. Activation Services Analysis

Analysis of services that are used in a set device should be prioritized.

Various scripts operate through init script execution, and the last binary that is usually executed plays a role in activating the embedded device's service.

Therefore, commands such as netstat, lsof, and ps should be used to analyze which files the binary references before determining which processes are running. Reversing of binaries should be performed as necessary to analyze the activated services.

### 2.3. mount confirmation

In addition to service activation analysis, it is important to check the devices mounted from the embedded devices. By checking the information as follows, it is possible to identify devices that are mounted read-only and devices that can be read and written.

```bash
~ # mount
rootfs on / type rootfs (rw)
none on /dev type devtmpfs (rw,relatime,size=316408k,nr_inodes=79102,mode=755)
proc on /proc type proc (rw,relatime)
/dev/mtdblock3 on /mnt type squashfs (ro,relatime)
/dev/loop0 on / type squashfs (ro,relatime)
proc on /proc type proc (rw,relatime)
sysfs on /sys type sysfs (rw,relatime)
tmpfs on /root type tmpfs (rw,relatime)
none on /dev type devtmpfs (rw,relatime,size=316408k,nr_inodes=79102,mode=755)
devpts on /dev/pts type devpts (rw,relatime,mode=600)
none on /sys/kernel/debug type debugfs (rw,relatime)
/dev/mtdblock8 on /mnt/ext_usr type squashfs (ro,relatime)
/dev/mtdblock5 on /mnt/web type squashfs (ro,relatime)
/dev/mtdblock4 on /mnt/custom type squashfs (ro,relatime)
/dev/mtdblock6 on /mnt/logo type cramfs (ro,relatime)
/dev/mem on /var type ramfs (rw,relatime)
/dev/ubi0_0 on /mnt/mtd type ubifs (rw,relatime)
```

In mounting the `/dev/mtdblock` device, files related to setting are frequently located in order to acquire flash memory and hard disk data. There is a high possibility that basic settings, encryption keys, logs, etc. remain in the folder.

In addition, if mounted read-only, there is a high possibility that there are files to activate the service on embedded devices such as web services.

Therefore, it will be very helpful to analyze embedded file systems if you carefully examine the device and folder paths that are mounted during initscript analysis.

### 2.4. W**atchdog analysis**

#### 2.5.1. Overview

watchdog is a function of monitoring the occurrence of specified operations at specific time intervals on Iranian embedded devices.

In general, watchdogs interact with binaries that perform services and periodically transmit signals to a device called `/dev/watchdog`. Such a signal indicates that the device is operating normally.However, if this signal is not received for a certain period of time, the device considers that a problem has occurred and is forced to restart.

```bash
~~~~~~~~~~~~pid (492) will exit!
~~~~~~~~~~~~FN:[fn_master_status]
~~~~~~~~~~~~iRet [-88][Session Handle Err!!]
[165249.722559] [HKBSP][hik_wdt hik_wdt.1]hik-wdt:hikwdt_isr. I'm so Sorry (>_<)…
[165249.730063] [HKBSP][hik_wdt hik_wdt.1]hik-wdt:hikwdt_isr. last_feedwdt:4311458247(jiffies64:4311461694,timeout:25)
```

Therefore, if the binary is debugged for vulnerability analysis, the device may automatically restart after a certain period of time if the signal is not transmitted to the watchdog device in a timely manner.

#### 2.5.2. Watchdog analysis

The `/dev/watchdog` device is the core of the watchdog and can be checked for interaction with the watchdog by checking the PID of an activated binary and then checking whether it is referenced in the `/proc/<PID>/fd` folder.

```bash
[root@dvrdvs fd] # pwd
/proc/421/fd
[root@dvrdvs fd] # ls -l
lrwx------    1 root     root            64 Nov 19 14:54 36 -> socket:[3139]
lrwx------    1 root     root            64 Nov 19 14:54 37 -> socket:[3140]
lrwx------    1 root     root            64 Nov 19 14:54 38 -> socket:[3141]
lrwx------    1 root     root            64 Nov 19 14:54 39 -> /monitorMsg
l-wx------    1 root     root            64 Nov 19 14:54 4 -> /dev/watchdog
lr-x------    1 root     root            64 Nov 19 14:54 40 -> /home/app/exec/ptzCfg.bin
lrwx------    1 root     root            64 Nov 19 14:54 41 -> /ptz-mq
```

If you proceed with debugging based on this information, the watchdog may cause a reboot. Therefore, when analyzing initscripts, it is necessary to check how watchdog runs and prevent reboots through binary patches or watchdog feeding.

In general, watchdogs are executed by setting a timeout in the library or kernel module and set through the ioctl function. Therefore, it is necessary to patch libraries and kernel modules to adjust the timeout or to prevent reboots by performing watchdog feeding through shellscript.

```bash
#!/bin/sh
while true; do
        echo -n "C" > /dev/watchdog
        sleep 1
done
```
