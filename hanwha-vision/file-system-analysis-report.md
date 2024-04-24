# File System Analysis Report

## 1. Overview

***

This document is a report described by Team.ENVY (Kim Chan-in, Park Myung-hoon, Shin Myung-jin, Yang Gang-min, and Lee Yoo-kyung) who carried out the BoB 12th NVR Vulnability Analysis project.

### 1.1. Necessity

File system analysis is essential to perform embedded vulnerability analysis. It is an essential step to identify and deactivate a watchdog for debugging, which activates a service for performing vulnerability analysis. Therefore, this document describes the contents of file system analysis to perform vulnerability analysis.

### 1.2. /etc/inittab

The contents of "/etc/initab" are as follows. First of all, when the NVR is booted, the "/etc/init.d/rcS" file will be executed first. In addition, it can be seen that the "/etc/scripts/SsShutdown.sh " file is executed when the NVR is terminated.

```bash
::sysinit:/etc/init.d/rcS

# Example of how to put a getty on a serial line (for a terminal)
::respawn:/sbin/getty -L ttyS0 115200 vt100

# Stuff to do when restarting the init process
::restart:/sbin/init

# Stuff to do before rebooting
::ctrlaltdel:/sbin/reboot
::shutdown:/etc/scripts/SsShutdown.sh
```

## 2. Analyzing Boot Scripts

***

### 2.1. init script

#### 2.1.1. /etc/init.d/rcS

With the "/bin/mount -a" command, mount the device based on the content in "/etc/mtab", set the environment variable and run all scripts in the "/etc/init.d" directory.

#### 2.1.2. /etc/init.d/S00hostname

Use the hostname command to set the hostname.

#### 2.1.3. /etc/init.d/S01devs

If there is no directory used for the NVR service, create and mount it.

#### 2.1.4. /etc/init.d/S02udevd

Run the udevd command to activate the udev service.

#### 2.1.5. /etc/init.d/S03syslogd

Run the /sbin/syslogd command to activate the syslog service.

#### 2.1.6. /etc/init.d/S04klogd

Run the /sbin/klogd command to record the kernel log.

#### 2.1.7. /etc/init.d/S05sysctl

Run the sysctl command based on the contents of the /etc/sysctl.conf configuration file.

#### 2.1.8. /etc/init.d/S06network

Configure the local network interface using the ifconfig, route command.

#### 2.1.9. /etc/init.d/S82mount

The mount command is used to mount the flash memory, which is an mtdblock device, and the flash memory that is mounted in the app directory is only read-only.

#### 2.1.10. /etc/init.d/S83dvr\_main

Run the startup.sh script.

#### 2.1.11. /root/startup.sh

After going through processes such as loading the driver module, initializing storage, and initializing the network related to the NVR service, /bin/scheduler, /root/daemon binary is executed.

### 2.2. Activation service analysis

#### 2.2.1. daemon

This binary is the last binary to run in init script. When the binary is reversed, the dvr\_main binary is executed through the fork function, and when the child process ends, the state is imported using a waitpid system call and different tasks are performed based on the state.

```c
DAT_000250e4 = fork();
  if (DAT_000250e4 == 0) {
    memset(dvr_main_path,0,0x80);
    snprintf(dvr_main_path,0x80,"%s/dvr_main","/root",uVar16,pcVar3,iVar4,pcVar1);
    memset(acStack_52c,0,0x80);
    snprintf(acStack_52c,0x80,"%s",&DAT_000138b8);
    memset(acStack_4ac,0,0x80);
    snprintf(acStack_4ac,0x80,"%d",DAT_000250e0);
    memset(acStack_22c,0,0x200);
    snprintf(acStack_22c,0x200,"[DAEMON] %s:%d %s %s %s\n","dvr_main_thread_body",0x331,
             dvr_main_path,acStack_52c,acStack_4ac);
    iVar4 = 5;
    FUN_0001162c(acStack_22c);
    do {
      iVar13 = execl(dvr_main_path,dvr_main_path,acStack_52c,acStack_4ac,&DAT_000138e8,"console.log",0);
...
```

#### 2.2.2. dvr\_main

Analysis using the lsof command yields the following results.

```bash
dvr_main   865 1024 root  105u     unix 0x9ed9b9c0       0t0      8785 /tmp/ARBSocket_Main type=STREAM
dvr_main   865 1024 root  106u     unix 0xaca1f9c0       0t0     10202 /tmp/upgrade_sock type=STREAM
dvr_main   865 1024 root  107u     unix 0x99824000       0t0     11267 /tmp/SunapiSocket type=STREAM
dvr_main   865 1024 root  109u     unix 0xa027cdc0       0t0     10302 /tmp/OnvifSocket type=STREAM
dvr_main   865 1024 root  110u     unix 0xa027cb00       0t0     10300 /tmp/rtsp_socket type=STREAM
```

Since onvif and rtsp sockets are used and SunapiSocket sockets are also used, it can be determined that the binary activates the service.

#### 2.2.3. Web Service

Finally, we analyzed the process running through the ps command.

```bash
2669  2668  2668 ?        00:00:00   lighttpd
2670  2670  2670 ?        00:00:00     php-cgi
2731  2670  2670 ?        00:00:00       php-cgi
2671  2671  2671 ?        00:00:00     php-cgi
2730  2671  2671 ?        00:00:00       php-cgi
2672  2672  2672 ?        00:00:00     php-cgi
2733  2672  2672 ?        00:00:00       php-cgi
2673  2673  2673 ?        00:00:00     php-cgi
2732  2673  2673 ?        00:00:00       php-cgi
2675  2668  2668 ?        00:00:00     attributes.cgi
2679  2668  2668 ?        00:00:00     eventstatus.cgi
2707  2668  2668 ?        00:00:00     system.cgi
2710  2668  2668 ?        00:00:00     network.cgi
2729  2668  2668 ?        00:00:00     media.cgi
2754  2668  2668 ?        00:00:00     security.cgi
2767  2668  2668 ?        00:00:00     video.cgi
2784  2668  2668 ?        00:00:00     transfer.cgi
2799  2668  2668 ?        00:00:00     image.cgi
2823  2668  2668 ?        00:00:00     eventactions.cg
2843  2668  2668 ?        00:00:00     eventsources.cg
2848  2668  2668 ?        00:00:00     io.cgi
2866  2668  2668 ?        00:00:00     recording.cgi
2880  2668  2668 ?        00:00:00     ptzcontrol.cgi
2900  2668  2668 ?        00:00:00     ptzconfig.cgi
2915  2668  2668 ?        00:00:00     bypass.cgi
2929  2668  2668 ?        00:00:00     display.cgi
2952  2668  2668 ?        00:00:00     pw_init.cgi
2960  2668  2668 ?        00:00:00     eventrules.cgi
2961  2668  2668 ?        00:00:00     ai.cgi
2975  2668  2668 ?        00:00:00     factory.cgi
2998  2668  2668 ?        00:00:00     debug.cgi
```

Through the lighttpd binary, it can be seen that the web service is operating as a cgi binary.

```bash
sh-4.3# lsof -p 2848
COMMAND  PID USER   FD   TYPE     DEVICE SIZE/OFF  NODE NAME
io.cgi  2848 root  cwd    DIR      31,12        0   680 /app/root/webviewer/stw-cgi
io.cgi  2848 root  rtd    DIR        0,1        0     1 /
io.cgi  2848 root  txt    REG      31,12    87976  2762 /app/root/webviewer/stw-cgi/io.cgi
...
io.cgi  2848 root    0u  unix 0xa027f700      0t0 10487 /tmp/io-fastcgi.socket-0 type=STREAM
io.cgi  2848 root    3u  unix 0x99826940      0t0 11428 /tmp/io-fastcgi.socket-0 type=STREAM
```

Additionally, as a result of executing the lsof command on the operating cgi, it may be confirmed that the cgi binary also refers to the socket file.

### 2.3. Check mount

After the boot is complete, the following results can be obtained by executing the mount command.

```bash
sh-4.3# mount
rootfs on / type rootfs (rw)
proc on /proc type proc (rw,relatime)
sysfs on /sys type sysfs (rw,relatime)
tmpfs on /dev type tmpfs (rw,relatime,size=74752k)
tmpfs on /tmp type tmpfs (rw,relatime)
tmpfs on /pam type tmpfs (rw,relatime,size=163840k)
tmpfs on /media type tmpfs (rw,relatime,size=32768k)
tmpfs on /debug type tmpfs (rw,relatime,size=5120k)
devpts on /dev/pts type devpts (rw,relatime,mode=600,ptmxmode=000)
none on /dev/shm type tmpfs (rw,relatime,size=10240k)
/dev/mtdblock9 on /system type jffs2 (rw,relatime)
/dev/mtdblock12 on /app type jffs2 (ro,relatime)
/dev/sda1 on /mnt/sda1 type xfs (rw,relatime,attr2,inode64,noquota)
/dev/sda2 on /mnt/sda2 type xfs (rw,relatime,attr2,inode64,noquota)
/dev/sda3 on /mnt/sda3 type xfs (rw,relatime,attr2,inode64,noquota)
/dev/sda4 on /mnt/sda4 type xfs (rw,relatime,attr2,inode64,noquota)
```

As confirmed in the init script, the /app directory was counted as read-only, and web service-related files existed in the folder. In addition, it was confirmed that the sda device loaded with xfs was a hard disk.

It was confirmed that log-related data were present in the /mnt/sda1 directory as follows.

```bash
sh-4.3# pwd
/mnt/sda1/MetaData/log
sh-4.3# ls
HDDStatus.log               console_20231026014525.log
access.log                  console_20231027050004.log
backup_log_vss.db2          console_20231027210411.log
console.log                 console_20231029070032.log
console.log_NetworkError    console_20231031180103.log
console_20230917145053.log  cslog.log
console_20230918011457.log  easy_server-fri.log
console_20230918070311.log  easy_server-fri.log.bak
console_20230918080536.log  easy_server-mon.log
console_20230918130141.log  easy_server-mon.log.bak
console_20230919062706.log  easy_server-sat.log
console_20230925115326.log  easy_server-sat.log.bak
console_20230926094533.log  easy_server-sun.log
console_20230930105047.log  easy_server-sun.log.bak
console_20231003084051.log  easy_server-thr.log
console_20231005212057.log  easy_server-thr.log.bak
console_20231008220122.log  easy_server-tue.log
console_20231012064649.log  easy_server-tue.log.bak
console_20231013002935.log  easy_server-wed.log
console_20231013180020.log  error.log
console_20231015064517.log  event_log.sql
console_20231015115634.log  event_log.sql-shm
console_20231016043407.log  event_log.sql-wal
console_20231017143458.log  event_log.txt
console_20231019071853.log  hddman.log
console_20231019073859.log  system_log.txt
console_20231020090143.log  upgrade.log_backup
console_20231022230605.log  upgrade_std_str.log
console_20231024032436.log
```

### 2.4. Watchdog Analysis

The /dev/watchdog device is referred to by the daemon binary and the dvr\_main binary. Therefore, a reboot may be prevented through feeding.

```bash
sh-4.3# lsof /dev/watchdog
COMMAND     PID USER   FD   TYPE DEVICE SIZE/OFF  NODE NAME
CamThread   848 root   28r  FIFO    0,8      0t0  7019 pipe
CamThread   848 root   29w  FIFO    0,8      0t0  7019 pipe
CamThread   848 root   31r  FIFO    0,8      0t0  7031 pipe
CamThread   848 root   32w  FIFO    0,8      0t0  7031 pipe
CamThread   848 root   34r  FIFO    0,8      0t0  7710 pipe
CamThread   848 root   35w  FIFO    0,8      0t0  7710 pipe
CamThread   848 root   37r  FIFO    0,8      0t0  7069 pipe
CamThread   848 root   38w  FIFO    0,8      0t0  7069 pipe
CamThread   848 root   72w   CHR 10,130      0t0  1879 /dev/watchdog
ssui       1210 root    3r  FIFO    0,8      0t0  6910 pipe
ssui       1210 root    4w  FIFO    0,8      0t0  6910 pipe
ssui       1210 root    5r  FIFO    0,8      0t0  6913 pipe
ssui       1210 root    6w  FIFO    0,8      0t0  6913 pipe
ssui       1210 root   13r  FIFO    0,8      0t0  6944 pipe
ssui       1210 root   14w  FIFO    0,8      0t0  6944 pipe
lwproxy    1362 root    1w  FIFO    0,8      0t0  7860 pipe
lwproxy    1362 root    4r  FIFO    0,8      0t0  7853 pipe
dhcpd      2357 root    5r  FIFO    0,8      0t0  7860 pipe
ntpd       2383 root   28w  FIFO    0,8      0t0  9772 pipe
tutkd      2522 root    5r  FIFO    0,8      0t0  7860 pipe
lighttpd   2576 root    4r  FIFO    0,8      0t0  8971 pipe
lighttpd   2576 root    5r  FIFO    0,8      0t0  7860 pipe
dropbear   4191 root    4r  FIFO    0,8      0t0 15766 pipe
dropbear   4191 root    6w  FIFO    0,8      0t0 15766 pipe
sh         4228 root    6w  FIFO    0,8      0t0 15766 pipe
dropbear   6941 root    4r  FIFO    0,8      0t0 79055 pipe
dropbear   6941 root    6w  FIFO    0,8      0t0 79055 pipe
sh         6988 root    6w  FIFO    0,8      0t0 79055 pipe
lsof      12667 root    4w  FIFO    0,8      0t0 99111 pipe
lsof      12667 root    5r  FIFO    0,8      0t0 99112 pipe
lsof      12668 root    3r  FIFO    0,8      0t0 99111 pipe
lsof      12668 root    6w  FIFO    0,8      0t0 99112 pipe
```

However, if an error occurs in the dvr\_main binary, the daemon binary catches it and reboots the device, so I will explain that part. Reversing daemon is as follows.

```c
do {
    if (*(uint *)((int)&status_arr+ ptr1) == uVar3) {
      memset(log1,0,0x200);
      uVar3 = (&error_code)[result * 3];
      snprintf(log1,0x200,"[DAEMON] %s:%d %s\n","handle_dvrmain_exitcode",0x2d0,uVar3);
      log_write(log1);
      local_15d0 = (&DAT_00013460)[result * 3];
      goto LAB_00012108;
    }
    result = result + 1;
    ptr1 = ptr1 + 0xc;
  } while (result != 0xf);
  local_15d0 = 1;
  memset(log1,0,0x200);
  snprintf(log1,0x200,"[DAEMON] %s:%d exit reason is [%d]\n","handle_dvrmain_exitcode",0x2d9,uVar 3);
...
snprintf(log1,0x200,"[DAEMON] %s:%d System Restart Count (%d), ExitCode (%d)\n",
           "dvr_main_thread_body",0x370,addr,local_15d0);
  log_write(log1);
  switch(local_15d0) {
        case 0:
          file system unmount
	  reboot
	case 1:
		continue
	case 2:
		reboot
	case 3:
		Format after unmount if file system type is xfs or ext type
		reboot
	case 4:
		running swupgrader process background
	default:
		Forced reboot after unmounting the file system
```

Since the daemon binary creates a child process through the fork function and executes the dvr\_main binary through the execl function, it has a structure that reboots the system through the case statement after checking the error code of dvr\_main.
