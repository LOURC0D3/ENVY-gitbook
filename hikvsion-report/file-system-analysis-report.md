# File System Analysis Report

## 1. Overview

***

This document is from the BoB 12th NVR Vulnerability Analysis project team.ENVY (Kim Chang-in, Park Myung-hoon, Shin Myung-jin, Yang Kang-min, and Lee Yoo-kyung) explains Hikvision file system analysis.



### 1.1. Necessity

File system analysis is essential for performing embedded vulnerability analysis. It is a necessary step to deactivate watchdogs for identifying and debugging binary analysis that activates services to perform vulnerability analysis. Therefore, this report describes the progress of file system analysis to perform vulnerability analysis.

### &#x20;1.2. /etc/inittab

The contents of /etc/inittab are as follows.

* **::sysinit:/etc/init.d/rcS**: This section specifies the instructions to be performed during system initialization, and when NVR is started, the /etc/init.d/rcS file is executed first, and when NVR is terminated, you can see that the /etc/scripts/SsShutdown.sh file is executed.
* **::respawn:-/bin/sh**: Specifies to run "/bin/sh" shell and, if finished, to run again. This part is usually used to manage the login shell for a particular console.
* **::restart:/sbin/init**:/sbin/init Specifies the command to run when the process is restarted, primarily used to restart the init process itself.
* **:ctrlaltdel:/sbin/reboot**:Specifies instructions to restart the system when Ctrl+Alt+Delete key combination is pressed.
* **::shutdown:/bin/umount-a-r**—Specifies an instruction to amount the file system upon system shutdown, where "-a" is used for all file systems and "-r" is used to force a read-only mounted file system.
* **::shutdown:/sbin/swapoff-a**—Specifies the instruction to disable all swap space upon system shutdown. "swapoff-a" disables all swap space.

```
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

#### 2.1.1. /etc/rcS.d/rcS

After mounting the device based on contents in /etc/mtab by a /bin/mount-a command, a local network interface is configured to execute all scripts in the /etc/rcS.d directory.

#### 2.1.2. /etc/rcS.d/S20hikbase

After unencrypting the hikbase.image file using the hikefs command, uncompress it with a tar command to set a file necessary for starting.

#### 2.1.3. /etc/rcS.d/S30udev

An udev service is executed by using an udevd command to generate a device node.

#### 2.1.4. /etc/rcS.d/S31devs

When multiple device nodes do not exist through the mkmod command, the device node is created so that the device can be used.

#### 2.1.5. /etc/rcS.d/S40distmnt

A plurality of subordinate directories are generated based on the /mnt directory.

#### 2.1.6. /etc/rcS.d/S70hostname

The hostname command sets the host name of the appliance to dvrdvs.

#### 2.1.7. /etc/rcS.d/S70ifconfig

A MAC address and an IP setting of a network interface are dynamically configured according to specific conditions.

#### 2.1.8. /etc/rcS.d/S70ramoops

Ramoops provides a function to store memory dumps in the event of panic or other abnormal situations in the Linux kernel. It operates primarily using a pstore file system, which provides an interface for storing various types of data using persistent storage provided by the Linux kernel.

After mounting the pstore file system in /sys/fs/pstore to use ramoops, check whether the device has been warm rebooted or cold rebooted and output a log accordingly.

* warm reboot—Restart with some information retained without completely erasing memory when the system is restarted
* cold reboot—Full shutdown and restart of the system

#### 2.1.9. /etc/rcS.d/S71update

If there is a DIGICAP environment variable, proceed with the NVR update using the do\_update binary.

#### 2.1.10. /etc/rcS.d/S80mem

Adjust memory management to specific systems or special requirements.

#### 2.1.11. /etc/rcS.d/S80net

local network Modifies the routing behavior of traffic and adjusts it to specific network configurations or requirements.

#### 2.1.12. /etc/rcS.d/S81startbsp

Run the /home/bsp/startbsp.sh script, which copies the file to /usr/sbin/ if it exists.

#### 2.1.13. /etc/rcS.d/S90start\_cramfs

If the "BOOTMODE" of the "/proc/hkvs/ability" file is "cramfs", a "/dev/mtdblock1" device is mounted in the cramfs file system format to "/home/hk". After that, the /tmp/start.sh file is decrypted using a ded tool, and execution authority is given to execute the corresponding shell script file.

#### 2.1.14. /etc/rcS.d/S90start\_slave2

If the BOOTMODE of the /proc/hkvs/ability file is slave, create a /dev/slaveram device and a /home/slave directory, uncompress the /dev/slaveram device to /home/slave, and create a shell script for /home/slave/start.sh .

#### 2.1.15. /etc/rcS.d/S90start\_ubifs

If the BOOTMODE of the /proc/hkvs/ability file is ubifs, directories /home/dav0, /home/dav1 and /home/dav2 are generated, and subifs file systems are mounted in respective directories. After that, a start partition among the three directories is determined to set a network, and after decrypting the /tmp/start.sh file by using a ded tool, execution authority is given to execute the corresponding shell script file.

#### 2.1.16. /etc/rcS.d/S90start\_yaffs2

If the BOOTMODE of the /proc/hkvs/ability file is yaffs2, after generating directories /home/dav0, /home/dav1, /home/dav2, a yaffs2 file system is mounted in each directory. After that, the /tmp/start.sh file is decrypted using a ded tool, and execution authority is given to execute the corresponding shell script file.

#### 2.1.17. /etc/rcS.d/S95setconsole

Execute setconsole only when a console called shmty0 is configured and the settings are correct.

#### 2.1.18. /etc/rcS.d/S99selftests

If a kernel module called hik\_selftests.ko exists, it loads the module.



### 2.2. Activation Service Analysis

#### 2.2.1. sc\_hicore

Checking the port in service.

Since sc\_hicore is in charge of major services, it can be determined that the binary is the main binary.

```
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:49152           0.0.0.0:*               LISTEN      421/sc_hicore
tcp        0      0 127.0.0.1:53000         0.0.0.0:*               LISTEN      412/master
tcp        0      0 0.0.0.0:30960           0.0.0.0:*               LISTEN      421/sc_hicore
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1205/dropbear
tcp        0      0 127.0.0.1:7002          0.0.0.0:*               LISTEN      421/sc_hicore
tcp        0      0 :::8000                 :::*                    LISTEN      421/sc_hicore
tcp        0      0 :::554                  :::*                    LISTEN      421/sc_hicore
tcp        0      0 :::80                   :::*                    LISTEN      421/sc_hicore
tcp        0      0 :::22                   :::*                    LISTEN      1205/dropbear
```



#### 2.2.2. Web Services

Analysis using the ps-T command produces the following results.

```
  421 root       0:00 sc_hicore 192.168.0.104
  428 root       0:00 {evt2-hkdpl_sc_h} sc_hicore 192.168.0.104
  431 root       0:00 {th-worker} sc_hicore 192.168.0.104
  432 root       0:00 {th-worker} sc_hicore 192.168.0.104
  433 root       0:00 {th-worker} sc_hicore 192.168.0.104
  434 root       0:00 {th-worker} sc_hicore 192.168.0.104
  435 root       0:01 {th-worker} sc_hicore 192.168.0.104
  436 root       0:00 {ipcm_alarm_serv} sc_hicore 192.168.0.104
  437 root       0:00 {th-worker} sc_hicore 192.168.0.104
  438 root       0:00 {taskMoveLog} sc_hicore 192.168.0.104
  439 root       0:00 {taskDvrLog} sc_hicore 192.168.0.104
  440 root       0:00 {th-worker} sc_hicore 192.168.0.104
  441 root       0:00 {db_data_sync_ta} sc_hicore 192.168.0.104
  442 root       0:00 {th_check_sc_abn} sc_hicore 192.168.0.104
  443 root       0:03 {cfg_ctrl_task} sc_hicore 192.168.0.104
  444 root       0:00 {cfg_write_ctrl_} sc_hicore 192.168.0.104
  445 root       0:00 {hk_cmd_|3|2|_} sc_hicore 192.168.0.104
  446 root       0:14 {hisi_stream_rec} sc_hicore 192.168.0.104
  520 root       0:00 {thr_sadp_captur} sc_hicore 192.168.0.104
  521 root       0:00 {multicast_thr_s} sc_hicore 192.168.0.104
  522 root       0:00 {share svc recv } sc_hicore 192.168.0.104
  523 root       0:00 {share svc send } sc_hicore 192.168.0.104
  524 root       0:00 {share svc repos} sc_hicore 192.168.0.104
  525 root       0:00 {update_ptz_cfg_} sc_hicore 192.168.0.104
  526 root       0:00 {taskContiComman} sc_hicore 192.168.0.104
  527 root       0:00 {th-worker} sc_hicore 192.168.0.104
  528 root       0:00 {handle_pppoe_cf} sc_hicore 192.168.0.104
  529 root       0:00 {drop_caches_tas} sc_hicore 192.168.0.104
  533 root       0:00 {stor_check_db_s} sc_hicore 192.168.0.104
  534 root       0:00 {taskHdCtrl} sc_hicore 192.168.0.104
  535 root       0:00 {hdFlushTask} sc_hicore 192.168.0.104
  536 root       0:00 {hdLoadCtrlTask} sc_hicore 192.168.0.104
  537 root       0:00 {db_data_del_tas} sc_hicore 192.168.0.104
  538 root       0:00 {db_drop_table_t} sc_hicore 192.168.0.104
  539 root       0:01 {db_file_operati} sc_hicore 192.168.0.104
  540 root       0:00 {sataTaskCtrl} sc_hicore 192.168.0.104
  541 root       0:00 {recordSchedule} sc_hicore 192.168.0.104
  542 root       0:00 {taskDelOverTime} sc_hicore 192.168.0.104
  543 root       0:00 {detectExportDev} sc_hicore 192.168.0.104
  544 root       0:00 {anr_task_ipc_mo} sc_hicore 192.168.0.104
  548 root       0:00 {anr_task_schedu} sc_hicore 192.168.0.104
  558 root       0:00 {DesktopMain} sc_hicore 192.168.0.104
  559 root       0:00 {TimerEntry} sc_hicore 192.168.0.104
  560 root       0:00 {EventLoop} sc_hicore 192.168.0.104
  561 root       0:00 {KeyLoop} sc_hicore 192.168.0.104
  562 root       0:00 {RefreshLoop} sc_hicore 192.168.0.104
  563 root       0:00 {ScrolledLoop} sc_hicore 192.168.0.104
  564 root       0:00 {GStataDVD} sc_hicore 192.168.0.104
  566 root       0:00 {mgui_start_main} sc_hicore 192.168.0.104
  567 root       0:00 {Skb} sc_hicore 192.168.0.104
  568 root       0:00 {taskUsrSecurity} sc_hicore 192.168.0.104
  569 root       0:00 {evt2-rtsps-0} sc_hicore 192.168.0.104
  570 root       0:00 {evt2-e2Base-0} sc_hicore 192.168.0.104
  571 root       0:00 {RtspS_del_sessi} sc_hicore 192.168.0.104
  572 root       0:02 {RtspS_parse_dsp} sc_hicore 192.168.0.104
  573 root       0:00 {evt2-sdkPreview} sc_hicore 192.168.0.104
  574 root       0:00 {low_bw_time_tic} sc_hicore 192.168.0.104
  575 root       0:00 {evt2-lowbw_prev} sc_hicore 192.168.0.104
  576 root       0:00 {forceIframeWork} sc_hicore 192.168.0.104
  577 root       0:00 {taskPanelCmd} sc_hicore 192.168.0.104
  578 root       0:00 {key_board_recv_} sc_hicore 192.168.0.104
  579 root       0:00 {ds_1005_key_boa} sc_hicore 192.168.0.104
  580 root       0:00 {IRRecvTask_V001} sc_hicore 192.168.0.104
  581 root       0:00 {RtspS_th_cfg_ch} sc_hicore 192.168.0.104
  598 root       0:00 {th-worker} sc_hicore 192.168.0.104
  603 root       0:00 {evt2-rtspc-0} sc_hicore 192.168.0.104
  604 root       0:00 {rtspc_time_svc} sc_hicore 192.168.0.104
  605 root       0:00 {evt2-httpc-0} sc_hicore 192.168.0.104
  606 root       0:00 {ipcmConnTask-1} sc_hicore 192.168.0.104
  631 root       0:01 {Rec-Video-01} sc_hicore 192.168.0.104
  632 root       0:00 {Rec-Picture-01} sc_hicore 192.168.0.104
  633 root       0:00 {ipcmConnCh1} sc_hicore 192.168.0.104
  658 root       0:01 {Rec-Video-02} sc_hicore 192.168.0.104
  659 root       0:00 {Rec-Picture-02} sc_hicore 192.168.0.104
  660 root       0:00 {ipcmConnCh2} sc_hicore 192.168.0.104
  685 root       0:01 {Rec-Video-03} sc_hicore 192.168.0.104
  686 root       0:00 {Rec-Picture-03} sc_hicore 192.168.0.104
  687 root       0:00 {ipc_sadp_task} sc_hicore 192.168.0.104
  688 root       0:00 {thread_ipc_cfg_} sc_hicore 192.168.0.104
  689 root       0:00 {task mainport[2} sc_hicore 192.168.0.104
  690 root       0:00 {taskAdjustIPCTi} sc_hicore 192.168.0.104
  691 root       0:00 {taskSendEmail} sc_hicore 192.168.0.104
  692 root       0:00 {task logo} sc_hicore 192.168.0.104
  693 root       0:00 {monitor alarm t} sc_hicore 192.168.0.104
  694 root       0:00 {storSmartInfo_t} sc_hicore 192.168.0.104
  695 root       0:00 {taskVcaNetHost} sc_hicore 192.168.0.104
  696 root       0:00 {taskAdjustTime} sc_hicore 192.168.0.104
  697 root       0:00 {taskExceptionCt} sc_hicore 192.168.0.104
  698 root       0:00 {dspStoreCheck} sc_hicore 192.168.0.104
  699 root       0:00 {taskAlarmInCtrl} sc_hicore 192.168.0.104
  700 root       0:00 {uploadDevStsTas} sc_hicore 192.168.0.104
  701 root       0:00 {taskSendEmailCt} sc_hicore 192.168.0.104
  702 root       0:00 {taskSendAlarmTo} sc_hicore 192.168.0.104
  703 root       0:00 {taskAlarmToRest} sc_hicore 192.168.0.104
  704 root       0:00 {ipcmConnCh3} sc_hicore 192.168.0.104
  711 root       0:00 {taskIpDAD} sc_hicore 192.168.0.104
  714 root       0:00 {mgui_start_main} sc_hicore 192.168.0.104
  715 root       0:00 {mgui_start_main} sc_hicore 192.168.0.104
  716 root       0:00 {processMotDetDe} sc_hicore 192.168.0.104
  717 root       0:00 {task_net_broken} sc_hicore 192.168.0.104
  718 root       0:00 {taskDvrNetServe} sc_hicore 192.168.0.104
  721 root       0:00 {ezviz_srv_main} sc_hicore 192.168.0.104
  722 root       0:00 {taskStartDdnsCl} sc_hicore 192.168.0.104
  723 root       0:00 {taskStartSntpCl} sc_hicore 192.168.0.104
  724 root       0:00 {motdet_ctrl_tas} sc_hicore 192.168.0.104
  725 root       0:00 {taskSmdCtrltask} sc_hicore 192.168.0.104
  726 root       0:00 {startHttpServer} sc_hicore 192.168.0.104
  727 root       0:00 {taskMonitorDdns} sc_hicore 192.168.0.104
  728 root       0:00 {th-worker} sc_hicore 192.168.0.104
  729 root       0:00 {isapi_session_t} sc_hicore 192.168.0.104
  730 root       0:00 {taskAppWeb} sc_hicore 192.168.0.104
  736 root       0:00 {upnp_start} sc_hicore 192.168.0.104
  737 root       0:00 {upnp_check_desc} sc_hicore 192.168.0.104
  738 root       0:05 {ipc_pse_ctrl} sc_hicore 192.168.0.104
  739 root       0:00 {ipc_poe_ctrl} sc_hicore 192.168.0.104
  740 root       0:00 {ipc_password_sy} sc_hicore 192.168.0.104
  741 root       0:00 {recordSysStatIn} sc_hicore 192.168.0.104
  753 root       0:00 {th-worker} sc_hicore 192.168.0.104
  754 root       0:00 {WuHanCloud_Cli} sc_hicore 192.168.0.104
  755 root       0:00 {WHCloud_Update_} sc_hicore 192.168.0.104
  757 root       0:00 {isapi_intell_se} sc_hicore 192.168.0.104
  758 root       0:00 {th-worker} sc_hicore 192.168.0.104
  766 root       0:00 {upnp_start} sc_hicore 192.168.0.104
  768 root       0:00 {upnp_start} sc_hicore 192.168.0.104
  769 root       0:00 {upnp_start} sc_hicore 192.168.0.104
  779 root       0:00 {ipcPrev vo[2],c} sc_hicore 192.168.0.104
  780 root       0:00 {ipcPrev vo[2],c} sc_hicore 192.168.0.104
  781 root       0:00 {ipcPrev vo[2],c} sc_hicore 192.168.0.104
  782 root       0:00 {ipcPrev vo[2],c} sc_hicore 192.168.0.104
  783 root       0:01 {Rec-Video-04} sc_hicore 192.168.0.104
  784 root       0:00 {Rec-Picture-04} sc_hicore 192.168.0.104
  785 root       0:00 {poe_time_task} sc_hicore 192.168.0.104
  786 root       0:00 {taskMonitorIPCP} sc_hicore 192.168.0.104
  787 root       0:00 {SDKChanOpTask} sc_hicore 192.168.0.104
  788 root       0:00 {alarm_guid_task} sc_hicore 192.168.0.104
  813 root       0:00 {backup_manage_c} sc_hicore 192.168.0.104
  814 root       0:00 {backup_export_d} sc_hicore 192.168.0.104
  815 root       0:00 {flash_protect_T} sc_hicore 192.168.0.104
  816 root       0:00 {syslog_upload_t} sc_hicore 192.168.0.104
  820 root       0:00 {wpa_msg_handler} sc_hicore 192.168.0.104
 1144 root       0:00 {CS@ity/sessionH} sc_hicore 192.168.0.104
 1145 root       0:00 {CS@ity/sessionH} sc_hicore 192.168.0.104
 1148 root       0:00 {CS@ity/sessionH} sc_hicore 192.168.0.104
 1716 root       0:00 {upnp_start} sc_hicore 192.168.0.104
 1778 root       0:00 {upnp_start} sc_hicore 192.168.0.104
 1779 root       0:00 {upnp_start} sc_hicore 192.168.0.104
```

sc\_hicore uses threads to run multiple services and multiple tasks to run web services.



### 2.3. Check mount

After the start-up is completed, the following results can be obtained by executing the mount command.

```
rootfs on / type rootfs (rw,size=125624k,nr_inodes=31406)
proc on /proc type proc (rw,relatime)
sysfs on /sys type sysfs (rw,relatime)
udev on /dev type tmpfs (rw,relatime)
devpts on /dev/pts type devpts (rw,relatime,mode=600)
pstore on /sys/fs/pstore type pstore (rw,relatime)
/dev/ubi0_0 on /dav0 type ubifs (rw,relatime)
/dev/ubi1_0 on /dav1 type ubifs (rw,relatime)
/dev/ubi2_0 on /dav2 type ubifs (rw,relatime)
```

The device uses the ubifs file system, and it can be seen that the /etc/rcS.d/S90start\_ubifs shell script file was executed during the startup script.



### 2.4. Watchdog analysis

#### 2.4.1. hik\_watchdog.ko

When init script is executed, there is a part that loads the kernel module. Among the modules loaded in the process, hik\_watchdog.ko acts as a watchdog.

```
v17 = hikbase_support(71);
v18 = v5[22];
if ( v17 )
  v5[30] = 1;
if ( !v18 || (v17 = request_threaded_irq(v18, hikwdt_isr, 0, 0, "HIK_WDT_INT", 0), v13 = v17, v17 >= 0) )
{
  v19 = hkabi_proc_dir(v17);
  data = proc_create_data("wdtinfo", 0, v19, &unk_1760, v5);
  v21 = v5[25];
  LANCHOR1 = (int)v5;
  v5[34] = data;
  hkprt_printk(
    &LC40,
    v21,
    "/data/jenkins/workspace/Backend-BSP-CCI/4115/modules/drivers/wdt/hik_wdt.c",
    "hikwdt_probe",
    644,
    "[HIK]hikwdt: initialize success.\n");
  return 0;
}
```

As mentioned above, a function to be called when an error occurs through the request\_threaded\_irq function is set. If an error occurs, it can be confirmed that the hikwdt\_isr function is executed.

```
int __fastcall hikwdt_isr(int a1, int a2)
{
  int v4; // r5
  int v5; // r0
  int result; // r0
  int v8; // r6
  int v9; // r1
  int v10; // r1
  int v11; // r0
  __int64 v12; // r10
  int v13; // r4
  __int64 jiffies_64; // r0
  int v15; // r0
  int (__fastcall *v16)(int); // r3
  void (__fastcall *v17)(int); // r3
  void (__fastcall *v18)(int, int); // r3
  int v19; // r1
  int v20; // r0
  int (__fastcall *v21)(int); // r3
  bool v22; // zf
  int v23; // r1

  v4 = LANCHOR1;
  v5 = hikbase_console_loglevel();
  if ( dword_24BC++ > 0 )
    return 1;
  v8 = v5;
  if ( !v4 )
  {
    hikbase_console_loglevel_set(15);
    v23 = LANCHOR1;
    if ( LANCHOR1 )
      v23 = *(_DWORD *)(LANCHOR1 + 100);
    hkprt_printk(
      &LC40,
      v23,
      "/data/jenkins/workspace/Backend-BSP-CCI/4115/modules/drivers/wdt/hik_wdt.c",
      "hikwdt_isr",
      412,
      "hik-wdt:%s; The wdt struct is NULL\n",
      "hikwdt_isr");
    hikbase_console_loglevel_set(v8);
    return 1;
  }
  if ( *(_DWORD *)(v4 + 120) )
  {
    hikbase_console_loglevel_set(15);
    v19 = LANCHOR1;
    if ( LANCHOR1 )
      v19 = *(_DWORD *)(LANCHOR1 + 100);
    hkprt_printk(
      &LC42,
      v19,
      "/data/jenkins/workspace/Backend-BSP-CCI/4115/modules/drivers/wdt/hik_wdt.c",
      "hikwdt_isr",
      421,
      "hik-wdt:%s; We will trun off wacthdog.(^_^)\n",
      "hikwdt_isr");
    v20 = hikbase_console_loglevel_set(v8);
    v21 = *(int (__fastcall **)(int))(v4 + 76);
    if ( !v21 )
      return 1;
    v22 = v21(v20) == 0;
    result = 1;
    if ( v22 )
      *(_DWORD *)(v4 + 108) = 1;
  }
  else
  {
    hikbase_console_loglevel_set(15);
    v9 = LANCHOR1;
    if ( LANCHOR1 )
      v9 = *(_DWORD *)(LANCHOR1 + 100);
    hkprt_printk(
      &LC2,
      v9,
      "/data/jenkins/workspace/Backend-BSP-CCI/4115/modules/drivers/wdt/hik_wdt.c",
      "hikwdt_isr",
      431,
      "hik-wdt:%s. Call hikwdt notifier chain!\n",
      "hikwdt_isr");
    hikbase_notifiers_call(65538, 0);
    v10 = LANCHOR1;
    if ( LANCHOR1 )
      v10 = *(_DWORD *)(LANCHOR1 + 100);
    v11 = hkprt_printk(
            &LC2,
            v10,
            "/data/jenkins/workspace/Backend-BSP-CCI/4115/modules/drivers/wdt/hik_wdt.c",
            "hikwdt_isr",
            435,
            "hik-wdt:%s. I'm so Sorry (>_<)...\n",
            "hikwdt_isr");
    v12 = *(_QWORD *)(v4 + 128);
    if ( LANCHOR1 )
      v13 = *(_DWORD *)(LANCHOR1 + 100);
    else
      v13 = 0;
    jiffies_64 = get_jiffies_64(v11);
    v15 = hkprt_printk(
            &LC2,
            v13,
            "/data/jenkins/workspace/Backend-BSP-CCI/4115/modules/drivers/wdt/hik_wdt.c",
            "hikwdt_isr",
            437,
            "hik-wdt:%s. last_feedwdt:%llu(jiffies64:%llu,timeout:%u)\n",
            "hikwdt_isr",
            v12,
            jiffies_64,
            *(_DWORD *)(v4 + 112));
    v16 = *(int (__fastcall **)(int))(v4 + 84);
    if ( v16 )
      v15 = v16(1);
    v17 = *(void (__fastcall **)(int))(v4 + 80);
    if ( v17 )
      v17(v15);
    v18 = *(void (__fastcall **)(int, int))(v4 + 92);
    if ( !v18 )
      return 1;
    v18(a1, a2);
    return 1;
  }
  return result;
}
```

If you look at the function, you can see that it is performing various tasks according to the error code, and you can also see the string output when rebooted by the watchdog.



#### 2.4.2. libplatform.so

Watchdog init and feeding in the libplatform.so library.

```
HPR_INT32 hisi_watchdog_init(HPR_UINT32 uTimeOut)

{
  HPR_UINT32 iDogTimeOut;
  
  if (h_g_wdFd < 0) {
    h_g_wdFd = open64("/dev/watchdog",1);
    if (h_g_wdFd == -1) {
      __assert("h_g_wdFd != -1","src/hisi_bsp.c",0x9b0);
    }
  }
                    /* WARNING: Subroutine does not return */
  ioctl(h_g_wdFd,0xc0045706,&iDogTimeOut);
}
```

If you look at the code above, you can see that the ioctl function is executed after opening the /dev/watchdog device. At this time, the timeout period is set to the transmitted factor.

```
/* WARNING: Unknown calling convention */

HPR_INT32 hisi_watchdog_feed(void)

{
  if (h_g_wdFd < 0) {
                    /* WARNING: Subroutine does not return */
    util_dbg_open(2,0x200000,1);
  }
                    /* WARNING: Subroutine does not return */
  ioctl(h_g_wdFd,0x80045705,0);
}
```

Feeding is also done through the ioctl function like init.
