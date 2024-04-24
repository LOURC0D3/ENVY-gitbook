# Analysis Environment Build report

## 1. Overview

This document is a team that carried out the BoB 12th NVR Vulnability Analysis project.This is a report described by ENVY (Kim Chan-in, Park Myung-hoon, Shin Myung-jin, Yang Gang-min, and Lee Yoo-kyung) on the establishment of the Hikvision analysis environment.

### 1.1. Necessity

Debugging the binary that is activating the service is essential to proceed with the vulnerability analysis of hikvision. Therefore, in this document, we describe how to debug watchdog by bypassing it.

## 2. Analysis

If you debug the "sc\_hicore" binary using the gdb tool, you can see that it is output as follows.

```bash
~~~~~~~~~~~~pid (492) will exit!
~~~~~~~~~~~~FN:[fn_master_status]
~~~~~~~~~~~~iRet [-88][Session Handle Err!!]
[165249.722559] [HKBSP][hik_wdt hik_wdt.1]hik-wdt:hikwdt_isr. I'm so Sorry (>_<)…
[165249.730063] [HKBSP][hik_wdt hik_wdt.1]hik-wdt:hikwdt_isr. last_feedwdt:4311458247(jiffies64:4311461694,timeout:25)
```

If you look at the log, you can see that the watchdog feeding is rebooted after the timeout. The watchdog feeding timeout is set in the "hisi\_watchdog\_init" function of the "libplatform.so" file.

```bash
HPR_INT32 __fastcall hisi_watchdog_init(HPR_UINT32 uTimeOut)
{
  HPR_UINT32 iDogTimeOut; // [sp+Ch] [bp-14h] BYREF

  iDogTimeOut = uTimeOut;
  if ( h_g_wdFd < 0 )
  {
    h_g_wdFd = open64("/dev/watchdog", 1);
    if ( h_g_wdFd == -1 )
      _assert("h_g_wdFd != -1", "src/hisi_bsp.c", 2480);
  }
  if ( call_ioctl(h_g_wdFd, 0xC0045706, &iDogTimeOut) >= 0 )
  {
    fprintf((FILE *)stderr, "fun:%s, line:%d ", "hisi_watchdog_init", 2491);
    fprintf(
      (FILE *)stderr,
      "hisi_watchdog_init(%s, %d) ok iDogTimeOut:%d Sec!\n",
      "/dev/watchdog",
      h_g_wdFd,
      iDogTimeOut);
    return 0;
  }
  else
  {
    if ( util_dbg_open() )
      util_debug("src/hisi_bsp.c", 2485, "hisi_watchdog_init", 2, "hisi_watchdog_init error!\n");
    return -1;
  }
}
```

When the function is decoded, it can be seen that the timeout is set as much as the "uTimeOut" variable transmitted to the factor. Therefore, it was possible to bypass the watchdog by modifying the part and increasing the time that becomes the timeout.

```armasm
.text:00010F1C                 PUSH            {R4,R5,LR}
.text:00010F20                 SUB             SP, SP, #0x14
.text:00010F24                 LDR             R4, =h_g_iopFd
.text:00010F28                 MOV             uTimeOut_0, #0xFFFFFFFF
.text:00010F2C                 LDR             R3, [R4,#(h_g_wdFd - 0x49D64)]
.text:00010F30                 MOV             R5, R4
.text:00010F34                 CMP             R3, #0
.text:00010F38                 BGE             loc_10F68
.text:00010F3C                 LDR             uTimeOut_0, =aDevWatchdog ; "/dev/watchdog"
.text:00010F40                 MOV             R1, #1
.text:00010F44                 BL              open64
.text:00010F48                 STR             R0, [R4,#(h_g_wdFd - 0x49D64)]
.text:00010F4C                 CMN             R0, #1
.text:00010F50                 BNE             loc_10F68
.text:00010F54                 LDR             R3, =__PRETTY_FUNCTION__.24206 ; "hisi_watchdog_init"
.text:00010F58                 MOV             R2, #0x9B0 ; line
.text:00010F5C                 LDR             R1, =file ; "src/hisi_bsp.c"
.text:00010F60                 LDR             R0, =assertion ; "h_g_wdFd != -1"
.text:00010F64                 BL              __assert
```

As in the code above, by patching the "uTimeOut" variable to allocate 0xFFFFFFFFFFFFFF, the timeout time could be increased and debugging could be performed.

## 3. Deploy Analytical Environment Boot Script

I will explain the boot script for increasing watchdog timeout. First of all, the contents of "start.sh " and "S90start\_ubifs" were modified as follows.

```bash
#!/bin/sh
## This is a start script file for app startup.
## Modify by liweijie for DVR/NVR platform@2015-3-19

mkready_for_start_script()
{
	/bin/cp /dav$1/start.sh /tmp/start.sh -f;

	if [ -e /dav$1/RSA ]; then
		/bin/cp /dav$1/RSA /etc/RSA -f;
		/usr/bin/hrsaverify /tmp/start.sh -d
		if [ $? == 0 ]; then
			echo ""
		else
			echo "rsaverify start.sh error !!!"
			if [ $1 == "0" ]; then
				echo "system reboot from backup partition !!!"
			elif [ $1 == "1" ]; then
				echo "system reboot must after update or autoupdate !!!"
			fi
			[ -e /dav$1/version.bin ] && /bin/rm /dav$1/version.bin -f
			/sbin/reboot
			/bin/sleep 20
		fi
	fi

	/bin/ded -d /tmp/start.sh /home/start.sh >/dev/null 2>&1
	if [ $? == 0 ];then
		echo ""
	else
		echo "ded decrypt start.sh error !!!"
		if [ $1 == "0" ]; then
			echo "system reboot from backup partition !!!"
		elif [ $1 == "1" ]; then
			echo "system reboot must after update or autoupdate !!!"
		fi
		[ -e /dav$1/version.bin ] && /bin/rm /dav$1/version.bin -f
		/sbin/reboot
		/bin/sleep 20
	fi

	/bin/rm /tmp/start.sh -f
	/bin/chmod 777 /home/start.sh
}

if [ -e /proc/hkvs/ability ] ; then
	BOOTMODE=$(/usr/bin/awk -F: "/BOOTMODE/ {print \$2}" /proc/hkvs/ability)
	BOOTPART=$(/usr/bin/awk -F:0x "/BOOTPART/ {print \$2}" /proc/hkvs/ability)
	HIKDEBUG=$(/usr/bin/awk -F:0x "/DEBUG/ {print \$2}" /proc/hkvs/ability)
fi
if [ "$BOOTMODE" != "ubifs" ]; then
	exit 0;
fi

if [ "$BOOTPART" != "" ] ; then
	[ -e /home/dav0 ] || /bin/mkdir -p /dav0
	[ -e /home/dav1 ] || /bin/mkdir -p /dav1
	[ -e /home/dav2 ] || /bin/mkdir -p /dav2

	ENODEV=19
	for partnum in 0 1 2
	do
		/usr/sbin/mount_ubifs $partnum
		if [ "$?" == "$ENODEV" ] ; then
			/bin/echo "Recovering dav"$partnum" partition ..."
			/bin/echo $partnum unlock > /proc/hkvs/mtd/mtdprotect
			/usr/sbin/format_ubifs $partnum
			/usr/sbin/umount_ubifs $partnum
			/usr/sbin/mount_ubifs $partnum
			/bin/echo $partnum lock > /proc/hkvs/mtd/mtdprotect
		fi
	done

	if [ -e /dav0/version.bin ] ; then
		/bin/echo bootpart0 > /proc/hkvs/ability
		BOOTPART=0
	elif [ -e /dav1/version.bin ] ; then
		/bin/echo bootpart1 > /proc/hkvs/ability
		BOOTPART=1
	else
		/bin/echo bootpart0 > /proc/hkvs/ability
		/bin/echo "the system is damaged ?"
	fi
	/bin/echo "bootpart :"$BOOTPART
	if [ "$HIKDEBUG" == "1" ]; then
		exit 0;
	fi
	if [ "$BOOTPART" == "0" ] || [ "$BOOTPART" == "1" ] ; then
		mkready_for_start_script $BOOTPART;
	else
		/bin/echo "Boot Partition is error. Please update digicap.dav."
	fi
fi

if [ "$HIKDEBUG" == "1" ]; then
	exit 0;
fi

if [ -e /home/start.sh ];then
	echo -e "\033[34m[ENVY] restart nfs mount\033[0m"
	ifconfig lo 127.0.0.1 up
	ifconfig eth0 192.168.0.104 up
	route add default gw 192.168.0.1

	sleep 5
	mkdir /nfs
	mount -t nfs -o vers=3,nolock 192.168.0.105:/volume1/nfs /nfs
	echo -e "\033[34m[ENVY] nfs mount success!\033[0m"
	mv /home/start.sh /tmp/start.sh
	cp /nfs/booting/hikvision/start.sh /home/start.sh
	/home/start.sh&
elif [ -e /home/initrun.sh ];then
	/home/initrun.sh&
elif [ -e /opt/start.sh ];then
	/opt/start.sh&
fi
```

In the case of the "S90start\_ubifs" script, before executing the "start.sh " script, the network was held and nfs was added to move the modified start.sh .

```bash
#!/bin/sh
[ -e /proc/sys/vm/min_free_kbytes ] && echo 8192 > /proc/sys/vm/min_free_kbytes
#echo 1 > /proc/hkvs/ahci_scan

#�豸�����Ϣһ���
sdbg=$(/usr/bin/awk -F 'sdbg=' '{print substr($2,1,1)}' /proc/cmdline)
who=$(/usr/bin/awk -F 'who=' '{print $2}'  /proc/cmdline|awk '{print $1}')
data=$(/usr/bin/awk -F 'data=' '{print $2}' /proc/cmdline|awk '{print $1}')
nfsdir=$(/usr/bin/awk -F 'nfsdir=' '{print $2}' /proc/cmdline|awk '{print $1}')
serverip=$(/usr/bin/awk -F: '{print $2}' /proc/cmdline)
gdb=$(/usr/bin/awk -F 'gdb=' '{print $2}' /proc/cmdline|awk '{print $1}')

echo "----------<1> tar all res ----------"

BOOTPART=$(/usr/bin/awk -F:0x "/BOOTPART/ {print \$2}" /proc/hkvs/ability)
/bin/echo "bootpart :"$BOOTPART
if [ "$BOOTPART" == "0" ] ; then

	ded -d /dav0/sys_app.tar.lzma /home/app/sys_app.tar.lzma
	/bin/tar xaf /home/app/sys_app.tar.lzma -C /home/app/

	if [ $? == 0 ];then
		echo "decompress sys_app done."
	else
		echo "decompress sys_app error !!!"
	fi
	rm -f  /home/app/sys_app.tar.lzma

	ded -d /dav0/webs.tar.lzma /home/app/webs.tar.lzma
	/bin/tar xaf /home/app/webs.tar.lzma -C /home/app/

	if [ $? == 0 ];then
		echo "decompress webs done."
	else
		echo "decompress webs error !!!"
	fi
	rm -f /home/app/webs.tar.lzma

elif [ "$BOOTPART" == "1" ] ; then

	ded -d /dav1/sys_app.tar.lzma /home/app/sys_app.tar.lzma
	/bin/tar xaf /home/app/sys_app.tar.lzma -C /home/app/

	if [ $? == 0 ];then
		echo "decompress sys_app done."
	else
		echo "decompress sys_app error !!!"
	fi
	rm -f  /home/app/sys_app.tar.lzma

	ded -d /dav1/webs.tar.lzma /home/app/webs.tar.lzma
	/bin/tar xaf /home/app/webs.tar.lzma -C /home/app/

	if [ $? == 0 ];then
		echo "decompress webs done."
	else
		echo "decompress webs error !!!"
	fi
	rm -f /home/app/webs.tar.lzma
else
	/bin/echo "Boot Partition is error. Please update digicap.dav."
fi
/bin/tar xzf /home/app/exec/dvrCmd.tar.gz -C /usr/bin/

mv -f /home/app/exec/pppd /usr/bin/
mv -f /home/app/exec/pppoe /usr/bin/
mv -f /home/app/exec/ss /usr/bin/
mv -f /home/app/exec/dropbear /usr/sbin/
mv -f /home/app/exec/dropbearkey /usr/sbin/
mkdir -p /etc/dropbear && cd /etc/dropbear && dropbearkey -t rsa -f dropbear_rsa_host_key&

/bin/chmod 777 /usr/bin/dvrCmd/dvrtools
/bin/chmod 777 /dev/hikio
/bin/chmod 777 /dev/hikpse
/bin/chmod 777 /dev/rtc0
/bin/chmod 777 /dev/watchdog
/bin/chmod 777 /dev/hikstorage
/bin/chmod 777 /dev/hikbsp
/bin/chmod 777 /dev/logo
/bin/chmod 777 /dev/env
/bin/chmod 777 /dev/hikmtd

/bin/chmod 777 /dev/ttyS0
/bin/chmod 777 /dev/ttyS3

if [ "$sdbg" == "s" ] || [ "$sdbg" == "g" ];then
	echo "=>Start mount rootfs:${serverip}:/${data}/${who}/nfs/${nfsdir} /tmp"
	mount -t nfs -o intr,nolock,rsize=1024,wsize=1024 ${serverip}:/${data}/${who}/nfs/${nfsdir} /tmp
    echo "mount over"
	cp -f /tmp/sc_hicore /home/app/exec/
	cp -f /tmp/hik_dsp /home/app/exec/
	cp -f /tmp/hik_dsp_logo /home/app/exec/
	cp -f /tmp/libhisdsp.so /home/app/lib/
	if [ "$gdb" == "y" ];then
		echo "================= gdbserver ===================="
		cp -rf /tmp/dev_tools/gdb/hisi_3536C/bin/server /home/app/exec/
		cp -rf /tmp/dev_tools/gdb/bin/server /home/app/exec/
		cd /home/app/exec/server
		/bin/sh run_gdbserver.sh &
		cd -
	fi
	umount /tmp
fi

echo "----------<3> load hisi sdk ----------"
SYSTEM_DDR=`echo | awk -F: '/total_mm/{print $2}' /proc/hkvs/cpldinfo`
OS_DDR=`echo | awk -F: '/os_mm/{print $2}' /proc/hkvs/cpldinfo`
MMZ_DDR=`echo | awk -F: '/mmz_size/{print $2}' /proc/hkvs/cpldinfo`
HAVE9024=`echo | awk -F: '/SII9024/{print $2}' /proc/hkvs/cpldinfo`
HAVE8200=`echo | awk -F: '/THS8200/{print $2}' /proc/hkvs/cpldinfo`
TALKCHIP=`echo | awk -F: '/��Ƶ��������/{print $2}' /proc/hkvs/cpldinfo`
echo "The system mem size is all $SYSTEM_DDR os $OS_DDR  mmz$MMZ_DDR 9024:$HAVE9024 8200:$HAVE8200"


echo "####################################load GPU_KO################################################"
mv -f /home/app/lib/* /lib/
cd /home/app/exec/gpu_ko
./loadgpu -i

#0xffea0800��ʾNAU88C10
#chip_paraΪ2����NAU88C10 ,Ϊ1����rt5616
if [ "$TALKCHIP" == "0xffea0800" ];then
	chip_param="2"
else
	chip_param="1"
fi

cd /home/app/hisi/modules/
/bin/chmod -Rf 777 ./
if [ "$MMZ_DDR" == "256" ]
then
	/home/app/hisi/modules/load3536c -i 2 $chip_param
elif [ "$MMZ_DDR" == "384" ]
then
	/home/app/hisi/modules/load3536c -i 1 $chip_param
elif [ "$MMZ_DDR" == "768" ]
then
	/home/app/hisi/modules/load3536c -i 1 $chip_param
elif [ "$MMZ_DDR" == "180" ] || [ "$MMZ_DDR" == "200" ]
then
    echo "MA start with MMZ $MMZ_DDR"
	/home/app/hisi/modules/load3536c -i 2 0
fi
cd -

echo "####################################LOGO START################################################"
/home/app/exec/hik_dsp_logo  0  &
mv -f /home/app/lib/* /lib/
echo "load 3536 ok"

echo "----------<4> del no use res ----------"
rm -rf /home/app/hisi
rm -f /home/app/lib/*
rm -f /home/app/exec/dvrCmd.tar.gz

cd /home/app/exec
cp /sbin/vconfig /home/app/exec
/bin/chmod 777 /home/app/exec/vconfig

insmod vca_encrypt.ko

LANGUAGE=$(/usr/bin/awk -F:0x "/Id.language/ {print \$2}" /proc/hkvs/bootparam)

#�ر�TOE����Ҫ��TCP��SACK,��ֹ���绷�������µ��쳣
echo 1  > /proc/sys/net/ipv4/tcp_sack

echo "----------begain to load net filter modules--------"
cd net_filter
./load_netfiter -i
cd ../


/bin/chmod u+x ./iscsi/iscsid
./iscsi/iscsid&
./pppoed&
sleep 1
rm -f pppoed
rm -f iscsi/iscsid

echo 3 > /proc/sys/vm/drop_caches
if [ -e "/proc/sys/tnk/tnk_threshold" ];then
echo 0x100000 > /proc/sys/tnk/tnk_threshold
echo "!!! set tnk_threshold to 1M Ok !!! "
else
echo "!!! the device is not toe !!! "
fi

ulimit -n 8192

MA_RUN_SH="moviRun.sh"
if [ -f /home/app/exec/MA/$MA_RUN_SH ]; then
	cd /home/app/exec/MA/
	chmod 777 $MA_RUN_SH
	./$MA_RUN_SH
	cd -
	if [ $? == 0 ];then
		echo "run ma moviRun.sh ok!"
	else
		echo "run ma moviRun.sh error!"
	fi
fi

#����/tmp/psh�ļ�,�ں˿��Ծݴ��ж��Ƿ���dt��������-psh
echo -n > /tmp/psh

echo -e "\033[34m[ENVY] convert lib!\033[0m"
mv /lib/libplatform.so /lib/libplatform.so.bak
cp /nfs/booting/hikvision/patch_file/libplatform.so /lib/libplatform.so
mv /home/app/exec/sc_hicore /tmp/sc_hicore
cp /nfs/booting/hikvision/patch_file/sc_hicore /home/app/exec/sc_hicore

echo "start to start hik_dsp"
/home/app/exec/hik_dsp &

sleep 1
echo "start to start hik_app"
/home/app/exec/netOpenProc &
chmod 777 ./GPLProc
/home/app/exec/GPLProc &
sleep 1
/home/app/exec/master -M -P /home/app/exec &

# ���������ɾ���Ŀ¼�µĳ����ļ�
rm -f /home/app/exec/hik_dsp*
cp /home/app/exec/dbmem.html /home/app/webs

# ��������󣬽���̵Ľ�̺���Ϣд��gdb���������ļ���
if [ "$gdb" == "y" ];then
	mkdir /mnt/tools
	echo "=>Start mount $serverip:/${data}/${who}/nfs/${nfsdir} /mnt/tools"
	mount -t nfs -o intr,nolock,rsize=1024,wsize=1024 $serverip:/${data}/${who}/nfs/${nfsdir} /mnt/tools
	if [ $? -eq 0 ]; then
		echo "mount over"
		mkdir -p /mnt/tools/dev_tools/gdb/hisi_3536C/lib
		cp -f /lib/* /mnt/tools/dev_tools/gdb/hisi_3536C/lib/
		rm /mnt/tools/dev_tools/gdb/hisi_3536C/.config
		sleep 1
		echo "sc_hicore="`pidof sc_hicore` > /tmp/.config
		echo "master="`pidof master` >> /tmp/.config
		echo "dspcore="`pidof hik_dsp-1 || pidof hisi_dsp-2 || pidof hisi_dsp` >> /tmp/.config
		mv /tmp/.config /mnt/tools/dev_tools/gdb/hisi_3536C/
		umount /mnt/tools
	fi
fi
```

The "start.sh" script increased the timeout by allowing the "sc\_hicore" binary to run after counting nfs to change "libplatform.so " to patched "libplatform.so " and then moving the patched library to run the "sc\_hicore" binary. Therefore, the full script for this is as follows.

```bash
#! /bin/sh

echo -e "\\033[34m[ENVY] Starting!\\033[0m"
cat << "EOF"
███████╗███╗   ██╗██╗   ██╗██╗   ██╗
██╔════╝████╗  ██║██║   ██║╚██╗ ██╔╝
█████╗  ██╔██╗ ██║██║   ██║ ╚████╔╝
██╔══╝  ██║╚██╗██║╚██╗ ██╔╝  ╚██╔╝
███████╗██║ ╚████║ ╚████╔╝    ██║
╚══════╝╚═╝  ╚═══╝  ╚═══╝     ╚═╝
EOF

# This is a minmal rcS file for target startup
# Make sure that /proc is mounted.
## Modify by liweijie for DVR/NVR platform @2015-3-19

# Mount device or filesystem listed in /etc/fstab.
/bin/mount -a

# Application start below.
# Show current date.
/bin/date

echo -e "\\033[34m[ENVY] start nfs mount\\033[0m"
ifconfig lo 127.0.0.1 up
ifconfig eth0 192.168.0.104 up
route add default gw 192.168.0.1

sleep 5
mkdir /nfs
mkdir /nfs2
mount -t nfs -o vers=3,nolock 192.168.0.103:/volume3/nfs /nfs
mount -t nfs -o vers=3,nolock 192.168.0.103:/volume2/nfs2 /nfs2
echo -e "\\033[34m[ENVY] nfs mount success!\\033[0m"

mv /etc/rcS.d/S90start_ubifs /tmp/S90start_ubifs
cp /nfs/booting/hikvision/S90start_ubifs /etc/rcS.d/S90start_ubifs
echo -e "\\033[34m[ENVY] convert S90start_ubifs\\033[0m"

for initscript in /etc/rcS.d/S[0-9][0-9]*
do
	if [ -x $initscript ] ;
	then
		echo "[RCS]: $initscript"
		$initscript
	fi
done

export PATH=$PATH:/nfs/static_binary/bin

echo -e "\\033[34m[ENVY] run dropbear\\033[0m"
dropbear
mv /bin/psh /bin/psh_
ln -s /bin/sh /bin/psh

exit 0
```
