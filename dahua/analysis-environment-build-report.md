# Analysis Environment Build Report

## 1. Overview

***

This document is a report written by Team.ENVY (Chan-in Kim, Myung-hoon Park, Myeong-jin Shin, Kang-min Yang, Lee Yu-kyung), who carried out the KITRI BoB 12th NVR Vulnerability Analysis project, on the construction of the Dahua analysis environment.

### 1.1. Necessity

In order to analyze Dahua's vulnerabilities, debugging the binary that activates the service is essential. Therefore, this document describes how to debug by bypassing watchdog and Dahua's shell access restrictions.

## 2. Analysis

***

In the case of Dahua, after Challenge, the binary responsible for the service, is executed, the shell cannot be used, and a prompt where only a few commands can be executed is executed.

You can perform functions such as checking device status and changing settings at this prompt, but escaping was essential because gdb must be run through a shell to build an analysis environment.

Administrators can activate ssh using the web interface and GUI, but Dahua's self-produced dsh is executed, and the shell is very limited to 4 usable commands.

Therefore, it was necessary to make some modifications to the booting process through UART communication.

First, the commands that Dahua's U-Boot can use are limited compared to regular U-Boot.

There were no common commands like printenv.

```
MStar # printenv
Unknown command 'printenv' - try 'help'
```

However, this could be bypassed as follows.

```
MStar # setenv bootargs $(bootargs)
console=ttyS0 root=/dev/mtdblock3 rootfstype=squashfs ro init=/linuxrc LX_MEM=0x3D000000 mma_heap=mma_heap_name0,miu=0,sz=0x6000000 mma_heap=mma_heap_low_memory,miu=0,sz=0xF000000,max_off=0x1E000000 resolution=DACOUT_1080P_60 mtdparts=nand0:0x140000@0x000000(param),4m(uboot),2m(env),49408k(romfs),2m(custom),15m(web),2m(logo),512k(dgs),41m(ext_usr),2m(config_fw),-(config)
```

Additionally, the contents of all environment variables were dumped through nand read and the environment variables were output.

```
YDEVID=DHI-NVR4104HS-P-4KS2/L
HWID=00000000000000
ID=7L073F4PAZ19639
PRODUCTID=000000000000000000
UpgradeImage=SigmastarUpgrade.bin
appauto=1
authcode=000000
autogw=192.168.1.1
autolip=192.168.1.108
autonm=255.255.255.0
autosip=192.168.254.254
baudrate=115200
board_sn=000000000000
bootargs=console=ttyS0 root=/dev/mtdblock3 rootfstype=squashfs ro init=/linuxrc LX_MEM=0x3D000000 mma_heap=mma_heap_name0,miu=0,sz=0x6000000 mma_heap=mma_heap_low_memory,miu=0,sz=0xF000000,max_off=0x1E000000 resolution=DACOUT_1080P_60 mtdparts=nand0:0x140000@0x000000(param),4m(uboot),2m(env),49408k(romfs),2m(custom),15m(web),2m(logo),512k(dgs),41m(ext_usr),2m(config_fw),-(config)
bootcmd=bootlogo; fb_needreset; usbupdate; autoup; fsload; bootm 0x2E400000;
bootdelay=1
da=tftp u-boot.bin.img; flwrite
dbgLevel=INFO
dc=tftp custom-x.squashfs.img; flwrite
deviceid=000000000000000000
dh_keyboard=1
dl=tftp logo-x.squashfs.img; flwrite
dp=tftp param.bin.img; flwrite
dr=tftp romfs-x.squashfs.img; flwrite
du=tftp eusr-x.squashfs.img; flwrite
dw=tftp web-x.squashfs.img; flwrite
encrypbackup=mac[c0:39:5a:44:96:96]id[7L073F4PAZ19639]
eracfg_flag=0
eth1addr=A0:BD:1D:B4:AB:C2
eth2addr=A0:BD:1D:B4:AB:C3
ethact=mstar_emac
ethaddr=c0:39:5a:44:96:96
gatewayip=192.168.0.1
ipaddr=192.168.0.101
key=000000000000000000
load_modules=1
mtdids=nand0=nand0
mtdparts=mtdparts=nand0:0x140000@0x000000(param),4m(uboot),2m(env),49408k(romfs),2m(custom),15m(web),2m(logo),512k(dgs),41m(ext_usr),2m(config_fw),-(config)
nand_erasesize=20000
nand_oobsize=40
nand_writesize=800
net_mode=66625
netmask=255.255.255.0
netretry=no
randomcode=62334755909895063813748386068935
restore=0
securitycode=000000
serverip=164.124.101.2
stderr=serial
stdin=serial
stdout=serial
tftptimeout=1000
tk=tftp uImage; bootm
tracode=000000000000
up=tftp update.img; flwrite
update_state=0
updatetimeout=0
usb_folder=images
ID=7L073F4PAZ19639
DEVID=DHI-NVR4104HS-P-4KS2/L
HWID=00000000000000
PRODUCTID=000000000000000000
authcode=000000
board_sn=000000000000
ethaddr=c0:39:5a:44:96:96
eth1addr=A0:BD:1D:B4:AB:C2
eth2addr=A0:BD:1D:B4:AB:C3
serverip=164.124.101.2
ipaddr=192.168.0.101
gatewayip=192.168.0.1
netmask=255.255.255.0
deviceid=000000000000000000
key=000000000000000000
restore=0
encrypbackup=mac[c0:39:5a:44:96:96]id[7L073F4PAZ19639]
securitycode=000000
tracode=000000000000
randomcode=62334755909895063813748386068935
update_state=0
ID=7L073F4PAZ19639
DEVID=DHI-NVR4104HS-P-4KS2/L
HWID=00000000000000
PRODUCTID=000000000000000000
authcode=000000
board_sn=000000000000
ethaddr=c0:39:5a:44:96:96
eth1addr=A0:BD:1D:B4:AB:C2
eth2addr=A0:BD:1D:B4:AB:C3
serverip=164.124.101.2
ipaddr=192.168.0.101
gatewayip=192.168.0.1
netmask=255.255.255.0
deviceid=000000000000000000
key=000000000000000000
restore=0
encrypbackup=mac[c0:39:5a:44:96:96]id[7L073F4PAZ19639]
securitycode=000000
tracode=000000000000
randomcode=62334755909895063813748386068935
update_state=0
```

Afterwards, I changed the init variable in bootargs to /bin/sh, but I didn't get a shell.

Also, “Starting Kernel…” After confirming that the kernel boot log was not output, it was determined that the problem was related to standard output.

We confirmed that the dh\_keyboard environment variable is a variable that changes the kernel output mode, and changed the variable's value as follows.

```
 MStar # setenv -f dh_keyboard 0
```

Afterwards, I was able to check the kernel output.

Before executing the init script, I tried to run ash by modifying the contents of /etc/passwd, but modification was not possible because all directories except /var, /root, and /dev were read-only.

Therefore, an attempt was made to modify /etc/passwd through bind mount, but the integrity of the read-only file system was verified during initialization of the challenge binary, and if the verification failed, it was rebooted.

```
cp /etc/passwd /var/passwd
mount --bind /var/passwd /etc/passwd
```

Through the script written in /etc/init.d, all services up to just before the challenge binary was executed were activated to enable all functions in the shell, and then the nfs was mounted to enable the analysis binary.

```
mount -t nfs -o vers=3,nolock 192.168.0.103:/volume3/nfs /nfs 
```

I ran the challenge in the background and redirected the output so that the shell is still available after the challenge runs.

```
dvrhelper /var/Challenge > /dev/null &
```

After executing the challenge, the bind mount command could not be executed as if it were prohibited.

Therefore, all of the above restrictions were bypassed through the following steps.

1. Clone /etc/passwd to a writable location using the cp command.
2. Perform bind mount immediately before running the challenge (however, the file contents must not be changed)
3. After the initialization process has been completed in the Challenge binary and the service is running normally, change /etc/passwd contents (dsh → ash)
4. Perform nfs server mount

## 3. Analysis environment construction boot script

***

Modify the contents of rcS and run all init scripts except S99Dahua.

```
ROOTMNT=/mnt
mount -t devtmpfs none /dev
mount -t proc proc /proc
insmod /lib/modules/4.9.37/kernel/crypto.ko
insmod /lib/modules/4.9.37/kernel/fwcrypto.ko
mount -rw /dev/mtdblock3 /mnt
mount -t squashfs /dev/gpfwdecrypt_dev /root/

exec switch_root /root /bin/sh

/bin/mount -a

mount -t devtmpfs none /dev

/etc/init.d/S00devs
/etc/init.d/S01udev
/etc/init.d/S80network
```

Modify the contents of S99Dahua to background the Challenge binary and redirect output.

```
cat << 'EOF' > /var/S99Dahua
#!/bin/sh

source /etc/profile

mount -t squashfs /dev/mtdblock8 /mnt/ext_usr
mount -t squashfs /dev/mtdblock5 /mnt/web
mount -t squashfs /dev/mtdblock4 /mnt/custom
mount -t cramfs /dev/mtdblock6 /mnt/logo
mount -t ramfs /dev/mem /var

CONFIG_NUM=`cat /proc/mtd |grep -w "config"|awk -F':' '{print $1}' | grep -Eo '[0-9]+'`
ubiattach /dev/ubi_ctrl -b 4 -m $CONFIG_NUM -d 0
if [ $? -ne 0 ] ; then
   echo "Partition Config doesn't format"
   ubiformat /dev/mtd$CONFIG_NUM -y
   ubiattach /dev/ubi_ctrl -b 4 -m $CONFIG_NUM -d 0
else
  echo "ubiattch /dev/mtdblock$CONFIG_NUM OK"
fi

volnum=`ubinfo -a /dev/ubi0 | grep "Volumes count"|awk -F':' '{printf $2}'`

if [ $volnum -ne 0 ]; then
    echo "Partition Config already has vol"
    mount -t ubifs /dev/ubi0_0 /mnt/mtd/
else
    echo "Parition Config hasn't vol"
    ubimkvol /dev/ubi1 -m -N Config
    mount -t ubifs /dev/ubi0_0 /mnt/mtd/
fi

if [ $? -ne 0 ] ; then
    ubidetach -m $CONFIG_NUM
    ubiformat /dev/mtd$CONFIG_NUM -y
    ubiattach /dev/ubi_ctrl -b 4 -m $CONFIG_NUM -d 0
    ubimkvol /dev/ubi0 -m -N Config
    mount -t ubifs /dev/ubi0_0 /mnt/mtd
    mkdir -p /mnt/mtd/Config
    touch /mnt/mtd/Config/eracfg-finish
fi

mkdir -p /mnt/mtd/Config /mnt/mtd/Log /var/tmp

touch /var/udhcpd.leases
rm /mnt/mtd/Config/udhcpd.leases
ln -s /var/udhcpd.leases /mnt/mtd/Config/udhcpd.leases

if [ ! -f /mnt/mtd/Config/reboot_cnt.txt ]; then
    echo sys_reboot_cnt=0 > /mnt/mtd/Config/reboot_cnt.txt
fi
val=`cat /mnt/mtd/Config/reboot_cnt.txt|busybox sed 's/[^0-9]//g'`
let val=0
busybox sed -i 's/sys_reboot_cnt=.*/sys_reboot_cnt='$val'/g' /mnt/mtd/Config/reboot_cnt.txt

echo 5 > /proc/sys/vm/dirty_ratio
echo 8192 > /proc/sys/vm/min_free_kbytes
echo 200 > /proc/sys/vm/vfs_cache_pressure
echo f > /sys/class/net/eth0/queues/rx-0/rps_cpus
echo 4096 > /sys/class/net/eth0/queues/rx-0/rps_flow_cnt
echo 4096 > /proc/sys/net/core/rps_sock_flow_entries
echo 1 > /proc/sys/net/ipv4/conf/all/arp_filter
echo 307200 > /proc/sys/net/core/rmem_max

echo 0 > /proc/sys/net/ipv4/tcp_window_scaling
#echo 2000 > /proc/sys/net/core/netdev_max_backlog

echo 1 > /proc/sys/vm/overcommit_memory

p7zip x /usr/lib/lib.7z /var/

cat /proc/dahua/loadmodules | (read key value; if [ "$value" != "0" ];then
        /usr/etc/load_modules.sh
fi)

ifconfig lo up
ifconfig eth0 up

netinit
#busybox telnetd -l /bin/sh &

udhcpd -f&

net3g &
#rm /var/lib/* -rf
p7zip x /usr/bin/Challenge.7z /var
p7zip x /usr/bin/Aol.7z /var
chmod 777 /var/Challenge
chmod 777 /var/Aol

chmod -R 777 /var/*
sendboot 192.168.254.254 8899
echo 1 > /proc/sys/vm/drop_caches

mkdir -p /var/empty/sshd
chown root:root /var/empty/sshd
chmod 755 /var/empty/sshd

appauto= cat /proc/cmdline | busybox sed "s/ /\n/g" | grep "appauto" | busybox sed "s/[^0-9]//g"
if [ "$appauto" == "1" ]
then
 /var/Aol &
fi

ulimit -Sc unlimited
dvrhelper /var/Challenge > /dev/null &

#ulimit -Sc unlimited;cd /home;dvrhelper /var/Challenge
EOF
```

To mount a writable directory, run part of the contents of S99Dahua first.

```
source /etc/profile

mount -t squashfs /dev/mtdblock8 /mnt/ext_usr
mount -t squashfs /dev/mtdblock5 /mnt/web
mount -t squashfs /dev/mtdblock4 /mnt/custom
mount -t cramfs /dev/mtdblock6 /mnt/logo
mount -t ramfs  /dev/mem  /var
```

Copy the contents of the read-only directory to a writable location and perform bind mount.

```
cp /etc/passwd /var/passwd
mount --bind /var/passwd /etc/passwd

cp -r /bin /var/bin
mount --bind /var/bin /bin

cp -r /lib /var/lib
mount --bind /var/lib /lib
```

Run the modified S99Dahua.

```
chmod +x /var/S99Dahua
/var/S99Dahua
```

Afterwards, change the nfs server mount and /etc/passwd.

```
mount -t nfs -o vers=3,nolock 192.168.0.103:/volume3/nfs /nfs 

cat << 'EOF' > /etc/passwd
root:x:0:0:root:/:/bin/ash
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
admin:x:0:0:root,,,:/:/bin/ash
EOF
```

The full boot script is as follows.

```
ROOTMNT=/mnt
mount -t devtmpfs none /dev
mount -t proc proc /proc
insmod /lib/modules/4.9.37/kernel/crypto.ko
insmod /lib/modules/4.9.37/kernel/fwcrypto.ko
mount -rw /dev/mtdblock3 /mnt
mount -t squashfs /dev/gpfwdecrypt_dev /root/

exec switch_root /root /bin/sh
```

```
/bin/mount -a

mount -t devtmpfs none /dev

/etc/init.d/S00devs
/etc/init.d/S01udev
/etc/init.d/S80network

source /etc/profile

mount -t squashfs /dev/mtdblock8 /mnt/ext_usr
mount -t squashfs /dev/mtdblock5 /mnt/web
mount -t squashfs /dev/mtdblock4 /mnt/custom
mount -t cramfs /dev/mtdblock6 /mnt/logo
mount -t ramfs  /dev/mem  /var

cp /etc/passwd /var/passwd
mount --bind /var/passwd /etc/passwd

cp -r /bin /var/bin
mount --bind /var/bin /bin

cp -r /lib /var/lib
mount --bind /var/lib /lib

cat << 'EOF' > /var/S99Dahua
#!/bin/sh

CONFIG_NUM=`cat /proc/mtd |grep -w "config"|awk -F':' '{print $1}' | grep -Eo '[0-9]+'`
ubiattach /dev/ubi_ctrl -b 4 -m $CONFIG_NUM -d 0
if [ $? -ne 0 ] ; then
   echo "Partition Config doesn't format"
   ubiformat /dev/mtd$CONFIG_NUM -y
   ubiattach /dev/ubi_ctrl -b 4 -m $CONFIG_NUM -d 0
else
  echo "ubiattch /dev/mtdblock$CONFIG_NUM OK"
fi

volnum=`ubinfo -a /dev/ubi0 | grep "Volumes count"|awk -F':' '{printf $2}'`

if [ $volnum -ne 0 ]; then
    echo "Partition Config already has vol"
    mount -t ubifs /dev/ubi0_0 /mnt/mtd/
else
    echo "Parition Config hasn't vol"
    ubimkvol /dev/ubi1 -m -N Config
    mount -t ubifs /dev/ubi0_0 /mnt/mtd/
fi

if [ $? -ne 0 ] ; then
    ubidetach -m $CONFIG_NUM
    ubiformat /dev/mtd$CONFIG_NUM -y
    ubiattach /dev/ubi_ctrl -b 4 -m $CONFIG_NUM -d 0
    ubimkvol /dev/ubi0 -m -N Config
    mount -t ubifs /dev/ubi0_0 /mnt/mtd
    mkdir -p /mnt/mtd/Config
    touch /mnt/mtd/Config/eracfg-finish
fi

mkdir -p /mnt/mtd/Config /mnt/mtd/Log /var/tmp

touch /var/udhcpd.leases
rm /mnt/mtd/Config/udhcpd.leases
ln -s /var/udhcpd.leases /mnt/mtd/Config/udhcpd.leases

if [ ! -f /mnt/mtd/Config/reboot_cnt.txt ]; then
    echo sys_reboot_cnt=0 > /mnt/mtd/Config/reboot_cnt.txt
fi
val=`cat /mnt/mtd/Config/reboot_cnt.txt|busybox sed 's/[^0-9]//g'`
let val=0
busybox sed -i 's/sys_reboot_cnt=.*/sys_reboot_cnt='$val'/g' /mnt/mtd/Config/reboot_cnt.txt

echo 5 > /proc/sys/vm/dirty_ratio
echo 8192 > /proc/sys/vm/min_free_kbytes
echo 200 > /proc/sys/vm/vfs_cache_pressure
echo f > /sys/class/net/eth0/queues/rx-0/rps_cpus
echo 4096 > /sys/class/net/eth0/queues/rx-0/rps_flow_cnt
echo 4096 > /proc/sys/net/core/rps_sock_flow_entries
echo 1 > /proc/sys/net/ipv4/conf/all/arp_filter
echo 307200 > /proc/sys/net/core/rmem_max

echo 0 > /proc/sys/net/ipv4/tcp_window_scaling
#echo 2000 > /proc/sys/net/core/netdev_max_backlog

echo 1 > /proc/sys/vm/overcommit_memory

p7zip x /usr/lib/lib.7z /var/

cat /proc/dahua/loadmodules | (read key value; if [ "$value" != "0" ];then
        /usr/etc/load_modules.sh
fi)

ifconfig lo up
ifconfig eth0 up

netinit
#busybox telnetd -l /bin/sh &

udhcpd -f&

net3g &
#rm /var/lib/* -rf
p7zip x /usr/bin/Challenge.7z /var
p7zip x /usr/bin/Aol.7z /var
chmod 777 /var/Challenge
chmod 777 /var/Aol

chmod -R 777 /var/*
sendboot 192.168.254.254 8899
echo 1 > /proc/sys/vm/drop_caches

mkdir -p /var/empty/sshd
chown root:root /var/empty/sshd
chmod 755 /var/empty/sshd

appauto= cat /proc/cmdline | busybox sed "s/ /\n/g" | grep "appauto" | busybox sed "s/[^0-9]//g"
if [ "$appauto" == "1" ]
then
 /var/Aol &
fi

ulimit -Sc unlimited
dvrhelper /var/Challenge > /dev/null &

#ulimit -Sc unlimited;cd /home;dvrhelper /var/Challenge
EOF

chmod +x /var/S99Dahua
/var/S99Dahua
```

```
mount -t nfs -o vers=3,nolock 192.168.0.103:/volume3/nfs /nfs 

cat << 'EOF' > /etc/passwd
root:x:0:0:root:/:/bin/ash
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
admin:x:0:0:root,,,:/:/bin/ash
EOF

cat << 'EOF' > /bin/watchdog.sh
#!/bin/sh
while true; do
        echo -n "C" > /dev/watchdog
        sleep 1
done
EOF

sh /bin/watchdog.sh&
```
