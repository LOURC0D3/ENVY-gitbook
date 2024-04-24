# File System Analysis Report

## 1. Overview

***

This document is a report described by Team.ENVY (Kim Chan-in, Park Myung-hoon, Shin Myung-jin, Yang Gang-min, and Lee Yoo-kyung) who carried out the BoB 12th NVR Vulnability Analysis project.

### 1.1. Necessity

File system analysis is essential to perform embedded vulnerability analysis. This is an essential step for identifying and deactivating watchdogs for debugging binary analysis that activates services for performing vulnerability analysis. Therefore, in this report, the contents of file system analysis to perform vulnerability analysis are described.

### 1.2. /etc/inittab

The contents of "/etc/initab" are as follows. First of all, when NVR is booted, the "/etc/init.d/rcS" file will be executed first.

When "/bin/dsh" is terminated, the process is created again, and when NVR is terminated, it can be seen that all devices are unmounted and the swap area is disabled.

```bash
::sysinit:/etc/init.d/rcS
::respawn:/bin/dsh
::restart:/sbin/init
::ctrlaltdel:/sbin/reboot
::shutdown:/bin/umount -a -r
::shutdown:/sbin/swapoff -a
```

## 2. Analyzing Boot Scripts

***

### 2.1. init script

#### 2.1.1. /etc/init.d/rcS

After mounting the device based on the information in "/etc/mtab" with the "/bin/mount -a" command, mount the device file system to the "/dev" path.

After that, run all scripts in the directory "/etc/init.d".

#### 2.1.2. /etc/init.d/S00devs

Devices related to device input are created, and device nodes are newly created.

#### 2.1.3. /etc/init.d/S01udev

A file system for device-related settings and debugging required for system initialization is mounted, and device management is performed by setting mdev.

#### 2.1.4. /etc/init.d/S80network

At boot time, the network setting is performed by extracting IP information from parameters transmitted to the kernel.

#### 2.1.5. /etc/init.d/S99Dahua

It mounts all file systems necessary for web services, and loads kernel modules to be used for service binaries.

After that, run the "/var/Challenge" binary.

### 2.2. Activation service analysis

#### 2.2.1. Aol

It is a binary used to upgrade and maintain devices online when they are abnormal.

#### 2.2.2. dvrhelper

Run the Challenge binary using "dvrhelper Challenge" in init script.

Within dvrhelper, debugging and binary execution-related behaviors vary depending on environmental variables.

#### 2.2.3. Challenge

It is the last binary that runs in init script and runs about 112 threads.

Various services such as web services, GUI, and ONVIF are executed in one binary.

In the case of Dahua, it is not possible to determine which services are performed by ps and top, so it can be confirmed through "/var/mem.text".

<details>

<summary>mem.text</summary>

end Fun:moduleMemInit , last = 0 , Fun-Use= 8452 , total = VmRSS: 8452 kB

end Fun:InitDvrSystem , last = 8536 , Fun-Use= 628 , total = VmRSS: 9164 kB

end Fun:AVS\_Init , last = 9164 , Fun-Use= 724 , total = VmRSS: 9888 kB

end Fun:CGIManager2Dahua2ProtocolAuthority , last = 9892 , Fun-Use= 984 , total = VmRSS: 10876 kB

end Fun:Ipv6Conflict , last = 10876 , Fun-Use= 12 , total = VmRSS: 10888 kB

end Fun:DeviceManager , last = 10888 , Fun-Use= 8 , total = VmRSS: 10896 kB

end Fun:RecordFinder , last = 10896 , Fun-Use= 12 , total = VmRSS: 10908 kB

end Fun:SecurityApp , last = 10908 , Fun-Use= 24 , total = VmRSS: 10932 kB

end Fun:MediaEncrypt , last = 10932 , Fun-Use= 32 , total = VmRSS: 10964 kB

end Fun:Snapshot , last = 10964 , Fun-Use= 12 , total = VmRSS: 10976 kB

end Fun:MediaForDahua2 , last = 10976 , Fun-Use= 0 , total = VmRSS: 10976 kB

end Fun:StreamApp , last = 10976 , Fun-Use= 128 , total = VmRSS: 11104 kB

end Fun:StreamForDahua2 , last = 11104 , Fun-Use= 8 , total = VmRSS: 11112 kB

end Fun:StorageForDahua2 , last = 11112 , Fun-Use= 0 , total = VmRSS: 11112 kB

end Fun:P2P , last = 11112 , Fun-Use= 24 , total = VmRSS: 11136 kB

end Fun:webapp , last = 11136 , Fun-Use= 8 , total = VmRSS: 11144 kB

end Fun:GDI , last = 11144 , Fun-Use= 20 , total = VmRSS: 11164 kB

end Fun:VFS , last = 11164 , Fun-Use= 4 , total = VmRSS: 11168 kB

end Fun:Database , last = 11168 , Fun-Use= 40 , total = VmRSS: 11208 kB

end Fun:AnalyseAdapterRecord , last = 11208 , Fun-Use= 28 , total = VmRSS: 11236 kB

end Fun:VideoStatServer , last = 11236 , Fun-Use= 4 , total = VmRSS: 11240 kB

end Fun:RemoteDevVideoAnalyse , last = 11240 , Fun-Use= 8 , total = VmRSS: 11248 kB

end Fun:LocalDevVideoAnalyse , last = 11248 , Fun-Use= 4 , total = VmRSS: 11252 kB

end Fun:RecordUpdater , last = 11252 , Fun-Use= 0 , total = VmRSS: 11252 kB

end Fun:RecordFinder , last = 11252 , Fun-Use= 4 , total = VmRSS: 11256 kB

end Fun:HeatMap , last = 11256 , Fun-Use= 28 , total = VmRSS: 11284 kB

end Fun:MasterSlave , last = 11284 , Fun-Use= 8 , total = VmRSS: 11292 kB

end Fun:FaceRecognition , last = 11292 , Fun-Use= 0 , total = VmRSS: 11292 kB

end Fun:RemoteFace , last = 11292 , Fun-Use= 24 , total = VmRSS: 11316 kB

end Fun:RemoteVideoIn , last = 11316 , Fun-Use= 8 , total = VmRSS: 11324 kB

end Fun:WLAN , last = 11324 , Fun-Use= 12 , total = VmRSS: 11336 kB

end Fun:Wireless , last = 11336 , Fun-Use= 4 , total = VmRSS: 11340 kB

end Fun:SecurityUnitCipher , last = 11340 , Fun-Use= 16 , total = VmRSS: 11356 kB

end Fun:DevInitPasswdFind , last = 11356 , Fun-Use= 16 , total = VmRSS: 11372 kB

end Fun:DNS , last = 11372 , Fun-Use= 12 , total = VmRSS: 11384 kB

end Fun:DHCP , last = 11384 , Fun-Use= 12 , total = VmRSS: 11396 kB

end Fun:NetApp , last = 11396 , Fun-Use= 4 , total = VmRSS: 11400 kB

end Fun:DDNS , last = 11400 , Fun-Use= 24 , total = VmRSS: 11424 kB

end Fun:NtpClient , last = 11424 , Fun-Use= 20 , total = VmRSS: 11444 kB

end Fun:SmtpClient , last = 11444 , Fun-Use= 4 , total = VmRSS: 11448 kB

end Fun:SNMP , last = 11448 , Fun-Use= 12 , total = VmRSS: 11460 kB

end Fun:DH3DevicePoint , last = 11460 , Fun-Use= 8 , total = VmRSS: 11468 kB

end Fun:DH2DevicePoint , last = 11468 , Fun-Use= 8 , total = VmRSS: 11476 kB

end Fun:NetCheck , last = 11476 , Fun-Use= 32 , total = VmRSS: 11508 kB

end Fun:NetAppDeviceDiscoveryIPV6 , last = 11508 , Fun-Use= 16 , total = VmRSS: 11524 kB

end Fun:NetAppDeviceDiscovery , last = 11524 , Fun-Use= 4 , total = VmRSS: 11528 kB

end Fun:LLDP , last = 11528 , Fun-Use= 12 , total = VmRSS: 11540 kB

end Fun:Diagnosis , last = 11540 , Fun-Use= 8 , total = VmRSS: 11548 kB

end Fun:CipherAesServer , last = 11548 , Fun-Use= 8 , total = VmRSS: 11556 kB

end Fun:CertManager , last = 11620 , Fun-Use= 12 , total = VmRSS: 11632 kB

end Fun:Comm , last = 11632 , Fun-Use= 64 , total = VmRSS: 11696 kB

end Fun:Dh3Authority , last = 11696 , Fun-Use= 784 , total = VmRSS: 12480 kB

end Fun:VideoComposite , last = 12524 , Fun-Use= 4 , total = VmRSS: 12528 kB

end Fun:AppIntelliTracker , last = 12528 , Fun-Use= 4 , total = VmRSS: 12532 kB

end Fun:OnvifDiscovery , last = 12532 , Fun-Use= 12 , total = VmRSS: 12544 kB

end Fun:DevPoe , last = 12544 , Fun-Use= 12 , total = VmRSS: 12556 kB

end Fun:StreamConvertor , last = 12560 , Fun-Use= 36 , total = VmRSS: 12596 kB

end Fun:NVRShare , last = 12596 , Fun-Use= 8 , total = VmRSS: 12604 kB

end Fun:DVRIPAll , last = 12604 , Fun-Use= 52 , total = VmRSS: 12656 kB

end Fun:Functions3 , last = 12656 , Fun-Use= 8 , total = VmRSS: 12664 kB

end Fun:DHCloudUpgrader , last = 12664 , Fun-Use= 12 , total = VmRSS: 12676 kB

end Fun:SecurityImExport , last = 12676 , Fun-Use= 0 , total = VmRSS: 12676 kB

end Fun:Performance , last = 12676 , Fun-Use= 12 , total = VmRSS: 12688 kB

end Fun:AppPresen , last = 12688 , Fun-Use= 24 , total = VmRSS: 12712 kB

end Fun:UserOperateError , last = 12712 , Fun-Use= 4 , total = VmRSS: 12716 kB

end Fun:OnvifUserOperateError , last = 12716 , Fun-Use= 0 , total = VmRSS: 12716 kB

end Fun:DigitalCertificate , last = 12716 , Fun-Use= 8 , total = VmRSS: 12724 kB

end Fun:CertBuild , last = 12724 , Fun-Use= 8 , total = VmRSS: 12732 kB

end Fun:802\_1x , last = 12732 , Fun-Use= 4 , total = VmRSS: 12736 kB

end Fun:IpTablesFilter , last = 12736 , Fun-Use= 12 , total = VmRSS: 12748 kB

end Fun:SystemSecurityCenter , last = 12748 , Fun-Use= 4 , total = VmRSS: 12752 kB

end Fun:WebInit , last = 12752 , Fun-Use= 4 , total = VmRSS: 12756 kB

end Fun:SnifferManager , last = 12756 , Fun-Use= 8 , total = VmRSS: 12764 kB

end Fun:ConfigRestore , last = 12764 , Fun-Use= 4 , total = VmRSS: 12768 kB

end Fun:StreamAppSSlSvr , last = 12768 , Fun-Use= 4 , total = VmRSS: 12772 kB

end Fun:RemoteFileM , last = 12772 , Fun-Use= 8 , total = VmRSS: 12780 kB

end Fun:RemoteSpeak , last = 12780 , Fun-Use= 4 , total = VmRSS: 12784 kB

end Fun:Diagnosis , last = 12784 , Fun-Use= 8 , total = VmRSS: 12792 kB

end Fun:Coaxial , last = 12792 , Fun-Use= 0 , total = VmRSS: 12792 kB

end Fun:SwitchPOE , last = 12924 , Fun-Use= 32 , total = VmRSS: 12956 kB

end Fun:NetFramework , last = 13076 , Fun-Use= 596 , total = VmRSS: 13672 kB

end Fun:Application , last = 13672 , Fun-Use= 20 , total = VmRSS: 13692 kB

end Fun:ScriptEngine , last = 13704 , Fun-Use= 600 , total = VmRSS: 14304 kB

end Fun:initpacket , last = 14312 , Fun-Use= 1408 , total = VmRSS: 15720 kB

end Fun:TimerManager , last = 15720 , Fun-Use= 0 , total = VmRSS: 15720 kB

end Fun:setCipher , last = 15720 , Fun-Use= 36 , total = VmRSS: 15756 kB

end Fun:CConfigManager::config , last = 15756 , Fun-Use= 24 , total = VmRSS: 15780 kB

end Fun:CIntelCfgMag::Config , last = 15780 , Fun-Use= 2492 , total = VmRSS: 18272 kB

end Fun:CCMOS::Initialize , last = 18272 , Fun-Use= 36 , total = VmRSS: 18308 kB

end Fun:g\_Challenger , last = 18308 , Fun-Use= 196 , total = VmRSS: 18504 kB

end Fun:getDefault , last = 18516 , Fun-Use= 28 , total = VmRSS: 18544 kB

end Fun:checkVersionMatch , last = 18552 , Fun-Use= 0 , total = VmRSS: 18552 kB

end Fun:CDevBackup , last = 18552 , Fun-Use= 48 , total = VmRSS: 18600 kB

end Fun:CDevCapture , last = 18600 , Fun-Use= 0 , total = VmRSS: 18600 kB

end Fun:GetScreenNum , last = 18600 , Fun-Use= 0 , total = VmRSS: 18600 kB

end Fun:CDevPlay::GetChannels , last = 18600 , Fun-Use= 40876 , total = VmRSS: 59476 kB

end Fun:CDevAudio , last = 59476 , Fun-Use= 236 , total = VmRSS: 59712 kB

end Fun:CDevMotionDetect , last = 59712 , Fun-Use= 0 , total = VmRSS: 59712 kB

end Fun:CDevAudioIn::GetChannels , last = 59712 , Fun-Use= 4 , total = VmRSS: 59716 kB

end Fun:GetSpeakOutChannels , last = 59716 , Fun-Use= 0 , total = VmRSS: 59716 kB

end Fun:NetGetCaps , last = 59716 , Fun-Use= 0 , total = VmRSS: 59716 kB

end Fun:NetGetEthDevice , last = 59720 , Fun-Use= 4 , total = VmRSS: 59724 kB

end Fun:NetGetDeviceName , last = 59724 , Fun-Use= 0 , total = VmRSS: 59724 kB

end Fun:FrontboardCom , last = 59724 , Fun-Use= 8320 , total = VmRSS: 68044 kB

end Fun:CDevPlay::instance , last = 68056 , Fun-Use= 16 , total = VmRSS: 68072 kB

end Fun:CResDataBase , last = 68072 , Fun-Use= 80 , total = VmRSS: 68152 kB

end Fun:ICapture::instance , last = 68152 , Fun-Use= 0 , total = VmRSS: 68152 kB

end Fun:CDevAudioIn , last = 68152 , Fun-Use= 224 , total = VmRSS: 68376 kB

end Fun:CDevGraphics , last = 68396 , Fun-Use= 64 , total = VmRSS: 68460 kB

end Fun:CDevVideoCDevSplit , last = 68460 , Fun-Use= 0 , total = VmRSS: 68460 kB

end Fun:CDecoderCapsCDevMonitor , last = 68460 , Fun-Use= 0 , total = VmRSS: 68460 kB

end Fun:selectPath , last = 68460 , Fun-Use= 28 , total = VmRSS: 68488 kB

end Fun:setLanguage , last = 68488 , Fun-Use= 316 , total = VmRSS: 68804 kB

end Fun:InitLibNetClient , last = 68804 , Fun-Use= 296 , total = VmRSS: 69100 kB

end Fun:g\_Config.initialize , last = 69100 , Fun-Use= 2412 , total = VmRSS: 71512 kB

end Fun:checkConfig , last = 71512 , Fun-Use= 0 , total = VmRSS: 71512 kB

end Fun:g\_General.Start , last = 71520 , Fun-Use= 2320 , total = VmRSS: 73840 kB

end Fun:CRPCServerstart , last = 73840 , Fun-Use= 1712 , total = VmRSS: 75552 kB

end Fun:NewUPnP , last = 75564 , Fun-Use= 4 , total = VmRSS: 75568 kB

end Fun:g\_GUI.Start , last = 75636 , Fun-Use= 632 , total = VmRSS: 76268 kB

end Fun:CheckCrossMarket , last = 76268 , Fun-Use= 0 , total = VmRSS: 76268 kB

end Fun:NetServiceInit , last = 76268 , Fun-Use= 704 , total = VmRSS: 76972 kB

end Fun:setDeviceInfo , last = 76972 , Fun-Use= 0 , total = VmRSS: 76972 kB

end Fun:CDatabase::config , last = 76972 , Fun-Use= 72 , total = VmRSS: 77044 kB

end Fun:g\_Log.config , last = 77044 , Fun-Use= 96 , total = VmRSS: 77140 kB

end Fun:removeLogDB\_backup , last = 77140 , Fun-Use= 0 , total = VmRSS: 77140 kB

end Fun:g\_VFSFileSystemManagerInit , last = 77140 , Fun-Use= 16 , total = VmRSS: 77156 kB

end Fun:g\_Log.Init , last = 77156 , Fun-Use= 568 , total = VmRSS: 77724 kB

end Fun:IVQA , last = 77724 , Fun-Use= 0 , total = VmRSS: 77724 kB

end Fun:IVideoStatServer , last = 77724 , Fun-Use= 40 , total = VmRSS: 77764 kB

end Fun:IHeatMap , last = 77764 , Fun-Use= 40 , total = VmRSS: 77804 kB

end Fun:CertServerManager , last = 77804 , Fun-Use= 328 , total = VmRSS: 78132 kB

end Fun:I802\_1x , last = 78148 , Fun-Use= 88 , total = VmRSS: 78236 kB

end Fun:IIPTablesFilter , last = 78236 , Fun-Use= 808 , total = VmRSS: 79044 kB

end Fun:ISystemSecurityCenter , last = 79056 , Fun-Use= 16 , total = VmRSS: 79072 kB

end Fun:Dahua::RemoteApp::CConfigMgrRemote , last = 79072 , Fun-Use= 96 , total = VmRSS: 79168 kB

end Fun:g\_ConfigInfo\_Log , last = 79168 , Fun-Use= 96 , total = VmRSS: 79264 kB

end Fun:FileInfo\_Log , last = 79264 , Fun-Use= 12 , total = VmRSS: 79276 kB

end Fun:CRemoteLog , last = 79276 , Fun-Use= 4 , total = VmRSS: 79280 kB

end Fun:CHddFSLog , last = 79280 , Fun-Use= 0 , total = VmRSS: 79280 kB

end Fun:CSystemInfoLog , last = 79280 , Fun-Use= 4 , total = VmRSS: 79284 kB

end Fun:g\_DriverManager , last = 79288 , Fun-Use= 76 , total = VmRSS: 79364 kB

end Fun:g\_HDDDetectManager , last = 79364 , Fun-Use= 8 , total = VmRSS: 79372 kB

end Fun:g\_DriverManager.Start , last = 79392 , Fun-Use= 1616 , total = VmRSS: 81008 kB

end Fun:IRecordUpdater , last = 81008 , Fun-Use= 16 , total = VmRSS: 81024 kB

end Fun:g\_Raid.Start , last = 81024 , Fun-Use= 0 , total = VmRSS: 81024 kB

end Fun:g\_BackupRestore , last = 81024 , Fun-Use= 64 , total = VmRSS: 81088 kB

end Fun:g\_FileLock , last = 81088 , Fun-Use= 0 , total = VmRSS: 81088 kB

end Fun:g\_AutoMaintain , last = 81088 , Fun-Use= 8 , total = VmRSS: 81096 kB

end Fun:g\_Play , last = 81096 , Fun-Use= 4376 , total = VmRSS: 85472 kB

end Fun:g\_DisplayTour , last = 85472 , Fun-Use= 12 , total = VmRSS: 85484 kB

end Fun:CSplitManager , last = 85488 , Fun-Use= 44 , total = VmRSS: 85532 kB

end Fun:g\_Display.Start , last = 85532 , Fun-Use= 2064 , total = VmRSS: 87596 kB

end Fun:g\_UserManage , last = 87596 , Fun-Use= 24 , total = VmRSS: 87620 kB

end Fun:IUserManager , last = 87620 , Fun-Use= 12 , total = VmRSS: 87632 kB

end Fun:SetStreetModeEx , last = 87632 , Fun-Use= 0 , total = VmRSS: 87632 kB

end Fun:PtzStart , last = 87632 , Fun-Use= 592 , total = VmRSS: 88224 kB

end Fun:g\_Encode.Start , last = 88224 , Fun-Use= 1096 , total = VmRSS: 89320 kB

end Fun:IConsole , last = 89344 , Fun-Use= 36 , total = VmRSS: 89380 kB

end Fun:g\_Daylight.Start , last = 89388 , Fun-Use= 8 , total = VmRSS: 89396 kB

end Fun:LogoClose , last = 89396 , Fun-Use= 0 , total = VmRSS: 89396 kB

end Fun:SetTVMargin , last = 89396 , Fun-Use= 0 , total = VmRSS: 89396 kB

end Fun:g\_HddGroup.Start , last = 89396 , Fun-Use= 20 , total = VmRSS: 89416 kB

end Fun:ISnapManager.start , last = 89416 , Fun-Use= 1192 , total = VmRSS: 90608 kB

end Fun:g\_GUI.CreatePages , last = 90608 , Fun-Use= 2180 , total = VmRSS: 92788 kB

end Fun:g\_GUI.createMainMenuRegisterPage , last = 92788 , Fun-Use= 3152 , total = VmRSS: 95940 kB

end Fun:g\_GUI.EnableCursor , last = 95940 , Fun-Use= 4 , total = VmRSS: 95944 kB

end Fun:g\_GUI.Login , last = 95944 , Fun-Use= 52 , total = VmRSS: 95996 kB

end Fun:IVideoInAnalyse , last = 95996 , Fun-Use= 556 , total = VmRSS: 96552 kB

end Fun:CDevPoe , last = 96572 , Fun-Use= 0 , total = VmRSS: 96572 kB

end Fun:CNetClientManager , last = 96572 , Fun-Use= 688 , total = VmRSS: 97260 kB

end Fun:CDevPoestart , last = 97264 , Fun-Use= 372 , total = VmRSS: 97636 kB

end Fun:CSplitManager , last = 97636 , Fun-Use= 0 , total = VmRSS: 97636 kB

end Fun:RemoteApp::CRemoteEventManager , last = 97636 , Fun-Use= 0 , total = VmRSS: 97636 kB

end Fun:g\_DisplayTour.Start , last = 97636 , Fun-Use= 0 , total = VmRSS: 97636 kB

end Fun:checkVideoOutCfg , last = 97636 , Fun-Use= 0 , total = VmRSS: 97636 kB

end Fun:g\_Record.Start , last = 97636 , Fun-Use= 44 , total = VmRSS: 97680 kB

end Fun:g\_AudioManager.init , last = 97680 , Fun-Use= 224 , total = VmRSS: 97904 kB

end Fun:NetServiceStart , last = 97952 , Fun-Use= 1584 , total = VmRSS: 99536 kB

end Fun:g\_Net3G.Start , last = 99536 , Fun-Use= 0 , total = VmRSS: 99536 kB

end Fun:initArch3Adaptor , last = 99536 , Fun-Use= 4 , total = VmRSS: 99540 kB

end Fun:g\_VFSFileSystemManager.Start , last = 99548 , Fun-Use= 72 , total = VmRSS: 99620 kB

end Fun:g\_FlashStat.Init.Start , last = 99620 , Fun-Use= 1048 , total = VmRSS: 100668 kB

end Fun:g\_NetApp.Start , last = 100668 , Fun-Use= 2184 , total = VmRSS: 102852 kB

end Fun:g\_SmtpClient.Start , last = 102852 , Fun-Use= 16 , total = VmRSS: 102868 kB

end Fun:CDownloadOfflineRec , last = 102868 , Fun-Use= 8 , total = VmRSS: 102876 kB

end Fun:g\_FtpClient , last = 102876 , Fun-Use= 24 , total = VmRSS: 102900 kB

end Fun:g\_DdnsClient , last = 102900 , Fun-Use= 0 , total = VmRSS: 102900 kB

end Fun:g\_DhcpClient , last = 102900 , Fun-Use= 0 , total = VmRSS: 102900 kB

end Fun:g\_NtpClient , last = 102900 , Fun-Use= 0 , total = VmRSS: 102900 kB

end Fun:g\_Backup , last = 102900 , Fun-Use= 64 , total = VmRSS: 102964 kB

end Fun:g\_SNMP , last = 102964 , Fun-Use= 0 , total = VmRSS: 102964 kB

end Fun:CommPort , last = 102964 , Fun-Use= 4 , total = VmRSS: 102968 kB

end Fun:StartDebug , last = 102968 , Fun-Use= 4 , total = VmRSS: 102972 kB

end Fun:DVRIPstart , last = 102972 , Fun-Use= 7688 , total = VmRSS: 110660 kB

end Fun:AlarmBox , last = 110660 , Fun-Use= 0 , total = VmRSS: 110660 kB

end Fun:pAlarm.Start , last = 110660 , Fun-Use= 672 , total = VmRSS: 111332 kB

end Fun:g\_RtspSvr\_V3 , last = 111452 , Fun-Use= 496 , total = VmRSS: 111948 kB

end Fun:CSecurityServiceApp\_WebSvr , last = 111948 , Fun-Use= 336 , total = VmRSS: 112284 kB

end Fun:g\_UpnpClient , last = 112284 , Fun-Use= 8 , total = VmRSS: 112292 kB

end Fun:CDevPoestartAddDevice , last = 112448 , Fun-Use= 0 , total = VmRSS: 112448 kB

end Fun:IWizardManagerPtr , last = 112448 , Fun-Use= 0 , total = VmRSS: 112448 kB

end Fun:ProviderService , last = 112448 , Fun-Use= 28 , total = VmRSS: 112476 kB

end Fun:INtpServerPtr , last = 112476 , Fun-Use= 84 , total = VmRSS: 112560 kB

end Fun:IntervideoOnvif , last = 112616 , Fun-Use= 460 , total = VmRSS: 113076 kB

end Fun:ICloudUpgrader , last = 113076 , Fun-Use= 112 , total = VmRSS: 113188 kB

end Fun:IP2Pstart , last = 113188 , Fun-Use= 48 , total = VmRSS: 113236 kB

end Fun:InitDefaultConfig , last = 113236 , Fun-Use= 16 , total = VmRSS: 113252 kB

end Fun:InitPaaS , last = 113252 , Fun-Use= 636 , total = VmRSS: 113888 kB

end Fun:InitSaaS , last = 113888 , Fun-Use= 116 , total = VmRSS: 114004 kB

end Fun:vkManager , last = 114004 , Fun-Use= 56 , total = VmRSS: 114060 kB

end Fun:StreamAppRtspWebSocket , last = 114060 , Fun-Use= 4 , total = VmRSS: 114064 kB

end Fun:g\_InterVideo , last = 114104 , Fun-Use= 0 , total = VmRSS: 114104 kB

</details>

### 2.3. Check mount

After the boot is complete, the following results can be obtained by executing the mount command.

```c
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

With the exception of some directories, web-related directories, /bin, /etc, etc., are all read-only with the squashfs file system.

### 2.4. Watchdog Analysis

When the Challenge binary is terminated, the device is rebooted after a certain period of time.

#### 2.4.1. Challenge

After opening the "/dev/watchdog" device in the sub\_186A9A4 function, it was confirmed that C was continuously input using the write function to feed.

```c
int sub_186A9A4()
{
  int v0; // r0
  int v1; // r4

  v0 = j_open_1("/dev/watchdog", 2);
  v1 = v0;
  if ( v0 < 0 )
  {
    sub_190D128(
      0,
      1,
      "[LIBDVR@57888] ERROR  (%s|%d): create watchdog failed(%s).\n",
      "WdgLinuxStandKeepAlive",
      205,
      "/dev/watchdog");
    return -1;
  }
  if ( j_write_0(v0, "C", 2u) != 2 )
  {
    sub_190D128(0, 1, "[LIBDVR@57888] ERROR  (%s|%d): write watchdog \"C\" failed.\n", "WdgLinuxStandKeepAlive", 211);
    j_close_1(v1);
    return -1;
  }
  j_close_1(v1);
  return 0;
}
```

Therefore, the following bash script was written to prevent the device from rebooting.

```bash
#!/bin/sh
while true; do
		echo -n "C" > /dev/watchdog
		sleep 1
done
```
