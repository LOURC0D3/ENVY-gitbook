# Binary Analysis Report



## 1. Overview

***

This document is a report described by Team.ENVY (Kim Chan-in, Park Myung-hoon, Shin Myung-jin, Yang Kang-min, and Lee Yoo-kyung), who carried out the BoB 12th NVR Vulnability Analysis project.

### 1.1. Necessity

Analysis of web service operation method is essential for Dahua's vulnerability analysis. Therefore, we want to analyze the binary used by Dahua for vulnerability analysis.

## 2. challenge

***

### 2.1. main

When the binary is executed, the main function first goes through the device initialization process.

After sending arbitrary commands to the `/dev/dh_resource` device using the ioctl function, the initialization work is performed using the acquired data.

```cpp
  v2 = sub_1853134(v1);
  if ( v2 )
    v2 = sub_190D128(0, 1, "[LIBDVR@57888] ERROR  (%s|%d): GpioManager init error\r\n", "InitDvrSystem", 905);
  v3 = sub_184139C(v2);
  if ( v3 )
    v3 = sub_190D128(0, 1, "[LIBDVR@57888] ERROR  (%s|%d): TransComDevInit init error\r\n", "InitDvrSystem", 911);
  v4 = sub_185F424(v3);
  if ( v4 )
```

Subsequently, the services are executed.

```cpp
  v1 = sub_7CFF0("CGIManager2Dahua2ProtocolAuthority", 1);
  v2 = sub_3CFFA0(v1);
  v3 = sub_2DE668(v2);
  sub_3D0F18(v3);
  sub_7CFF0("CGIManager2Dahua2ProtocolAuthority", 0);
  v4 = sub_7CFF0("Ipv6Conflict", 1);
  sub_419E58(v4);
  sub_7CFF0("Ipv6Conflict", 0);
  v5 = sub_7CFF0("DeviceManager", 1);
  sub_305C9C(v5);
  sub_7CFF0("DeviceManager", 0);
  v6 = sub_7CFF0("RecordFinder", 1);
  sub_2FF260(v6);
  sub_7CFF0("RecordFinder", 0);
  v7 = sub_7CFF0("SecurityApp", 1);
  v8 = sub_41A4F0(v7);
  v9 = sub_41A598(v8);
  v10 = sub_419B60(v9);
  sub_4193D0(v10);
	  sub_7CFF0("SecurityApp", 0);
```

The process of viewing the operation function for each service is as follows.

1. Entering a function between sub\_7CFF0 functions

```cpp
v19 = sub_7CFF0("webapp", 1);
**sub_BE5DF0(v19);**
sub_7CFF0("webapp", 0);
```

1. Find an array of functions (off\_?) inside that function

```cpp
  if ( (dword_29EA394 & 1) == 0 && _cxa_guard_acquire(&dword_29EA394) )
  {
    dword_29EA3C8 = **&off_1B20124;**
    sub_1479E10(&dword_29EA3C8, "WebApp");
    _cxa_guard_release(&dword_29EA394);
    _aeabi_atexit(&dword_29EA3C8, sub_BE4DF4, &dword_232E290);
  }
```

1. Find the last function in that function array

```cpp
.rodata:01B20124 off_1B20124     DCD sub_BE4DF4+1        ; DATA XREF: sub_BE4DF4↑o
.rodata:01B20124                                         ; .text:off_BE4E08↑o ...
.rodata:01B20128                 DCD sub_BE4E10+1
.rodata:01B2012C                 DCD sub_BE4DB4+1
.rodata:01B20130                 DCD **sub_BE5F60+1**
```

1. function entry

```cpp
void *sub_BE5F18()
{
  if ( (dword_29EA3C4 & 1) == 0 && _cxa_guard_acquire(&dword_29EA3C4) )
  {
    **sub_BE5EC8**(&unk_29EA398);
    _cxa_guard_release(&dword_29EA3C4);
    _aeabi_atexit(&unk_29EA398, sub_BE5D44, &dword_232E290);
  }
  return &unk_29EA398;
}
```

1. Check vtables after entering an internal function
   * Presumed to be a constructor

```cpp
int __fastcall sub_BE5EC8(int a1)
{
  int result; // r0

  sub_147A8C4(a1);         // constructor
  *a1 = **&off_1B20CD4**;      // vtables
  sub_146D8F0((a1 + 8));
  sub_BF627C(a1 + 16);
  result = a1;
  *(a1 + 28) = 0;
  *(a1 + 32) = 0;
  *(a1 + 36) = 0;
  *(a1 + 12) = 0;
  *(a1 + 40) = 0;
  return result;
}
```

1. Analysis of vtables

```cpp
.rodata:01B20CD4 off_1B20CD4     DCD sub_BE5D44+1        ; DATA XREF: sub_BE5D44↑o
.rodata:01B20CD4                                         ; .text:off_BE5D8C↑o ...
.rodata:01B20CD8                 DCD sub_BE5D94+1
.rodata:01B20CDC                 DCD nullsub_670+1
.rodata:01B20CE0                 DCD sub_BE4EFC+1
.rodata:01B20CE4                 DCD sub_147A54C+1
.rodata:01B20CE8                 DCD sub_147A824+1
.rodata:01B20CEC                 DCD **sub_BE6C78+1**
.rodata:01B20CF0                 DCD sub_BE67A8+1
.rodata:01B20CF4                 DCD sub_BE5A0C+1
.rodata:01B20CF8                 DCD sub_BE5A78+1
.rodata:01B20CFC                 DCD sub_BE5110+1
.rodata:01B20D00                 DCD sub_BE5122+1
.rodata:01B20D04                 DCD sub_BE5134+1
.rodata:01B20D08                 DCD sub_BE5028+1
.rodata:01B20D0C                 DCD sub_BE5970+1
.rodata:01B20D10                 DCD sub_BE6B00+1
.rodata:01B20D14                 DCD sub_BE6974+1
.rodata:01B20D18                 DCD sub_BE5DA6+1
.rodata:01B20D1C                 DCD sub_BE5018+1
.rodata:01B20D20                 DCD sub_BE5924+1
.rodata:01B20D24                 DCD sub_BE5BC8+1
.rodata:01B20D28                 DCD sub_BE509C+1
.rodata:01B20D2C                 DCD sub_BE4DD0+1
.rodata:01B20D30                 DCD sub_BE5C50+1
.rodata:01B20D34                 DCD sub_BE5CD8+1
.rodata:01B20D38                 DCD sub_BE590C+1
.rodata:01B20D3C                 DCD sub_BE4FD8+1
.rodata:01B20D40                 DCD sub_BE4FC8+1
.rodata:01B20D44                 DCD sub_BE4FB8+1
.rodata:01B20D48                 DCD sub_BE4FA8+1
.rodata:01B20D4C                 DCD sub_BE4F98+1
.rodata:01B20D50                 DCD sub_BE4F88+1
.rodata:01B20D54                 DCD sub_BE4F78+1
.rodata:01B20D58                 DCD sub_BE4F68+1
.rodata:01B20D5C                 DCD sub_BE4F58+1
.rodata:01B20D60                 DCD sub_BE4F48+1
.rodata:01B20D64                 DCD sub_BE4F38+1
.rodata:01B20D68                 DCD sub_BE4F28+1
```

```cpp
      int __fastcall sub_BE6C78(int a1, int a2)
      {
	...
	if ( sub_15EEA94(a2, "WebSvr") && (v4 = sub_15EEA14(a2, "WebSvr"), sub_15EEBBA(v4)) )
	  {
	    v5 = sub_15EEA14(a2, "WebSvr");
	    if ( sub_15EEA94(v5, &unk_1AF2B5A) )
	    {
	      v6 = sub_15EEA14(a2, "WebSvr");
	      v7 = sub_15EEA14(v6, &unk_1AF2B5A);
	      if ( sub_15EEAD4(v7) )
	      {
	        v8 = sub_15EEA14(a2, "WebSvr");
	        v9 = sub_15EEA14(v8, &unk_1AF2B5A);
	        if ( sub_15EE608(v9) == 1 )
	        {
	          v10 = "SAMEORIGIN";
	        }
```

### 2.2. RPC

#### 2.2.1. RPC Method Analysis Method

Dahua sends JSON requests through the /RPC2, /RPC2\_Login path.

The format is as follows.

```json
{
  "method": "deviceDiscovery.attach",
  "params": {
    "proc": 1
  },
  "id": 386,
  "session": "b2193e2279aa752eaa6db6750e51074f",
  "object": 123271728
}
```

Here's how to find a function that handles that method.

1. Search String
   * deviceDiscovery.attach→ configManager.factory.instance.
   * Change the string after the dot to factory.instance.
2. Check reference

You can check the address that is the .rodata area of the reference. If you follow the address, you can see that it is listed in the form of Method Name, Function Address as follows, so you can check the processing method by checking the function under the desired method name.

```json
.rodata:01CAA5B4 off_1CAA5B4     DCD aDevicediscover_1   ; DATA XREF: sub_FA9A80+8↑o
.rodata:01CAA5B4                                         ; .text:off_FA9AAC↑o ...
.rodata:01CAA5B4                                         ; "deviceDiscovery.factory.instance"
.rodata:01CAA5B8                 DCD sub_FAB484+1
.rodata:01CAA5BC                 ALIGN 0x10
.rodata:01CAA5C0                 DCD aDevicediscover_11  ; "deviceDiscovery.destroy"
.rodata:01CAA5C4                 DCD sub_FAB1DC+1
.rodata:01CAA5C8                 DCB    0
.rodata:01CAA5C9                 DCB    0
.rodata:01CAA5CA                 DCB    0
.rodata:01CAA5CB                 DCB    0
.rodata:01CAA5CC                 DCD aDevicediscover_2   ; "deviceDiscovery.attach"
.rodata:01CAA5D0                 DCD **sub_FAA420+1**
.rodata:01CAA5D4                 DCB    0
.rodata:01CAA5D5                 DCB    0
.rodata:01CAA5D6                 DCB    0
.rodata:01CAA5D7                 DCB    0
.rodata:01CAA5D8                 DCD aDevicediscover_12  ; "deviceDiscovery.detach"
.rodata:01CAA5DC                 DCD sub_FAA60C+1
```

In the case of Dahua, since it is implemented in C++, most functions that process actual logic are indirect calls.

Therefore, analysis should be conducted after establishing an analysis environment such as gdb and watchdog feeding.

```cpp
int __fastcall sub_FAA420(int a1, int a2, int a3, int a4)
{
  int v7; // r0
  int v8; // r10
  unsigned __int8 *v9; // r0
  int v10; // r9
  int v11; // r7
  int v12; // r0
  int v13; // r0
  int v14; // r0
  int v15; // r0
  int v16; // r0
  int v18; // [sp+4h] [bp-2Ch] BYREF
  int v19; // [sp+8h] [bp-28h]
  int v20; // [sp+Ch] [bp-24h]

  v18 = a2;
  v19 = a3;
  v20 = a4;
  v7 = sub_15EFA30(a4, "result");
  sub_15EF7C0(v7, 0);
  if ( sub_DF5390(a2) )
  {
    v18 = 0;
    v8 = sub_DF3EB8(a2, ".params.proc", &v18);
    v9 = sub_15EEA14(a2, "id");
    v10 = sub_15EE608(v9);
    v11 = sub_DE5BD2(a1);
    v12 = sub_15EEA14(a2, "object");
    v13 = sub_15EE6AC(v12);
    v18 = v11;
    v19 = v8;
    v20 = v10;
    if ( sub_FAA2A0(a1, v13, &v18) )
    {
      v14 = sub_15EFA30(a4, "params");
      v15 = sub_15EFA30(v14, "SID");
      sub_15EF6B8(v15, v11);
      v16 = sub_15EFA30(a4, "result");
      sub_15EF7C0(v16, 1);
    }
  }
  else
  {
    sub_146F36C(3, "RPCServer", "get component pointer failed or invalid request! \n");
    sub_146AF90(-267976703);
  }
  return 1;
}
```

#### 2.2.2. RPC order of operation

When requesting the deviceDiscovery.attach method, the backtrace is as follows.

```cpp
#0  0x00faa420 in ?? ()
#1  0x00de5fba in ?? ()
#2  0x00de6100 in ?? ()
#3  0x00de134e in ?? ()
#4  0x00de271e in ?? ()
#5  0x00de28b4 in ?? ()
#6  0x00de305c in ?? ()
#7  0x01470874 in ?? ()
#8  0xb6cdb390 in ?? () from /lib/libpthread.so.0
```

1. start\_routine
2. sub\_DE2F86
3. sub\_DE2878
4. sub\_DE245C(proc\_request\_arrive)
5. sub\_DE1134(deal\_request)
6. sub\_DE6090(\_Method\_Call)
7. sub\_DE5F40(GetSubService)
8. Execute method&#x20;

### 2.3. **Additional Analysis Methods**

#### 2.3.1. Challenge Log

In the case of Challenge binary, a log is output to the terminal when it is executed.

Since it is output in great detail, it is convenient to analyze by searching for a string that appears in the log.

```bash
[2023-11-27T18:25:06 trace WebApp:1303297 2697 RequestHandler.cpp:554]Close called, this=0x7165eb8
[2023-11-27T18:25:06 trace WebApp:1303297 2697 RequestHandler.cpp:565]ref_count is 0
[2023-11-27T18:25:06 trace NetFramework:1184332 2697 Message.cpp:79]Ready to close NetHandler object:0x7165eb8, obj_id: -1405940, class_type:N5Dahua6WebApp18CRPCRequestHandlerE
[2023-11-27T18:25:06 trace NetFramework:1184332 2694 Message.cpp:79]Ready to close NetHandler object:0xb6203f38, obj_id: -1283070, class_type:N5Dahua12NetFramework13CStreamSenderE
[2023-11-27T18:25:06 warn NetFramework:1184332 2698 SslStream.cpp:528]this:0xb62a5e78 SSL_peek error! fd:110, len:131071, ERR_get_error=0, errno:0,Success
[LIBMED@68650] WARN  (DH_SSM_VDEC_CACHE_Notify|1122): cach[1] stream cutoff, need reset.
[2023-11-27T18:25:06 info NetApp_V4:1174208 2698 Ipv6ConflictChecker.cpp:663]IPAddr is NULL
[2023-11-27T18:25:06 warn NetProtocol:1198304 2698 IPv6ConflictCheckNew.cpp:173]Invalid IPv6 address!
```

#### 2.3.2. Settings File

The challenge is that the configuration file is located in `/mnt/mtd/Config` and is managed in a special format or JSON format.

The configuration files are encrypted and stored in the memory after initial decryption when the binary is executed.

#### 2.3.3. Legacy Code

In the case of Dahua, as the size of the binary is large, there are codes that are not used, and codes that do not exist on websites but can be used. Therefore, it will be an important point to find vulnerabilities by targeting the area.
