# Binary Analysis Report

## 1. Overview

***

This document is a report described by Team.ENVY (Kim Chan-in, Park Myung-hoon, Shin Myung-jin, Yang Gang-min, and Lee Yoo-kyung), who carried out the BoB 12th NVR Vulnability Analysis project.

### 1.1. Necessity

Analysis of web services and web APIs is essential for Hanwha Vision's vulnerability analysis. Therefore, the binary used by Hanwha Vision for vulnerability analysis is to be analyzed.

## 2. dvr\_main

***

The dvr\_main binary is Hanwha Vision's main binary and is the first binary to be executed after init script.

The binary executes necessary binary and services such as GUI and web server.

First, through string search, the following shell script files could be checked.

```bash
/etc/scripts/SsCore.sh GUI
/etc/scripts/SsCore.sh WebServer
/etc/scripts/SsCore.sh
/etc/scripts/SsDhcpClient.sh restart 
/etc/scripts/SsDhcpClient.sh stop 
/etc/scripts/SsDhcpServer.sh start v4
/etc/scripts/SsDhcpServer.sh start v6
/etc/scripts/SsDhcpServer.sh stop v4
/etc/scripts/SsDhcpServer.sh stop v6
/etc/scripts/SsDiskHealthChk.sh %s
/etc/scripts/SsDuplicateIpChk.sh %s %s %s
/etc/scripts/SsFtpUpgrade.sh %s
/etc/scripts/SsMvRaidDiskHealthChk.sh %s
/etc/scripts/SsMvRaidDiskHealthChk.sh
/etc/scripts/SsNTP.sh start
/etc/scripts/SsNTP.sh
/etc/scripts/SsSqliteChk.sh %s %s
/etc/scripts/SsSqliteChk.sh %s
/etc/scripts/SsSqliteChk.sh %s1/MetaData/log/%s
/etc/scripts/SsTuTk.sh restart
/etc/scripts/SsTuTk.sh test
/etc/scripts/SsUpgrade.sh %s
/etc/scripts/SsWebserver.sh error\n
/etc/scripts/SsWebserver.sh start %s
/etc/scripts/SsZeroconf.sh rebind
/etc/scripts/SsZeroconf.sh stop
```

When tracking this, it was confirmed that the web server was uploaded by executing "/etc/scripts/SsWebserver.sh start %s" in the web::WebServerProcess::start\_web\_server function.

```c
web::WebServerProcess::start_web_server

snprintf(acStack_c4,0x96,"/etc/scripts/SsWebserver.sh start %s",pcVar6);
      iVar3 = lsystem_t_external("ignore",acStack_c4,0x3c);
```

The system command is executed using the lsystem\_t\_external function.

```c
void lsystem_t_external(char *param_1,char *command,int param_3)

{
...
  uVar1 = InitSyscall();
  FUN_00d79c78(command,auStack_41c);
  traceline(0x10021,0x10022,"[S] ExeSyscall : cmd(\"%s\") timeout(%d sec)",command,param_3);
  ExeSyscall(uVar1,auStack_41c,command);
  traceline(0x10021,0x10022,"[W] WaitSyscall");
  uVar2 = WaitSyscall(uVar1,0,0,param_3);
  ReleaseSyscall(uVar1)
...
```

When going up the web::WebServerProcess::start\_web\_server function, it was confirmed that a thread was created under the name LighttpdProc and executed lighttpd.

```c
void FUN_018dccd8(void)

{
  int iVar1;
  
  iVar1 = cmn_pthread_create((ulong *)&DAT_032c9f18,FUN_018dd18c,(void *)0x0,"128K","LighttpdProc" );
  if (iVar1 != 0) {
    debug_message(5,6,"webController.cpp","lighttpd_init",0x1b7,
                  "[ERR] Error pthread_create(lighttpd_thread_create) (%d)\n",iVar1);
  }
  return;
}
```

### 2.1. syscall

```c
do {
    do {
      iVar2 = CamMsgQueue::read(aCStack_848,1,aCStack_840);
    } while (iVar2 == 0);
...
case 4:
      pnVar3 = (nvr_list *)CamCommand::getData(aCStack_840,0);
      iVar2 = CamCommand::getData(aCStack_840,1);
      iVar4 = CamCommand::getData(aCStack_840,2);
      Syscall::call((Syscall *)this,pnVar3,local_824,acStack_424,iVar2,iVar4);
      break;
...
} while(true);
```

Run an infinite loop in the syscall daemon and wait until the request is received via the "CamMsgQueue::read" function.

If a request is made, do something different depending on the switch syntax.

In case 4, the system command is executed through the "Syscall::call" function and the result is returned.

## 3. SUNAPI

Hanwha Vision uses its own SUNAPI interface in place of the ONVIF standard.

According to official documents, SUNAPI stands for Smart Unified Network API and is a complete single interface that can control various products that make up the image system connected to the network.

It is also said that it can integrate not only Hanwha Vision products but also other companies' products.

The link below shows the functional differences between ONVIF standards and SUNAPI.

{% embed url="https://support.networkoptix.com/hc/en-us/articles/360058314513-Hanwha-SUNAPI-vs-ONVIF" %}

In Hanwha Vision's internal implementation, the processing of these SUNAPI requests is all composed of CGI binary.

CGI is separated for each function, and the following CGIs exist.

```bash
init-cgi/
`-- pw_init.cgi
stw-cgi/
|-- ai.cgi
|-- attributes.cgi
|-- bypass.cgi
|-- debug.cgi
|-- display.cgi
|-- eventactions.cgi
|-- eventrules.cgi
|-- eventsources.cgi
|-- eventstatus.cgi
|-- factory.cgi
|-- image.cgi
|-- io.cgi
|-- media.cgi
|-- network.cgi
|-- ptzconfig.cgi
|-- ptzcontrol.cgi
|-- recording.cgi
|-- security.cgi
|-- system.cgi
|-- transfer.cgi
`-- video.cgi
```

## 4. Structure

Hanwha Vision's web server is implemented with lighttpd + FastCGI.

Each CGI consists of one main thread and 10 child threads, and child threads exist to reduce the load on request.

<figure><img src="../.gitbook/assets/cgi ps.png" alt=""><figcaption></figcaption></figure>

If the child thread is dead, the main thread detects it and restarts the binary.

It also consists of php-cgi for web pages and CGIs for SUNAPI, and SUNAPI's CGI is implemented in libfcgi's fcgiapp library (in FCGX\_XXX format).

The following is a description of SUNAPI. First, the command of SUNAPI consists of an HTTP URL. Each URL transmits the IP of the device and the CGI name in which the desired command exists, and the submenu, action, and parameter of the command are transmitted to the next query string.

<figure><img src="../.gitbook/assets/sunapi query.png" alt=""><figcaption></figcaption></figure>

For example, the URL that requests information from the device is.

```
http://192.168.0.102/stw-cgi/system.cgi?msubmenu=deviceinfo&action=view
```

Digest authentication is handled by lighttpd at the front-end, and Digest authentication information is also sent when sending requests to the socket.

### 4.1. Submenus

Each CGI is divided into sub-functions that perform specific functions.

For example, system.cgi has a sub-menu called deviceinfo, which is a function of inquiring/controlling product information, time, and date.

SUNAPI grammar requires that these submenus be sent to the query string as "msubmenu".

### 4.2. Actions

Each SUNAPI command must define its behavior. SUNAPI provides the following actions.

* view
* set
* control
* update
* add
* install
* remove

## 5. Binary Analysis

Each cgi has the same implementation for thread generation, url parsing, submenu, and action parsing.

In this document, the most basic "init-cgi/pw\_init.cgi" of all cgi was written.

### 5.1. Initialization/Thread creation

Since each CGI includes its own CGI name and leaves it in the log, it initializes the factor from the main function to its own name, creates a socket to be in charge of transmission and reception with lighttpd, and calls the main thread.

```c
int main(void)

{
  mainThreadArguments args;
  
  signal(13,(__sighandler_t)0x1);
  FCGX_Init();
  umask(0);
  remove("/tmp/pw_init-fastcgi.socket-0");
  args.watingCount = 10;
  args.socket = socket_setting("/tmp/pw_init-fastcgi.socket-0",0x80);
  args.cgiName = "PW_INIT\0";
  createThread(mainThread,&args);
  return 0;
}
```

### 5.2. Main Thread Behavior

1. After initializing the FCGI, it enters an infinite loop and receives a request through the FCGX\_Accept\_r function.

```c
HttpRequest = InitializeFCGI(&reqDataPtr,args->socket,0);
if (HttpRequest == 0) {
    pid = getpid();
    tid = pthread_self();
    currentCGI = args->cgiName;
    logging(1,"%d : %lu : %s-%s",pid,tid,currentCGI,"THREAD-START");
    do {
      pid = getpid();
      localWaitingCount = args->watingCount - globalWaitingCount;
      logging(2,"%d : %lu : %s-%s-%d",pid,tid,currentCGI,"WAITING",localWaitingCount);
      HttpRequest = FCGX_Accept_r(&reqDataPtr);
```

2. When the request is received, the URI parses the msubmenu, action, and request method and outputs it to the log.

```c
if (HttpRequest < 0) {
        pid = getpid();
        logging(1,"%d : %lu : %s-%s",pid,tid,currentCGI,"FCGI-ACCEPT-FAIL",localWaitingCount);
      }
      else {
        HttpRequest = globalWaitingCount + 1;
        parsedDataBuf = 0;
        globalWaitingCount = HttpRequest;
        memset(auStack_e4,0,0x3c);
        pid = getpid();
        parsedURI = parse_uri(&reqDataPtr,&parsedDataBuf);
        logging(2,"%d : %lu : %s-%s-%d %s",pid,tid,currentCGI,"REQ-RECEIVED",HttpRequest,parsedURI);
        parsedUsernameBuf = 0;
        memset(auStack_a4,0,0x7c);
        parsedUsernameBufPtr = parseUsername(&reqDataPtr,(char *)&parsedUsernameBuf);
```

```c
char * parse_uri(FCGX_Request *reqDataPtr,char *retBuf)

{
  char *reqURI;
  char *start;
  char *end;
  char *reqMethod;
  size_t len;
  char msubmenu [65];
  char action [65];
  
  reqURI = (char *)parse_value("REQUEST_URI",reqDataPtr->envp);
  if (reqURI != (char *)0x0) {
    memset(msubmenu,0,0x3c);
    start = strcasestr(reqURI,"msubmenu=");
    if ((start != (char *)0x0) && (start = strchr(start,L'='), start != (char *)0x0)) {
      end = strchr(start,L'&');
      if (end == (char *)0x0) {
        snprintf(msubmenu + 1,0x40,"%s",start + 1);
      }
      else {
        len = (int)end - (int)(start + 1);
        strncpy(msubmenu,start,len);
        msubmenu[len + 1] = '\0';
      }
    }
   
    memset(action,0,0x3c);
    reqURI = strcasestr(reqURI,"action=");
    if ((reqURI != (char *)0x0) && (reqURI = strchr(reqURI,L'='), reqURI != (char *)0x0)) {
      start = strchr(reqURI,L'&');
      if (start == (char *)0x0) {
        snprintf(action,0x40,"%s",reqURI + 1);
      }
      else {
        len = (int)start - (int)(reqURI + 1);
        strncpy(action,reqURI,len);
        action[len] = '\0';
      }
    }
    reqMethod = (char *)parse_value("REQUEST_METHOD",reqDataPtr->envp);
    sprintf(retBuf,"%s:%s:%s",reqMethod,msubmenu,action);
  }
  return retBuf;
}
```

3. Parse Digest's username in the request header.
4. Check if the received username is empty, parse submenu to check if it is in password recovery mode.

Returns 401 error if username is empty and is not in password recovery mode.

```c
if ((*parsedUsernameBufPtr == '\0') &&
           (HttpRequest = isOneTimePassword(&reqDataPtr), HttpRequest == 0)) {
          parsedUsernameBufPtr = parseUsername(&reqDataPtr,(char *)&parsedUsernameBuf);
          logging(1,"username = %s",parsedUsernameBufPtr);
          send_4xx_response(&reqDataPtr,401);
        }
```

5. If the username is not empty, call the serverRequest handler that handles the action and submenu.

```c
else {
          result = request_handler(&reqDataPtr);
          handledRequestResult = result & 0xffff;
          logging(1,"serveRequest::result = %d",handledRequestResult);
          if (handledRequestResult != 0) {
            if ((handledRequestResult == 401) || (handledRequestResult == 490)) {
              send_4xx_response(&reqDataPtr,result);
            }
            else {
              send_response(&reqDataPtr,result);
            }
          }
        }
```

6. The handler is implemented by parsing the action first and then parsing the submenu from the function defined for each action.

Here, the action also includes other CGI functions, but if it is not its own function, a separate definition of the action is not implemented.

```c
int request_handler(FCGX_Request *reqDataPtr)

{
  int actionNo;
  
  logging(1,"serveRequest start");
  actionNo = parse_action(reqDataPtr);
  switch(actionNo) {
  case 100:
    actionNo = action_view(reqDataPtr);
    return actionNo;
  case 0x65:
    actionNo = action_set(reqDataPtr);
    return actionNo;
  case 0x66:
    actionNo = action_control(reqDataPtr);
    return actionNo;
  case 0x67:
    actionNo = action_add(reqDataPtr);
    return actionNo;
  case 0x68:
    actionNo = action_remove(reqDataPtr);
    return actionNo;
  case 0x69:
    actionNo = action_update(reqDataPtr);
    return actionNo;
  case 0x6a:
    actionNo = action_update_check(reqDataPtr);
    return actionNo;
  case 0x6b:
    actionNo = action_monitor(reqDataPtr);
    return actionNo;
  case 0x6c:
    actionNo = action_monitordiff(reqDataPtr);
    return actionNo;
  case 0x6d:
    actionNo = action_install(reqDataPtr);
    return actionNo;
  case 0x6e:
    actionNo = action_test(reqDataPtr);
    return actionNo;
  default:
    return 0x259;
  }
}
```

7. The contents of parse\_action are as follows.

Parse the action, and if there is no action, handle the action through InsertDeviceCert and macAddr.

```c
int parse_action(FCGX_Request *reqDataPtr)

{
  char *reqURI;
  char *action;
  int cmpFlag;
  size_t len;
  char argumentBuf [64];
  
  reqURI = (char *)parse_value("REQUEST_URI",reqDataPtr->envp);
  if (reqURI == (char *)0x0) {
    return 0;
  }
  argumentBuf[1] = '\0';
  argumentBuf[2] = '\0';
  argumentBuf[3] = '\0';
  argumentBuf[4] = '\0';
  memset(argumentBuf + 5,0,0x3c);
  action = strcasestr(reqURI,"action=");
  if (action == (char *)0x0) {
    action = strcasestr(reqURI,"InsertDeviceCert=");
    reqURI = strcasestr(reqURI,"macAddr=");
    if ((reqURI != (char *)0x0) && (action != (char *)0x0)) {
      return 0x6d;
    }
  }
  else {
    reqURI = strchr(action,L'=');
    if (reqURI != (char *)0x0) {
      action = strchr(reqURI,L'&');
      if (action == (char *)0x0) {
        snprintf(argumentBuf + 1,0x40,"%s",reqURI + 1);
      }
      else {
        len = (int)action - (int)(reqURI + 1);
        strncpy(argumentBuf + 1,reqURI + 1,len);
        argumentBuf[len + 1] = '\0';
      }
    }
  }
  cmpFlag = strcasecmp(argumentBuf + 1,"view");
  if (cmpFlag == 0) {
    return 100;
  }
  cmpFlag = strcasecmp(argumentBuf + 1,"set");
  if (cmpFlag == 0) {
    return 101;
  }
  cmpFlag = strcasecmp(argumentBuf + 1,"control");
  if (cmpFlag == 0) {
    return 102;
  }
  cmpFlag = strcasecmp(argumentBuf + 1,"add");
  if (cmpFlag == 0) {
    return 103;
  }
  cmpFlag = strcasecmp(argumentBuf + 1,"remove");
  if (cmpFlag == 0) {
    return 104;
  }
  cmpFlag = strcasecmp(argumentBuf + 1,"update");
  if (cmpFlag != 0) {
    cmpFlag = strcasecmp(argumentBuf + 1,"check");
    if (cmpFlag == 0) {
      return 106;
    }
    cmpFlag = strcasecmp(argumentBuf + 1,"monitor");
    if (cmpFlag == 0) {
      return 107;
    }
    cmpFlag = strcasecmp(argumentBuf + 1,"monitordiff");
    if (cmpFlag == 0) {
      return 108;
    }
    cmpFlag = strcasecmp(argumentBuf + 1,"install");
    if (cmpFlag == 0) {
      return 109;
    }
    cmpFlag = strcasecmp(argumentBuf + 1,"test");
    if (cmpFlag == 0) {
      return 110;
    }
    return 0;
  }
  return 0x69;
}
```

8. For example, let's look at the content of action\_view.

After parsing the msubmenu, handle only for a specific return value. The corresponding return value is statuscheck.

```c
int action_view(FCGX_Request *reqDataPtr)

{
  int retVal;
  
  retVal = parse_msubmenu(reqDataPtr);
  if (retVal != 0x153) {
    return 600;
  }
  retVal = statusCheck(reqDataPtr);
  return retVal;
}
```

9. The contents of parse\_msubmenu are as follows.

```c
int parse_msubmenu(FCGX_Request *reqDataPtr)

{
  char *reqURI;
  char *pcVar1;
  int menuNo;
  int cmpFlag;
  size_t len;
  char msubmenu [64];
  
  reqURI = (char *)parse_value("REQUEST_URI",reqDataPtr->envp);
  if (reqURI != (char *)0x0) {
    msubmenu[1] = '\0';
    msubmenu[2] = '\0';
    msubmenu[3] = '\0';
    msubmenu[4] = '\0';
    memset(msubmenu + 5,0,0x3c);
    reqURI = strcasestr(reqURI,"msubmenu=");
    if ((reqURI != (char *)0x0) && (reqURI = strchr(reqURI,L'='), reqURI != (char *)0x0)) {
      pcVar1 = strchr(reqURI,L'&');
      if (pcVar1 == (char *)0x0) {
        snprintf(msubmenu + 1,0x40,"%s",reqURI + 1);
      }
      else {
        len = (int)pcVar1 - (int)(reqURI + 1);
        strncpy(msubmenu + 1,reqURI + 1,len);
        msubmenu[len + 1] = '\0';
      }
    }
    cmpFlag = strcasecmp(msubmenu + 1,"deviceinfo");
    if (cmpFlag == 0) {
      menuNo = 0xde;
    }
    else {
      cmpFlag = strcasecmp(msubmenu + 1,"date");
      if (cmpFlag == 0) {
        menuNo = 0xdf;
      }
	... 중간 생략
    }
    return menuNo;
  }
  return 0;
}
```

10. Afterwards, if the msubmenu is statuscheck, it is a structure that executes the status\_check function below.

pw\_init.cgi is implemented only for status\_check, set\_initial\_password functions.

11. Each function sends a request to the /tmp/SunapiSocket socket after making Digest, parameters, etc. in json form.

Processing related to Digest authentication seems to take place inside the socket. The data transmitted are as follows.

```bash
{
	"JsonPacket":	"IPC-REQUEST",
	"RequestType":	1002,
	"SPCommand":	4205,
	"RemoteAddress":	"192.168.0.201",
	"ServerName":	"192.168.0.102",
	"Url":	"/init-cgi/pw_init.cgi?msubmenu=statuscheck&action=view",
	"IsJsonRequired":	0,
	"HttpMethod":	"GET",
	"RemoteUser":	"",
	"RealM":	"",
	"ResP":	"",
	"Qop":	"",
	"CNonce":	"",
	"Nonce":	"",
	"NonceCount":	"",
	"AuthURL":	"",
	"RemoveNonce":	""
}
```

The data to be returned are as follows.

```bash
{
	"JsonPacket":	"IPC-RESPONSE",
	"LCount":	"1",
	"PFile":	"/tmp/sunapi/Sunapi_28789.dat",
	"ResponseType":	"2001"
}
```

12. Afterwards, the data is parsed from the response and the return value is loaded into the response and transmitted to the client.
13. For example, the contents of the statusCheck function are as follows.

```c
int statusCheck(FCGX_Request *reqDataPtr)

{
  char *sendSockBuf;
  undefined4 digest;
  void *json;
  size_t len;
  int sockBuf;
  int response;
  long lVar1;
  undefined4 uVar2;
  int iVar3;
  
  sendSockBuf = (char *)malloc_size_10000();
  digest = parseDigest(reqDataPtr,0x3ea,0x106d);
  json = (void *)make_json();
  FUN_0001c1e8(digest);
  snprintf(sendSockBuf,0x10000,"%s",json);
  free(json);
  len = strlen(sendSockBuf);
  digest = 0x10000;
  sockBuf = send_message_SunapiSocket(sendSockBuf,len,sendSockBuf);
  if (sockBuf == -1) {
    sockBuf = 607;
    goto ExitFunction;
  }
  sockBuf = get_SunAPISocket_Response(sendSockBuf);
  if (sockBuf != 1000) goto ExitFunction;
  response = FUN_0001c268(sendSockBuf);
  if ((response == 0) || (sockBuf = parse(response,"LCount"), sockBuf == 0)) {
LAB_00012488:
    sockBuf = 0;
  }
  else {
    sockBuf = parse(response,"LCount");
    lVar1 = strtol(*(char **)(sockBuf + 0x10),(char **)0x0,10);
    if (lVar1 == 0) {
      sockBuf = 0x264;
    }
    else {
      uVar2 = FCGX_GetParam("SERVER_PROTOCOL",reqDataPtr->envp);
      ::response(reqDataPtr,"%s 200 OK\r\nContent-type:application/json;charset=utf-8\r\n\r\n",uVar2
                 ,digest);
      sockBuf = parse(response,"PFile");
      if (sockBuf == 0) goto LAB_00012488;
      sockBuf = 0;
      iVar3 = parse(response,"PFile");
      readFile(reqDataPtr,*(undefined4 *)(iVar3 + 0x10));
    }
  }
  FUN_0001c1e8(response);
ExitFunction:
  safe_free(sendSockBuf);
  return sockBuf;
}
```

14. The response is sent to the client according to the result in the above function.

### 5.3. Data processing method

#### 5.3.1. POST - multipart/form-data

SUNAPI's CGIs do not send data other than "query string" or "request header" directly to the socket.

When "Content-Type" receives a request defined as "multipart/form-data", if body data is written in "/mnt/sda1/MetaData/upload", that is, when sending a request to a socket, the socket reads the data in the file system.

```c
is_post_request = (char *)FCGX_GetParam("REQUEST_METHOD",*(undefined4 *)(param_1 + 0x14));
  is_post_request = strcasestr(is_post_request,"POST");
  if (is_post_request != (char *)0x0) {
    download_post_data(param_1,&request_uri);
  }
  request_uri_new = malloc_and_copy_0x28(&request_uri);
  add_header_str(soc_packet,"EncPassword",request_uri_new);
  __ptr = (void *)make_json(soc_packet);
  FUN_0001c1e8(soc_packet);
  snprintf(__s,0x10000,"%s",__ptr);
  free(__ptr);
  sVar1 = strlen(__s);
  soc_packet = send_SunAPISocket_Request(__s,sVar1,__s,0x10000);
  if (soc_packet == -1) {
    uVar2 = 607;
  }
  else {
    uVar2 = recv_SunAPISocket_Response(__s);
  }
```

#### 5.3.2. Socket Response

When the socket returns the requested data, it writes it in "/tmp/sunapi" and sends the path to CGI in JSON format. CGI reads the path above to check the return value.

```bash
{
	"JsonPacket":	"IPC-RESPONSE",
	"LCount":	"1",
	"PFile":	"/tmp/sunapi/Sunapi_28789.dat",
	"ResponseType":	"2001"
}
```

```c
sockBuf = send_SunAPISocket_Request(sendSockBuf,len,sendSockBuf);
  if (sockBuf == -1) {
    sockBuf = 607;
    goto ExitFunction;
  }
  sockBuf = recv_SunAPISocket_Response(sendSockBuf);
  if (sockBuf != 1000) goto ExitFunction;
  response = FUN_0001c268(sendSockBuf);
  if ((response == 0) || (sockBuf = parse(response,"LCount"), sockBuf == 0)) {
LAB_00012488:
    sockBuf = 0;
  }
  else {
    sockBuf = parse(response,"LCount");
    lVar1 = strtol(*(char **)(sockBuf + 0x10),(char **)0x0,10);
    if (lVar1 == 0) {
      sockBuf = 612;
    }
    else {
      uVar2 = FCGX_GetParam("SERVER_PROTOCOL",reqDataPtr->envp);
      ::response(reqDataPtr,"%s 200 OK\r\nContent-type:application/json;charset=utf-8\r\n\r\n",uVar2
                 ,digest);
      sockBuf = parse(response,"PFile");
      if (sockBuf == 0) goto LAB_00012488;
      sockBuf = 0;
      iVar3 = parse(response,"PFile");
      readFile(reqDataPtr,*(undefined4 *)(iVar3 + 0x10));
    }
```

## 6. Schematic Diagram

<figure><img src="../.gitbook/assets/Whitebox - 한화비전 DFD.jpg" alt=""><figcaption></figcaption></figure>
