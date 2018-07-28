---
title: Android HCE开发
date: 2018-07-28 00:00:00
categories:
- CTF/Android
tags: Android HCE
--- 

官方手册：[Host-based card emulation overview](https://developer.android.com/guide/topics/connectivity/nfc/hce)

## 简介

Google在Android4.4中引入了一种新的卡仿真方法，即HCE（基于主机的卡模拟），利用手机本身来模拟一张NFC的tag，其中回应数据的规则不需要有一张真实卡的逻辑结构，按照对应规则返回即可（比如查表）

## 最简开发步骤

示例工程：NFCTest.zip、PaymentHost.zip

### 继承HostApduService

自己实现一个服务类，继承自[HostApduService](https://developer.android.com/reference/android/nfc/cardemulation/HostApduService)，并重写其中的processCommandApdu与onDeactivated方法

```java
public class MyHostApduService extends HostApduService {
    @Override
    public byte[] processCommandApdu(byte[] apdu, Bundle extras) {
       ...
    }
    @Override
    public void onDeactivated(int reason) {
       ...
    }
}
```

#### processCommandApdu

这个方法将会在收到一个APDU指令时被调用，用于处理APDU指令并返回相应的数据，即程序的主要逻辑部分。

需要注意，APDU的参数类型都是字节数组，所以这里利用如下的工具方法进行字节数组与字符串（小写）转换：

```JAVA
public static byte[] hexStringToByteArray(String s) {
        s=s.toLowerCase();
        int len = s.length();
        byte[] data = new byte[len / 2];

        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

public static String bytesToHex(byte[] bytes) {
        final char[] hexArray = {'0','1','2','3','4','5','6','7',
                                 '8','9','a','b','c','d','e','f'};
        char[] hexChars = new char[bytes.length * 2];
        int v;

        for ( int j = 0; j < bytes.length; j++ ) {
            v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }
```



#### onDeactivated

这个方法会在以下两种情况被调用：

- 一个NFC链接断开或者丢失 (0x00000000) 
- 设备收到了选择另一个AID的指令，并且被解析到另一个服务组件上(0x00000001) 

### 修改AndroidManifest.xml文件

在application标签中添加service标签

```Xml
<service android:name=".MyHostApduService" android:exported="true"
         android:permission="android.permission.BIND_NFC_SERVICE">
    <intent-filter>
        <action android:name="android.nfc.cardemulation.action.HOST_APDU_SERVICE"/>
    </intent-filter>
    <meta-data android:name="android.nfc.cardemulation.host_apdu_service"
               android:resource="@xml/apduservice"/>
</service>
```

- service标签中的android:name 就是第一步实现的类的名字
- meta-data标签中的android:resoucrce中指明了一个xml文件，之后要实现这个HCE的配置xml

### 编写HCE配置xml

在res目录下新建xml目录，目录下新建一个xml文件，文件名与在AndroidManifest.xml中引用的相同即可，这里我们设置文件名apduservice.xml，这个配置文件主要决定NFC通信过程中的数据路由

```XML
<host-apdu-service xmlns:android="http://schemas.android.com/apk/res/android"
        android:description="@string/servicedesc"
        android:requireDeviceUnlock="false"
        android:apduServiceBanner="@drawable/my_banner">
    <aid-group android:description="@string/aiddescription"
               android:category="payment">
        <aid-filter android:name="F0010203040506"/>
        <aid-filter android:name="F0394148148100"/>
    </aid-group>
</host-apdu-service>
```

- android:requireDeviceUnlock的值为false时，则允许锁屏时使用该HCE服务，反之亦然
- android:category指明HCE的类型是payment或者other，与HCE默认付款应用和AID的路由有关
- aid-filter中android:name为当前HCE应用注册的AID
- 只有收到在aid-filter注册过的AID的select AID指令，才会将本条以及后续的指令数据路由到当前应用中
- 并且配置好相应的字符串以及图片资源

### 默认应用

可以在应用初始化的时候设置本应用为默认付款应用，可以在MainActivity的onCreate中实现如下方法：

```JAVA
NfcAdapter adapter = NfcAdapter.getDefaultAdapter(this);
CardEmulation mCardEmulation = CardEmulation.getInstance(adapter);
ComponentName myComponent = new ComponentName("com.nxp.cascaen.paymenthost",
                                              "com.nxp.cascaen.paymenthost.PaymentServiceHost");
if (!mCardEmulation.isDefaultServiceForCategory(myComponent, CardEmulation.CATEGORY_PAYMENT)) {
    		Intent intent = new Intent(CardEmulation.ACTION_CHANGE_DEFAULT);
    		intent.putExtra(CardEmulation.EXTRA_CATEGORY, CardEmulation.CATEGORY_PAYMENT);
    		intent.putExtra(CardEmulation.EXTRA_SERVICE_COMPONENT, myComponent);
    		startActivityForResult(intent, 0);
} else {
 	Log.e("MainActivityHost", "on Create: Already default!");
}
```

需要修改的是第三行的ComponentName的初始化的两个参数，一个参数是应用的包名，第二个参数是实现的继承自HostApduService的实现类的类名。实现之后需要在AndroidManifest.xml中添加uses-permission权限：

```XML
<uses-permission android:name="android.permission.NFC" />
```



## SELECT MF 路由问题

### 路由规则

>  参考文档：NFC 路由表讲解和路由规则梳理.docx

在Android中，nfc数据的处理可能有三种方式：eSE，UICC，HCE。一条nfc数据路由到那种处理方式，是由nfc的路由表来决定的，我们可以通过dumpsys nfc命令查看路由表，如下为mate10的路由表信息（略有删减）

``` bash
$adb shell dumpsys nfc

mState=off
mIsZeroClickRequested=false
mScreenState=ON_UNLOCKED
mNfcPollingEnabled=false
mNfceeRouteEnabled=false
mOpenEe=null
mLockscreenPollMask=0
mTechMask: 0
mEnableLPD: true
mEnableReader: false
mEnableHostRouting: false
mEnableP2p: falsemEnable2ndLevelMenu: false
mIsSendEnabled=false
mIsReceiveEnabled=false
mLinkState=LINK_STATE_DOWN
mSendState=SEND_STATE_NOTHING_TO_SEND
mCallbackNdef=android.nfc.IAppCallback$Stub$Proxy@4d6bfbd
mMessageToSend=null
Registered HCE services for current user: 
    ComponentInfo{com.huawei.wallet/com.huawei.nfc.carrera.
    lifecycle.swipeservice.NFCOffHostApduService} (Description: 华为钱包)
    Static AID groups:
        Category: payment
            AID: 325041592E5359532E4444463031
            AID: A0000003330101020063020000000301
    Dynamic AID groups:
    Settings Activity: null
    Routing Destination: secure element
Registered HCE-F services for current user: 
Preferred services (in order of importance): 
    *** Current preferred foreground service: null
    *** Current preferred payment service: ComponentInfo{com.huawei.wallet/com.huawei.nfc.
    carrera.lifecycle.swipeservice.NFCOffHostApduService}
        Next tap default: null
        Default for foreground app (UID: 0): null
        Default in payment settings: ComponentInfo{com.huawei.wallet/com.huawei.nfc.
        carrera.lifecycle.swipeservice.NFCOffHostApduService}
        Payment settings allows override: true
    AID cache entries: 
    "325041592E5359532E4444463031" (category: payment)
        *DEFAULT* ComponentInfo{com.huawei.wallet/com.huawei.nfc.
        carrera.lifecycle.swipeservice.NFCOffHostApduService} (Description: 华为钱包)
    "A0000003330101020063020000000301" (category: payment)
        *DEFAULT* ComponentInfo{com.huawei.wallet/com.huawei.nfc.
        carrera.lifecycle.swipeservice.NFCOffHostApduService} (Description: 华为钱包)
    Service preferred by foreground app: null
    Preferred payment service: ComponentInfo{com.huawei.wallet/com.huawei.nfc.carrera.
    lifecycle.swipeservice.NFCOffHostApduService}
Routing table:
    Default route: secure element
T3T Identifier cache entries: 
HCE-F routing table:
Bound HCE-A/HCE-B services: 
Bound HCE-F services: 
mOverrideIntent=null
mOverrideFilters=null
mOverrideTechLists=null
libnfc llc error_count=0
```

Routing table中的Default route为默认路由，经测试更改手机中的默认付款应用并无法修改默认路由配置为HCE，所以能否路由到HCE是完全由AID来决定的！即在选应用的时候的命令必须是：00 A4 04 00 开头，而以前的SELECT MF命令：00 A4 00 00 02 3F 00，命令的第三个字节是00，而非04。选择的是FID的标签，并非AID，这种方式不被HCE接受，是无法激活HCE的，知乎链接：[HCE 无法处理 SELECT MF 指令吗？](https://www.zhihu.com/question/44597598/answer/106838087)

### 解决方法

但是NFCgate却能解决SELECT MF的路由问题，研究发现，NFCGate应该hook了底层的路由方法，以及选择aid的方法，通过自己选择自己的方式激活HCE，则可以完成后续的SELECT MF的响应问题，除此之外暂无他法。NFCGate的Xposed代码如下：

[https://github.com/nfcgate/nfcgate/blob/dev/nfcd/src/main/java/tud/seemuh/nfcgate/xposed/Hooks.java](https://github.com/nfcgate/nfcgate/blob/dev/nfcd/src/main/java/tud/seemuh/nfcgate/xposed/Hooks.java)

``` java
findAndHookMethod("com.android.nfc.cardemulation.HostEmulationManager", lpparam.classLoader, "findSelectAid", byte[].class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {

                Log.i("HOOKNFC", "beforeHookedMethod");
                if (Native.Instance.isEnabled()) {
                    Log.i("HOOKNFC", "enabled");
                    // setting a result will prevent the original method to run.
                    // F0010203040506 is a aid registered by the nfcgate hce service
                    param.setResult("F0010203040506");
                }
            }
        });
```

笔者尝试了直接去复用这个xposed的方法，不过没有用其中的Native来加载NFCGate实现的底层hook方法，结果失败，验证了实现这个功能不只是hook java层的代码，也要hook底层的c代码。

## UID

### 手机中的UID配置

在一次NFC过程中，读卡器会先读取标签的UID信息，这个信息在巡场的时候就已经发送了，并不在后续发送的APDU中。对于真正的卡来说，UID是写死在卡的固件中，而对于手机来说，UID存在于nfc的配置文件中。这些配置文件的名字一般为libnfc-nxp.conf等，可以在手机的shell中通过如下命令找到，以mate10为例：

```bash
$ adb shell "find / -name libnfc*.conf 2>/dev/null"
/product/etc/nfc/libnfc-brcm.conf
/product/etc/nfc/libnfc-nxp.conf
/product/etc/nfc/libnfc-nxp_RF.conf
/odm/etc/libnfc-brcm.conf
/odm/etc/libnfc-nxp.conf
/odm/etc/libnfc-nxp_RF.conf
```

具体生效的配置文件是哪个，可以根据手机的NFC芯片型号来判断，找到配置文件中的如下字段：

```bash
# Core configuration settings
NXP_CORE_CONF={ 20, 02, 2E, 0E,
        28, 01, 00,
        21, 01, 00,
        30, 01, 08,
        31, 01, 03,
        32, 01, 60,
        38, 01, 01,
        33, 04, 01, 02, 03, 04,
        54, 01, 06,
        50, 01, 02,
        5B, 01, 00,
        80, 01, 01,
        81, 01, 01,
        82, 01, 0E,
        18, 01, 01 
        }
```

33, 04, 01, 02, 03, 04,即为UID的信息，33是UID的标记，04是长度，01020304即为UID

- 有些手机的这个字段没有配置，即可能为随机UID
- 有些手机即使这个字段配置了，仍然为随机卡号，貌似没有解决办法，如三星的s7，s8

### 用于门禁校验

某些门禁就是读取的卡片UID来进行认证，于是小米手机的模拟门禁卡就是通过更改这个配置文件来实现手机模拟门禁卡的，而且小米的这个功能不支持加密卡（如M1卡）。

### 用于认证计算

这里猜测，UID的信息还可能是某些实现中秘钥分发的一个参数。

在我们用NFCGate中继深圳地铁时，发现闸机对卡进行外部认证时，通过我们中继的卡片返回的信息居然是63CC，而非9000。而中继过程中传输的数据与正常通信过程中应该只有UID的信息没有进行中继，因为读卡器接受的UID为NFCGate的模拟端手机的UID，而非卡真实的UID。所以猜测，在进行外部认证时，闸机通过卡发的随机数与卡片的UID进行认证的计算，而在中继过程中参与运算的UID而非真实卡的UID，卡片返回认证错误也就可以解释了。
