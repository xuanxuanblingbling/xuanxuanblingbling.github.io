---
title: Android APP常见漏洞和挖掘技巧
date: 2018-02-12 00:00:00
categories:
- CTF/Android
tags:
---

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