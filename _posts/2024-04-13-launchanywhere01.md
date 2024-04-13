---
title: LaunchAnyWhere 漏洞现世：GoogleBug 7699048 复现与分析(Android4.3)
date: 2024-04-13 00:00:00
categories:
- CTF/Android
tags: 
---

> 使用Android Studio和Android模拟器完整调试LaunchAnyWhere漏洞的整个过程，包括exp代码、Settings APP和system_server进程这三部分代码的调试与理解。


## 漏洞简介

[launchAnyWhere: Activity组件权限绕过漏洞解析(Google Bug 7699048)](https://blogs.360.cn/post/launchanywhere-google-bug-7699048.html)

从效果上：恶意APP可向Settings系统APP发起intent调用，最终可**以Settings的权限即system权限**，发送任意intent，从而启动各种未导出的Activity等。例如绕过老密码，直接设置新密码。

![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/app.png)

从原理上：**Settings系统APP**使用的系统服务**AccountManagerService（进程为system_server）的addAccount功能**，其回传给Settings目标要启动的Activity（图中的step 4），可由恶意APP任意指定（图中的step 3），而**AccountManagerService** 未进行任何检查。

![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/step.png)

开发原理：

- [开发你自己的Android授权管理器.md](https://github.com/hehonghui/android-tech-frontier/blob/master/issue-27/开发你自己的Android授权管理器.md)
- [Android AccountManager帐号管理（一）_queryintentservices_小燕子的空间的博客-CSDN博客](http://blog.csdn.net/dzkdxyx/article/details/78569867)
- [Android AccountManager帐号管理（二）_安卓12accountmanager_小燕子的空间的博客-CSDN博客](https://blog.csdn.net/dzkdxyx/article/details/78632945)
- [Android里帐户同步的实现_怎么用代码模拟android账户同步_子云心的博客-CSDN博客](https://blog.csdn.net/lyz_zyx/article/details/73571927)

其他参考：

- [launchAnyWhere: Activity组件权限绕过漏洞解析 - 掘金](https://juejin.cn/post/7225132351448186936)
- [LaunchAnyWhere学习笔记](https://chan-shaw.github.io/2020/04/11/LaunchAnyWhere学习笔记/)
- [安卓Bug 17356824 BroadcastAnywhere漏洞分析 - 掘金](https://juejin.cn/post/6844903571905839111#heading-4)
- [Android账户机制漏洞专题](https://zhuanlan.zhihu.com/p/39143908)


## 复现环境

使用android studio 自带的AVD，无论android版本选到4.1-4.3哪个版本均无法复现，在通过漏洞启动setting修改密码界面时会在logcat中发现如下错误，修了三个小时也没有修好（但其实我自己编译一个apk带有非导出activity是可以通过漏洞被启动的），因此我怀疑这个是模拟器模拟setting界面本身时出的问题：

> [Android Studio报错：E/EGL_emulation: tid 3197: eglSurfaceAttrib(1199): error 0x3009 (EGL_BAD_MATCH)_幻好的博客-CSDN博客](https://blog.csdn.net/qq_39771853/article/details/102797481)


![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/avderror.png)


后根据[https://github.com/EggUncle/LaunchAnyWhere/tree/master](https://github.com/EggUncle/LaunchAnyWhere/tree/master)其中的截图，使用老版本genymotion 3.0.3 中下载的android 4.3镜像复现成功：

> [Genymotion 的旧版本 (Windows) Uptodown](https://genymotion.cn.uptodown.com/windows/versions)



![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/genymotion.png)

通过点击button，即可自动跳转到修改pin码界面，推荐exp demo：

- [GitHub - stven0king/launchanywhere: study launch anywhere and bundle mismatch bug](https://github.com/stven0king/launchanywhere/tree/main)

![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/step.png)


## exp 相关

### exp demo


- [GitHub - retme7/launchAnyWhere_poc_by_retme_bug_7699048: source code & PoC file of  launchAnyWhere problem](https://github.com/retme7/launchAnyWhere_poc_by_retme_bug_7699048)
- [GitHub - stven0king/launchanywhere: study launch anywhere and bundle mismatch bug](https://github.com/stven0king/launchanywhere/tree/main)
- [GitHub - EggUncle/LaunchAnyWhere: 4.3及以下的一个系统漏洞](https://github.com/EggUncle/LaunchAnyWhere/tree/master)


### exp 调用梳理


manifest中首先要注册一个**service**，其中的xml不能少：


![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/servicexml.png)

xml中的accountType自定义设置好：


![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/accountType.png)


完成service对应的`MyAccountService`的类，在此类的onBind函数中返回另一个类`MyAuthenticator`的getIBinder，因为`MyAuthenticator`继承自`AbstractAccountAuthenticator`，所以其中就有getIBinder，不用管这个方法的实现。需要处理的是`MyAuthenticator`要处理的addAccount实现，这里要写最终要启动的目标intent，此函数返回的是一个Bundle，用攻击者视角这里就是在组织payload，所以这个payload不是主动发出去的，而是等着addAccount被调用时返回的。所以从通信的角度这可以看成：回包解析漏洞。


![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/MyAccountService.png)


然后就是`MainActivity`后就调用AddAccountSettings触发自动的addAccount，因此主要代码就这两部分：


![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/AddAccountSettings.png)


### exp demo 的 bug

在网友[EggUncle的exp demo](https://github.com/EggUncle/LaunchAnyWhere/tree/master)中，无法通过点击触发第0步的com.android.settings.accounts.AddAccountSettings，原因是启动AddAccountSettings时，account_types参数传递错误：


![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/account_error.png)

经过排错分析，调用AddAccountSettings的目的是，让setting来访问本恶意app提供的账户服务，所以你传递的参数中必须得包含本恶意app信息，否则setting如何才能找回来，而account_types正是这么一个类似路由的参数。在本例中account_types需要与account_xml.xml中定义的android:accountType相同，而account_xml.xml在manifest.xml中注册，所以最终AddAccountSettings才能根据account_types找回来：


![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/account_types.png)

网友这么写错的原因是他照抄了retme7的原始exp，但又没抄全，retme7的account_types使用的Constants，并不是egguncle的使用的SyncStateContract.Constants（这应该是自动补齐的结果）：

> [GitHub - retme7/launchAnyWhere_poc_by_retme_bug_7699048: source code & PoC file of  launchAnyWhere problem](https://github.com/retme7/launchAnyWhere_poc_by_retme_bug_7699048)



![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/Constants.png)


retme7的account_types使用的Constants是自己写的类，其中对account_types定义如下：


![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/retme7.png)


与其account_xml.xml中的一致：


![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/retme7xml.png)


### exp 简化


因为漏洞本身的触发逻辑是一个service的回包，这导致exp代码要分散到多个类中，而不能完全只在MainActivity中单独完成。在本例中，主要的逻辑有两部分：

1. **MainActivity的触发逻辑（对应图中step0）**
2. **MyAuthenticator 类中实现的addAccount的返回payload的组织逻辑（对应图中step3）**

这两部逻辑在大部分的exp中完全没有任何代码的关系，MainActivity没有直接调用到addAccount，这也造成了我在理解这个攻击代码时的费解，我无法理解payload的去向。payload由addAccount组织，而addAccount就在那单摆浮搁，没有任何人调用，一度陷入迷茫。

理解漏洞后明白，**MainActivity触发（step0）** 到 **addAccount组织payload（step3）** 之间的关联是由：**外部**的**Settings（系统app）**和**AccountManagerService.java（运行在system_server进程中）**来建立的，而不在本exp代码中。因此单独看exp不可能建立二者之间的关系：



![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/step.png)

所以我根据payload的组织与流向，改了一版对于攻击者来说易于理解的exp，主要是：

1. 封装了两个函数：触发与组织payload
2. 并允许触发并组织多次不同的payload
3. 然后把payload放在了MainActivity中

这样就强行的将exp中的payload与主函数相关联，便可一目了然payload的组织与去向，虽然看起来payload仍然停在了addAccount函数中，但至少可以确定payload是从MainActivity送入addAccount函数中，那么接下来一定是从这个addAccount函数出去，时机应该为trigger之后：


![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/myexp.png)


## 调试方法

### 断app


对于这种android代码，很多逻辑都是框架来处理的，比如组织payload的addAccount，在我们的app没有直接调用这个函数，那这个函数是被谁调用的呢？可以使用android studio进行调试非常方便，可以将断点打在addAccount函数上，断下后观察调用栈：

> 不过看起来只能追到binder，还是没找到上家（即通过AddAccountSettings触发的setting）


![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/debug1.png)


### 断system_server


漏洞点位于AccountManagerService.java，源码也就是可以下载的sdk源码（目标模拟器环境为Android 4.3 API 18），其最终运行在system_server进程中：

> [https://android.googlesource.com/platform/frameworks/base/+/c6568719671206e726f260fad390680f7fb0ee9e/services/java/com/android/server/accounts/AccountManagerService.java](https://android.googlesource.com/platform/frameworks/base/+/c6568719671206e726f260fad390680f7fb0ee9e/services/java/com/android/server/accounts/AccountManagerService.java)



![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/chat.png)



![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/chat2.png)

证明如下：


![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/maps.png)


拽出来逆向：


![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/re.png)

因此希望断在漏洞点处：

> [https://android.googlesource.com/platform/frameworks/base/+/5bab9da^!/#F0](https://android.googlesource.com/platform/frameworks/base/+/5bab9da%5E%21/#F0)

```java
if (result != null && !TextUtils.isEmpty(result.getString(AccountManager.KEY_AUTHTOKEN))) {
```

即直接调试system_server进程，方法如下：

- 调试的目标进程system_server在AS中提示的进程名为system_process
- 另外需要在android studio里手动打开漏洞的java源码，即API 18 的 SDK源码，然后打断点
- 执行exp app，即可断下


> `D:\AS\Sdk\sources\android-18\com\android\server\accounts\AccountManagerService.java`


![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/AccountManagerService.png)

### 断settings


**调试settings程序有些麻烦，但却是最重要的，因为整个交互的调度的一大部分逻辑都在Settings中，最开始的触发是Settings干的，最后拉起目标Activity 还是 Settings干的，所以如果没有调试到Settings，那么对于漏洞的理解一定是空中楼阁。调试Settings程序需要源码和apk：**

（1）settings的源码在AOSP中，如下，下载对应分支为android-4.3_r3的源码：

> [https://android.googlesource.com/platform/packages/apps/Settings/](https://android.googlesource.com/platform/packages/apps/Settings/)


```bash
➜  git clone https://android.googlesource.com/platform/packages/apps/Settings  --depth=1 --single-branch -b android-4.3_r3
```


（2）拿到settings程序的apk，apk路径可以通过pm path命令获得，位于：/system/app/Settings.apk

> [获取 Android 已安装应用的 .apk 安装包文件](https://www.jianshu.com/p/d25b85ccdda0)

```bash
root@vbox86p:/ # pm path com.android.settings
package:/system/app/Settings.apk
```


（3）调试方法如下，就是AS中导入apk并关联源码，调试目标选择和选择system_server过程类似：

> [调试预构建的 APK - Android Studio - Android Developers](https://developer.android.com/studio/debug/apk-debugger?hl=zh-cn)


![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/debug_Settings.png)

执行exp，成功断到`AddAccountSettings`的`onCreate`中的`startActivityForResult`函数，但需要在f7单步一下，才能在变量窗口中看到此时的intent，即可跟踪到下一个函数中：


![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/debug_Settings2.png)


## 漏洞过程分析


目标就是把下图的调用过程，通过调试器，切切实实的看到一遍：


![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/step.png)


因为总体涉及到三部分的代码，所以可能需要开启多个窗口：

- [Android Studio同时打开多个项目_小向光的博客-CSDN博客](https://blog.csdn.net/wuyou1336/article/details/67006398)

约定以下的标题格式大概为：**进程名：JAVA类名：函数名：出口函数名**，并且进程名有如下约定

- exp的进程名实际为包名com.xuan.launchanywhere，简写为 **exp**
- Settings的进程名实际为包名com.android.settings，简写为 **Settings**

整体调用过程大概如下：

![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/index.png)


### (step 0) [exp]：MainActivity（Activity）：onCreate：trigger：startActivity


- **类名: com.xuan.launchanywhere.MainActivity**
- [https://github.com/xuanxuanblingbling/geekcon-android/blob/master/launchAnyWhere/app/src/main/java/com/xuan/launchanywhere/MainActivity.java](https://github.com/xuanxuanblingbling/geekcon-android/blob/master/launchAnyWhere/app/src/main/java/com/xuan/launchanywhere/MainActivity.java)

首先是我们exp中的trigger函数发送的intent，调出到settings中的**AddAccountSettings**， 因为是intent我们自己构造的，所以调试窗口看到的变量信息没有什么特殊的：

> 如果关注后续的反序列化漏洞可以看到，此时的bundle还没有序列化（mParcelledData为空）


![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/trigger.png)

这个调用过程也正对应攻击流程图中的step 0：


![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/step0.png)


所以解下来要断到Settings中，无需中断本次app的调试，直接在另一个调试settings的窗口打断，然后在本次app的调试窗口中继续执行，断点断下后，AS会自动切换到调试settings的窗口。


### (………..) [Settings]：AddAccountSettings（Activity）：onCreate：startActivityForResult



- **类名: com.android.settings.accounts.AddAccountSettings**
- [https://android.googlesource.com/platform/packages/apps/Settings/+/refs/tags/android-4.3_r3/src/com/android/settings/accounts/AddAccountSettings.java](https://android.googlesource.com/platform/packages/apps/Settings/+/refs/tags/android-4.3_r3/src/com/android/settings/accounts/AddAccountSettings.java)

来到Settings的AddAccountSettings.java的onCreate函数，可以看到this.mintent就是启动此Activity所使用的intent，不过从此intent和this所有成员中均无法看出来是我的exp(`com.xuan.launchanywhere`)发起的此次调用，好像是在API22 (Android 5.1)才有this.getReferrer().getHost()方法获得调用者：

- [How to get the sender of an Intent?](https://stackoverflow.com/questions/3304304/how-to-get-the-sender-of-an-intent)

> 另外通过mIntent的mExtras也可以看出此时其中的bundle还未反序列化


![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/onCreate.png)

在执行完142行的getStingArrayExtra后，bundle完成了反序列化，其实可以通过观察bundle类的源码得知，基本是对bundle进行任意的读取操作，都会触发整个bundle的反序列化，之后会详细分析：

> [core/java/android/os/Bundle.java - platform/frameworks/base - Git at Google](https://android.googlesource.com/platform/frameworks/base/+/master/core/java/android/os/Bundle.java)


![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/getStingArrayExtra.png)


走到onCreate的最后，断到`startActivityForResult`时，调试窗口看不到intent变量，需要f7单步一下，才能正常显示。可见其使用`startActivityForResult`的启动了仍然在本包名下的ChooseAccountActivity，因此本次调用没有从Settings进程出去。并且原封不动的传递了我们exp中发送的account_type相关数据：


![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/ChooseAccountActivity.png)

### (………..) [Settings]：ChooseAccountActivity（Activity）：onCreate：onAuthDescriptionsUpdated：finish


- **类名: com.android.settings.accounts.ChooseAccountActivity**
- [https://android.googlesource.com/platform/packages/apps/Settings/+/refs/tags/android-4.3_r3/src/com/android/settings/accounts/AddAccountSettings.java](https://android.googlesource.com/platform/packages/apps/Settings/+/refs/tags/android-4.3_r3/src/com/android/settings/accounts/ChooseAccountActivity.java)

通过AddAccountSettings的`startActivityForResult`来到ChooseAccountActivity的onCreate函数，经过分析在ChooseAccountActivity中整个的调用流程为：

```bash
onCreate → updateAuthDescriptions → onAuthDescriptionsUpdated →  finishWithAccountType → finish 
```

最终通过finish函数，最后回到AddAccountSettings的`onActivityResult`，因此在整个漏洞利用的过程中，调用流经过ChooseAccountActivity的过程不太重要。


![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/finish.png)

稍微值得注意的是，在ChooseAccountActivity中的`onAuthDescriptionsUpdated` 函数会调用`AccountManager.*get*(this).getAuthenticatorTypes`，控制流会从此进程直接出到`AccountManagerSerivce`（`AccountManager`是服务接口java，即还在本进程中的代码）。调用出去的目的是查询我们传递的account_types是否又对应注册的认证服务，不过者对之后的回到AddAccountSettings没有什么太大的影响。**总之控制流在ChooseAccountActivity逛了一圈 ，没干啥特别主要的事。**



![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/ChooseAccountActivity_debug.png)

在最后的finishWithAccountType，对将要回到AddAccountSettings的onActivityResult设置的结果为：RESULT_OK，和将我们发送的account_type改了个名，但值没有变化传递回来了。


![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/finishWithAccountType.png)


### (step 1) [Settings]：AddAccountSettings(Activity)：onActivityResult：addAccount：AccountManager.get(this).addAccount


- **类名: com.android.settings.accounts.AddAccountSettings**
- [https://android.googlesource.com/platform/packages/apps/Settings/+/refs/tags/android-4.3_r3/src/com/android/settings/accounts/AddAccountSettings.java](https://android.googlesource.com/platform/packages/apps/Settings/+/refs/tags/android-4.3_r3/src/com/android/settings/accounts/AddAccountSettings.java)


之前从AddAccountSettings折腾到ChooseAccountActivity，又回到AddAccountSettings，其实还没有从settings进程出去，也其实还没到攻击流程图中的step1。现在回到AddAccountSettings的onActivityResult，这里终于要从Settings进程出去了：

- 根据requestCode和resultCode的结果，其会进入addAccount函数
- addAccount函数调用 AccountManager.get(this).addAccount，并传递`mCallback`函数指针
- 因此`mCallback`应该会在 AccountManager.get(this).addAccount执行后回调
- AccountManager 的完整类名为：android.accounts.AccountManager，并不在settings源码中，而在SDK源码中，源码AS可以直接下载
- AccountManager.get(this).addAccount最终调用到AccountManager.java中的addAccount函数
- AccountManager.java中的addAccount会调用mService.addAccount，这就从Settings进程出去了
- 调用出去的服务就是运行在**system_server**进程中的**AccountManagerService.java**
- 调用参数可以看到主要还是我们最开始传递的account_types

对这里调用的调用过程也可以看图中的调用栈进行观察：

> [http://androidxref.com/4.3_r2.1/xref/frameworks/base/core/java/android/accounts/AccountManager.java](http://androidxref.com/4.3_r2.1/xref/frameworks/base/core/java/android/accounts/AccountManager.java)

![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/addAccount_debug.png)


调用过程对应图中的step 1，另外因为对android的service机制确实不熟，所以就没去在调试中证明此处出去的目标确实为AccountManagerService：

![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/step1.png)



### (step 2) [system_server]: AccountManagerService（IAccountManager.Stub）：addAccount：new Session(){}：mAuthenticator.addAccount


> 调试system_server可以复用exp的窗口，也可以单独打开窗口加载对应的sdk源码进行调试

- **类名: com.android.server.accounts.AccountManagerService**
- [http://androidxref.com/4.3_r2.1/xref/frameworks/base/services/java/com/android/server/ accounts/AccountManagerService.java](http://androidxref.com/4.3_r2.1/xref/frameworks/base/services/java/com/android/server/accounts/AccountManagerService.java)


将断点断在AccountManagerService.java的addAccount函数开头处，如1456行，成功断下（1447行无法断下），在addAccount中经过一系列操作会走到1487行的new Session，这句写法有一些奇怪，仔细解释一下这种写法：匿名内部类（匿名类）

> [傻子都能看懂的匿名内部类](https://www.jianshu.com/p/0950c6787c7d)


- 写法的样子是：new的类后面还能加上大括号并且包裹代码
- 写法的含义是：新建一个匿名类并实例化（Session是一个抽象类，正常使用需要被继承）
- 写法的功能是：简化抽象类和接口的使用，可直接重写其方法，而不用新定义一个class
- “内部”二字的解释：因为这个类的定义和实例化，只存在于当前函数的作用域中，除非此函数将其当成参数传递出去，否则别的函数无法直接使用这个类，因此这个类是“匿名”且“内部”的。


![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/newSession.png)


所以对于AccountManagerService.java中的new Session：

- 新建一个匿名类并实例化（Session是一个抽象类，正常使用需要被继承）
- 重写Session抽象类的run方法和toDebugString方法
- 然后调用Session抽象类的bind方法
- 所以这里并没有直接调用重写的run方法
- 而是其实调用了两个函数：**Session抽象类构造函数**和**Session抽象类的bind函数**

![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/newSession2.png)


没有直接执行run函数，但也可以看到我们之前的断点也确实断在了run函数中，所以run也确实被执行了，通过调用栈可以看出，其父级函数onServiceConnected，而在AccountManagerService.java中并没有onServiceConnected函数的直接调用，因此run函数是回调回来的：


![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/onServiceConnected.png)

因此只能正向分析，即通过new Session调用的构造函数和bind，构造函数里没有什么特别的调用，但可以看到bind函数调用的bindToAuthenticator中有一些操作：

- `mAuthenticatorCache.getServiceInfo`会通过我传递的account_types查出对应的包名和Service名
- `mContext.bindServiceAsUser`将查出来的包名和Service名作为Intent的目标进行调用
- 所以推测这里当成功与目标Service建立连接后，即可以回调执行onServiceConnected

![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/bindServiceAsUser.png)


回调执行onServiceConnected，调用run函数，通过run函数的mAuthenticator.addAccount，调用出到exp中的MyAuthenticator.addAccount：

![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/onServiceConnected.png)

此调用过程对应图中的step 2：


![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/step2.png)


### (step 3) [exp]: MyAuthenticator(AbstractAccountAuthenticator)： addAccount：return


- **类名: com.xuan.launchanywhere.MyAuthenticator**
- [https://github.com/xuanxuanblingbling/geekcon-android/blob/master/launchAnyWhere/app/src/main/java/com/xuan/launchanywhere/MyAuthenticator.java](https://github.com/xuanxuanblingbling/geekcon-android/blob/master/launchAnyWhere/app/src/main/java/com/xuan/launchanywhere/MyAuthenticator.java)

断点回到exp中的MyAuthenticator.addAccount，就是返回payload bundle：


![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/MyAuthenticator.png)

此过程对应图中的step 3，这里虽然最简单，但其实是最重要通信过程，即**发送payload的过程**，也就是之前说的在通信的角度payload其实是回包：


![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/step3.png)


### (！bug) [system_server]：AccountManagerService（IAccountManager.Stub）：Session(){}：onResult：response.onResult


- **类名: com.android.server.accounts.AccountManagerService**
- [http://androidxref.com/4.3_r2.1/xref/frameworks/base/services/java/com/android/server/ accounts/AccountManagerService.java](http://androidxref.com/4.3_r2.1/xref/frameworks/base/services/java/com/android/server/accounts/AccountManagerService.java)


回到AccountManagerService.java中Session抽象类的onResult，断点到此函数开头成功命中，参数就是从exp的addAccount返回的payload bundle。通过调试窗口可以观察返回变量名为result的payload bundle，可见此时bundle的mMap中还没有任何内容，而mParcelledData还是有值的，所以此时这个payload bundle还没有反序列化：

![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/40.png)


单步一下调试就会自动的跟入onResult第一句判断中调用的getString函数，这个是bundle类的函数接口，bundle类的get系列函数都是上来就会调用unparcel，对此bundle对象进行反序列化：


![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/41.png)

> [Android 反序列化漏洞攻防史话](https://evilpan.com/2023/02/18/parcel-bugs/#反序列化与-bundle-风水)


![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/evilpan.png)


执行完unparcel后，再观察调试窗口中解析的bundle对象，可见传递的payload intent已经成功解析出来，即已经执行了intent对象的反序列化函数。但这里其实有一个问题：**我们序列化的任意类都可以被目标反序列化出来么**？这个问题关乎对后续漏洞（拼多多所利用的CVE-2023-20963）理解。如果从原理回答这个问题，可以将其转化为另一个问题：传递过来的bundle里需要被反序列化的对象，其对应的反序列化函数位于对应的类中，那么unparcel是如何调用过去的呢？


![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/43.png)

我们可以重新断在system_server进程中AccountManagerService.java中Session抽象类的onResult函数开头，此时bundle还没有反序列化，然后将下一个断点打**在intent的反序列化函数readFromParcel**函数上，然后继续执行，断下后观察调用栈如下。可以看到unparcel确实能直接调用到intent的反序列化函数readFromParcel，所以推测序列化的bundle里应该包含了intent的完整类名，能调用过来的原理应该类似反射，通过类名，加载对应类的反序列化函数然后再进行调用：


![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/44.png)

可以在exp中，把发送的payload bundle的序列化后内容打出来，可见确实包含intent的完整类名 `android.content.Intent`：


![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/bundle_hex.png)

上面讨论反序列化主要是希望对后续的漏洞有更好的理解，现在回到本漏洞分析中，在Session类的onResult函数中，对于返回的result bundle反序列化后，**没有对其中的intent对象进行任何检查**，就继续调用了response.onResult，将整个bundle返回给了Settings，这就是bug所在：

![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/46.png)


这个response对象是创建new Session这个匿名类时的参数，类型是IAccountManagerResponse，再往上找是step1中Settings调用 AccountManager.get(this).addAccount，在AccountManager.java中传递过去的。所以此时Session类中onResult调用的response.onResult能找回到Settings：

![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/addAccount_debug.png)


此过程对应攻击流程图中如下部分：

![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/step_bug.png)



### (step 4) [Settings]：AddAccountSettings（Activity）：mCallback：run：startActivityForResult


- **类名: com.android.settings.accounts.AddAccountSettings**
- [https://android.googlesource.com/platform/packages/apps/Settings/+/refs/tags/android-4.3_r3/src/com/android/settings/accounts/AddAccountSettings.java](https://android.googlesource.com/platform/packages/apps/Settings/+/refs/tags/android-4.3_r3/src/com/android/settings/accounts/AddAccountSettings.java)

step1中Settings调用 AccountManager.get(this).addAccount时传递了一个回调函数**mCallback**，当AccountManagerService.java中Session抽象类onResult调用response.onResult时，返回到Settings中，即会触发mCallback函数的执行。断点断到这，即可看到这里会**解析返回bundle中的intent**：

![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/48.png)

这个intent也没有任何检查，直接就作为startActivityForResult参数，即发起了最后的启动调用：

![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/49.png)

此过程对应图中的step 4：

![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/step4.png)

bundle.get和bundle.getParcelable基本没有区别：

> [http://androidxref.com/4.3_r2.1/xref/frameworks/base/core/java/android/os/Bundle.java](http://androidxref.com/4.3_r2.1/xref/frameworks/base/core/java/android/os/Bundle.java)


![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/51.png)


## 补丁分析

### 补丁简介

> [https://android.googlesource.com/platform/frameworks/base/+/5bab9da^!/#F0](https://android.googlesource.com/platform/frameworks/base/+/5bab9da%5E%21/#F0)

```patch
+   @Override
    public void onResult(Bundle result) {
        mNumResults++;
-       if (result != null && !TextUtils.isEmpty(result.getString(AccountManager.KEY_AUTHTOKEN))) {
+       Intent intent = null;
+       if (result != null
+               && (intent = result.getParcelable(AccountManager.KEY_INTENT)) != null) {
+           /*
+            * The Authenticator API allows third party authenticators to
+            * supply arbitrary intents to other apps that they can run,
+            * this can be very bad when those apps are in the system like
+            * the System Settings.
+            */
+           PackageManager pm = mContext.getPackageManager();
+           ResolveInfo resolveInfo = pm.resolveActivity(intent, 0);
+           int targetUid = resolveInfo.activityInfo.applicationInfo.uid;
+           int authenticatorUid = Binder.getCallingUid();
+           if (PackageManager.SIGNATURE_MATCH !=
+                   pm.checkSignatures(authenticatorUid, targetUid)) {
+               throw new SecurityException(
+                       "Activity to be started with KEY_INTENT must " +
+                       "share Authenticator's signatures");
+           }
+       }
+       if (result != null
+               && !TextUtils.isEmpty(result.getString(AccountManager.KEY_AUTHTOKEN))) {
            String accountName = result.getString(AccountManager.KEY_ACCOUNT_NAME);
            String accountType = result.getString(AccountManager.KEY_ACCOUNT_TYPE);
            if (!TextUtils.isEmpty(accountName) && !TextUtils.isEmpty(accountType)) {
```

最重要的一句如下，是对`authenticatorUid`和`targetUid`的对应的程序是否具有相同签名的判定：

```java
PackageManager.SIGNATURE_MATCH !=  pm.checkSignatures(authenticatorUid, targetUid))
```

### 补丁环境

模拟器环境使用Android Studio AVD提供的android 4.4（已经修复漏洞）：

![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/52.png)


启动后执行exp，查看logcat打印，确实打印了补丁的检查失败的提示：

![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/53.png)


### 补丁调试

补丁在AccountManagerService.java中，所以仍然是调试system_server，断在Session抽象类的onResult的函数中，补丁中的authenticatorUid通过**Binder.getCallingUid**函数获得，即回传 payload bundle的exp程序对应的uid，结果为10052：

![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/54.png)

可以在adb中使用dumpsys package命令并提供exp的包名获得其对应的uid，与调试结果一致：

![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/uid.png)

接下来，补丁会通过**PackageManager**的相关函数，从接收的bundle中解析出intent并确定intent中目标class对应的uid，即targetUid，结果为1000，这就是Settings进程对应的system权限：

![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/56.png)

最后通过`pm.checkSignatures`函数检查两个uid对应的签名，本次攻击中，这个判断结果为不必配，补丁会抛出一个异常，中止给Settings回传bundle，最后关于uid：


![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/57.png)
![image](https://xuanxuanblingbling.github.io/assets/pic/launchanywhere1/58.png)