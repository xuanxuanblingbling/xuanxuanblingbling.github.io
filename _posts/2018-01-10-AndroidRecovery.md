---
title: Android刷机
date: 2018-01-10 00:00:00
categories:
- CTF/Android
tags: Android刷机 kali nethunter
---

## 分类

刷机就是给android设备换操作系统的过程，以下三种刷机方式均能实现同样的更换系统的效果，但是三种刷机包的文件以及手机在刷机时的状态是不同的，要注意区分。

### 卡刷（recovery）

- 将完整的刷机包放入手机的sdcard中
- 手机进入recovery模式直接安装，整个安装不需要电脑参与
- 简单快捷，不易出错，适合新手

### 线刷（fastboot）

- 刷机包在电脑中，利用刷机软件对手机进行刷机
- 实际上手机进入了fastboot模式
- 需要电脑安装好手机驱动并连接
- 容易出错，一般用来救砖

### OTA（Android OS）

- Over-The-Air 空中下载技术
- 就是手机设置中更新操纵系统，下载补丁包，文件不大
- 手机就在Android OS层面完成了补丁的下载，并自动更新
- 一般手机root后将不再提供系统更新

## 模式

![image](http://images.cnitblog.com/blog2015/268182/201503/220742469229678.png)

### fastboot

进入方式：开机+音量上（一般）

>fastboot 主要是用来与bootloader的USB通讯的PC命令行工具。他一般主要也用来向bootloader传送刷机文件进行文件分区重烧。 因此在使用时，必须有一个PC机并且USB线要始终联着。所以这种方式称为线刷。 用fastboot需要bootloader 支持，所以不是每一家公司产品都支的这个功能的。

Android通过Fastboot刷机 >>> Fastboot的作用是开机后初始化硬件环境，实现最小系统，然后和PC上的刷机软件通讯，将PC上的刷机包写入至Emmc中，实现刷机。Recovery此时不起作用。

### recovery

进入方式：开机+音量下（一般）

> recovery过程主要有两个作用 ：factory reset 和 OTA install。一般Android系统都有两个分区 /boot /recovery。这两个分区都可以引导系统。recovery mode从本质上来看就像是一个**袖珍版的Linux**。简而言之，recovery模式其实方便了开发者升级系统和擦除相应的分区( /data和/cache )。在手机方面，这个功能可以体现在刷机的过程上。不过，对于一般用户来说，这个recovery mode对于开发者意义更大。

Android通过Recovery刷机 >>> Fastboot的作用是开机后初始化硬件环境，实现最小系统，然后引导Recovery启动，在Recovery中读取升级包数据，将升级包数据写至Emmc。这种方式，Fastboot和Recovery都起到各自的功能。而且第三方recovery的安装是要先进入fastboot模式的。

## 刷机包

这里主要介绍卡刷的刷机包，内核以及基带是可以单刷的。

### 组成
- ROM：就是手机的操作系统的文件包，一般是包括内核和基带的。

- 内核：Android操作系统的内核，操作系统的核心部分。一般集成在ROM包中，也可以单独成包。

- 基带：手机的通信固件，决定了手机可以使用的运营商服务。一般集成在ROM包中，也可以单独成包。


### 底包

刷机过程中，一般先刷入比较稳定的Android操作系统的ROM，再进行后续刷机，这称之为刷底包。常用的底包为`CyanogenMod 12.1 /13`，但CM公司已经倒闭，目前的相应机型的底包需要在各大论坛找到，比如ROM之家`http://www.romzj.com/`

### 误区

卡刷的刷机包文件未必只一个单独的文件，**所以当你遇到多个文件，并且告诉你这都是刷机包的时候，千万不要害怕**。这是可以在recovery中设置刷机序列，并且固件刷入的顺序是无所谓的。当你的rom文件中不含内核时，你可以先刷rom再刷内核，也可以先刷内核再刷rom。

## kali nethunter实践

- 在闲鱼上花了330￥入手了部oneplus one，自带的recovery很好用。
- 参考如下的刷机过程，不要在官网下载完整的ROM包，用参考中的内核与ROM分开的刷机包进行刷机是比较稳定的。
- 遇到了kali开机反复重启的问题，一顿反复刷机，确定为底包的问题，更换CM12.1底包为CM13，完美开机。当然不是12.1还是13的问题，是我的CM12.1这个网上的底包本身有问题，换用其他编译版本CM12.1也许同样也能解决。

```
1. cm-13.0-20160415-XXOS-bacon.zip  
2. kernel-nethunter-oneplus1-marshmallow-3.15.3-20161201-1343.zip 
3. nethunter-generic-armhf-kalifs-full-rolling-3.15.3-20161201-1343.zip
 ```

## 参考

> FastBoot BootLoader Recovery 模式解释  
> [http://blog.csdn.net/xiaoxiaozhu2010/article/details/51510107](http://blog.csdn.net/xiaoxiaozhu2010/article/details/51510107)

> 移动渗透测试平台搭建 – NetHunter 3.0   
> [http://www.freebuf.com/sectool/124074.html](http://www.freebuf.com/sectool/124074.html)