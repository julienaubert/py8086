import os
from emu8086 import DisAsm

def main(program):

    labels = {
                0x0:'start',
                0x6:'hlt',
                0x7:'cont',
                0x5d:'calltest',
                0x72:'rettest',
                0x81:'cont1',
                0x8f:'ascii_loop',
                0xa2:'boxloop',
                0xbb:'cont2',
                0xc3:'boxloop2',
                0xe6:'fibloop',
                0x100:'squareloop',
                0x11d:'primeloop',
                0x131:'primeloop_inner',
                0x13d:'primecont',
                0x144:'calcsq',
                0x14a:'calcsqloop',
                0x151:'calcsqfinish',
                0x154:'print',
                0x158:'printloop',
                0x169:'printchr',
                0x17c:'printnl',
                0x180:'printnlloop',
                0x18a:'printnum',
                0x198:'numloop_3digit',
                0x1ab:'numloop_2digit',
                0x1b6:'numcont_2digit',
                0x1bd:'numcont_1digit',
               }

    def labeled(addr):
        return labels[addr] if addr in labels else hex(addr)

    addr = 0
    for instr in DisAsm().instructions(program):
        if addr in labels:
            print "\n{0:>5}:".format(labels[addr])
        print "{0:<10}{1:<10}".format(hex(addr), instr),
        addr += instr.length()
        if (hasattr(instr, 'rel_addr')):
            print "# {0}".format(labeled(instr.rel_addr() + addr))
        else:
            print


if __name__ == '__main__':
    def program_path():
        return os.path.join(os.path.dirname(__file__), 'codegolf')
    main([ord(c) for c in open(program_path(), 'rb').read()])
