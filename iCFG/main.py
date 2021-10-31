import sys
import os
import archinfo
from capstone import *
from capstone.x86 import *

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

def indirect_list(assembly, disassembler, section, base):
    indirects= []
    for index, insn in enumerate(assembly):
        if insn.mnemonic == 'ud2':
            call = None

            jump_table_len = 0 
            jump_table_addr = 0
            jump_table_targets = []
        
            for target in assembly[index:]:
                if target.mnemonic == "call" and target.size == 2:
                    call = target
                    break
            for _index, target in enumerate(reversed(assembly[:index])):
                if target.mnemonic == 'cmp':
                    if target.op_count(X86_OP_IMM) != 0 :
                        op = target.op_find(X86_OP_IMM, 1)
                        jump_table_len = op.imm

                if target.mnemonic == 'lea':
                    disp = target.op_find(X86_OP_MEM, 1).mem.disp
                    rip = assembly[index - _index].address
                    jump_table_addr = rip + disp
                    break

                if target.mnemonic == 'movabs':
                    jump_table_addr = target.op_find(X86_OP_IMM, 1).imm
                    break

            for j in range(jump_table_len + 1) :
                slot_address = jump_table_addr + j*8
                insns = disassembler.disasm(section.data()[slot_address - base:], slot_address)
                func_body = None
                for k in insns:
                    func_body = k
                    break
                jump_table_targets.append(func_body.op_find(X86_OP_IMM, 1).imm)
            indirects.append([call.address, jump_table_targets])
    return indirects

def print_list(_list):
    for i in _list:
        print(hex(i[0]), '-> ', end="")
        for j in i[1]:
            print(hex(j), end=", ")
        print()
def main():

    binary_path = os.path.dirname(os.path.abspath(__file__)) + "/../examples/main.o"
    if len(sys.argv) > 1:
        binary_path = sys.argv[1]
    bin = open(binary_path, 'rb')
    elf = ELFFile(bin)
    section = elf.get_section_by_name('.text')
    if not section:
        print("[X] Can't find text section in binary!")
        exit()
    base = section.header['sh_addr']
    disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
    disassembler.detail = True
    _assembly = disassembler.disasm(section.data(), base)
    assembly = []
    for i in _assembly:
        assembly.append(i)

    indirects = indirect_list(assembly, disassembler, section, base)
    print_list(indirects)
    # irsb = pyvex.lift(section.data(), base, archinfo.ArchAMD64())
    # irsb.next.next.pp()

# this is the IR Expression of the jump target of the unconditional exit at the end of the basic block
    #print(irsb.next)
    

if __name__ == "__main__":
    main()