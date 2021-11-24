import sys
import os
import archinfo
from capstone import *
from capstone.x86 import *

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

import angr
import angr.analyses.cfg.indirect_jump_resolvers.resolver as resolver
import networkx
from angrutils import *

class Indirects():
    def __init__(self, binary):
        elf = ELFFile(binary)
        self.section = elf.get_section_by_name('.text')
        if not self.section:
            print("[X] Can't find text section in binary!")
            return
        
        self.base = self.section.header['sh_addr']
        self.init_base = elf.get_section_by_name(".init").header['sh_addr']
        fin = elf.get_section_by_name(".fini")
        self.end = fin.header['sh_addr'] + fin.data_size

        self.disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
        self.disassembler.detail = True
        _assembly = self.disassembler.disasm(self.section.data(), self.base)
        self.assembly = []
        for i in _assembly:
            self.assembly.append(i)
        self.indirects= {}
    
    def indirect_list(self):
        for index, insn in enumerate(self.assembly):
            if insn.mnemonic == 'ud2':
                call = None

                jump_table_len = 0 
                jump_table_addr = 0
                jump_table_targets = []
            
                for target in self.assembly[index:]:
                    if target.mnemonic == "call" and target.size == 2:
                        call = target
                        break
                for _index, target in enumerate(reversed(self.assembly[:index])):
                    if target.mnemonic == 'cmp':
                        if target.op_count(X86_OP_IMM) != 0 :
                            op = target.op_find(X86_OP_IMM, 1)
                            jump_table_len = op.imm

                    if target.mnemonic == 'lea':
                        disp = target.op_find(X86_OP_MEM, 1).mem.disp
                        rip = self.assembly[index - _index].address
                        jump_table_addr = rip + disp
                        break

                    if target.mnemonic == 'movabs':
                        jump_table_addr = target.op_find(X86_OP_IMM, 1).imm
                        break

                for j in range(jump_table_len + 1) :
                    slot_address = jump_table_addr + j*8
                    insns = self.disassembler.disasm(self.section.data()[slot_address - self.base:], slot_address)
                    func_body = None
                    for k in insns:
                        func_body = k
                        break
                    jump_table_targets.append(func_body.op_find(X86_OP_IMM, 1).imm)
                self.indirects[call.address] = jump_table_targets
        return self.indirects
    
    def print_list(self):
        for i in self.indirects.keys():
            print(hex(i), '-> ', end="")
            for j in self.indirects[i]:
                print(hex(j), end=", ")
            print()