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


def indirect_list(assembly, disassembler, section, base):
    indirects= {}
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
            # indirects.append({call.address: jump_table_targets})
            indirects[call.address] = jump_table_targets
    return indirects

def print_list(_list):
    for i in _list.keys():
        print(hex(i), '-> ', end="")
        for j in _list[i]:
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
    print(indirects)
    
    proj = angr.Project(binary_path, load_options={'auto_load_libs':False})
    p = proj
    main = proj.loader.main_object.get_symbol("main")
    vuln = proj.loader.main_object.get_symbol("vuln")
    target = proj.loader.main_object.get_symbol("target")
    start_state = proj.factory.blank_state(addr=main.rebased_addr)
    # cfg = proj.analyses.CFGEmulated(fail_fast=True, starts=[main.rebased_addr], initial_state=start_state, enable_symbolic_back_traversal=True)

    
    indirect_reslover = IFCCReslover(proj, indirects)
    cfg = proj.analyses.CFGFast(
        function_starts=[main.rebased_addr], 
        indirect_jump_resolvers = tuple(
		angr.analyses.cfg.indirect_jump_resolvers.default_resolvers.default_indirect_jump_resolvers(
			proj.loader.main_object,
			proj
		)) + (indirect_reslover,)
    )

    entry_node = cfg.get_any_node(p.entry)
    vuln_node = cfg.get_any_node(vuln.rebased_addr)
    target_node = cfg.get_any_node(target.rebased_addr)

    # This is our goal!
    paths = networkx.all_simple_paths(cfg.graph, vuln_node, target_node)

    # paths = networkx.all_simple_paths(cfg.graph, entry_node, vuln_node)
    for path in paths:
        for node in path:
            print(hex(node.addr))
        print()

    # For print CFG as png
    plot_cfg(cfg, "ais3_cfg", asminst=True, remove_imports=True, remove_path_terminator=True)  
    # irsb = pyvex.lift(section.data(), base, archinfo.ArchAMD64())
    # irsb.next.next.pp()

# this is the IR Expression of the jump target of the unconditional exit at the end of the basic block
    #print(irsb.next)
    

if __name__ == "__main__":
    if __package__ is None:
        import sys
        from os import path
        print(path.dirname( path.dirname( path.abspath(__file__) ) ))
        sys.path.append(path.dirname( path.dirname( path.abspath(__file__) ) ))
        from cfg import IFCCReslover
    else:
        from ..iCFG.cfg import IFCCReslover
    main()