import angr
import claripy
import subprocess
import avatar2
import sys
import os
import networkx
from angr_targets import AvatarGDBConcreteTarget

if __name__ == "__main__" and __package__ is None:
    from sys import path
    from os.path import dirname as dir

    path.append(dir(path[0]))
    __package__ = "iCFG"

from ..iCFG.find_indirects import Indirects
from ..iCFG.jump_resolver import IFCCReslover

STDIN_FD = 0
GDB_SERVER_IP = "localhost"
GDB_SERVER_PORT = 12345
binary_path = os.path.dirname(os.path.abspath(__file__)) + "/../examples/main.o"
TARGET_BINARY = binary_path

base_addr = 0x400000 # To match addresses to Ghidra

subprocess.Popen("gdbserver %s:%s %s" % (GDB_SERVER_IP,GDB_SERVER_PORT,TARGET_BINARY),
                  stdout=subprocess.PIPE,
                  stderr=subprocess.PIPE, shell=True)

avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86_64, GDB_SERVER_IP, GDB_SERVER_PORT)
proj = angr.Project(TARGET_BINARY, main_opts={'base_addr': base_addr}, concrete_target=avatar_gdb, use_sim_procedures=True) 

if len(sys.argv) > 1:
    binary_path = sys.argv[1]
bin = open(binary_path, 'rb')

indirects = Indirects(bin)
indirects.indirect_list()

indirect_reslover = IFCCReslover(proj, indirects.indirects)

main = proj.loader.main_object.get_symbol("main")
vuln = proj.loader.main_object.get_symbol("vuln")
target = proj.loader.main_object.get_symbol("target")


proj_cfg = angr.Project(binary_path, load_options={'auto_load_libs':False})
cfg = proj_cfg.analyses.CFGFast(
    function_starts=[main.rebased_addr], 
    indirect_jump_resolvers = tuple(
	angr.analyses.cfg.indirect_jump_resolvers.default_resolvers.default_indirect_jump_resolvers(
		proj_cfg.loader.main_object,
		proj_cfg
	)) + (indirect_reslover,)
)



src_node = cfg.model.get_any_node(vuln.rebased_addr)
dst_node = cfg.model.get_any_node(target.rebased_addr)
# entry_node = cfg.get_any_node(proj.entry)
print("Now we got CFG!")
# For print CFG as png
# plot_cfg(cfg, "ais3_cfg", asminst=True, remove_imports=True, remove_path_terminator=True)  
# ddg = proj.analyses.DDG(cfg=cfg)
# plot_ddg_stmt(ddg.graph, "ddg_stmt", project=proj)
# This is our goal!
paths = networkx.all_simple_paths(cfg.graph, src_node, dst_node)

# paths = networkx.all_simple_paths(cfg.graph, entry_node, vuln_node)
path = []
for _path in paths:
    for node in _path:
        if (node.addr < indirects.init_base) or (node.addr > indirects.end):
            pass
        else:
            path.append(node.addr)
    break
# iCFG will give the path to target


# concrete execution


entry_state = proj.factory.entry_state()

entry_state.options.add(angr.options.SYMBION_SYNC_CLE)
entry_state.options.add(angr.options.SYMBION_KEEP_STUBS_ON_SYNC)

un_init_func_table_addr = 0x404050

simgr = proj.factory.simulation_manager(entry_state)

simgr.use_technique(angr.exploration_techniques.Symbion(find=[vuln.rebased_addr]))

exploration = simgr.run()
vuln_state = None
if len(exploration.stashes['found']) > 0:
    vuln_state = exploration.stashes['found'][0]

if vuln_state == None:
    print("Something's wrong, I can feel it")
    sys.exit(0)

un_init_func_table_val = int.from_bytes(avatar_gdb.read_memory(un_init_func_table_addr, 8), "little")
un_init_func_table = claripy.BVV(un_init_func_table_val, 64).reversed
vuln_state.memory.store(un_init_func_table_addr, un_init_func_table)

#symbolic execution
simgr = proj.factory.simulation_manager(vuln_state)

for checkpoint in path:
    simgr.explore(find=checkpoint)
    if len(simgr.found) > 0 and checkpoint != path[-1]:
        # just checking whether the address of third gate is in un_init_func_table
        print(simgr.found[0].memory.load(un_init_func_table_addr, 8))
        simgr = proj.factory.simulation_manager(simgr.found[0])
        print(hex(checkpoint), "Found! move to next checkpoint.")

if len(simgr.found) > 0:
    print(simgr.found[0].posix.dumps(STDIN_FD))
else:
    print("Not found")
# b'00000000000004199496000000000000041994720000000000'
