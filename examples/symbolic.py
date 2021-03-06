import angr
import claripy
import subprocess
import avatar2
import sys
from angr_targets import AvatarGDBConcreteTarget

STDIN_FD = 0
GDB_SERVER_IP = "localhost"
GDB_SERVER_PORT = 12345
TARGET_BINARY = "./main.o"

base_addr = 0x400000 # To match addresses to Ghidra

# iCFG will give the path to target
# vuln, first_gate, second_gate, third_gate, target
path = [
    0x401310,
    0x401030,
    0x40134b,
    0x401040,
    0x40137d,
    0x401399,
    0x4013c3,
    0x401240,
    0x40125e,
    0x401264,
    0x40128e,
    0x401140,
    0x401159,
    0x401176,
    0x4012e0,
    0x4012f1,
    0x4011e0
]

# Not-working example
# path = [
# 0x401310,
# 0x40134b,
# 0x401360,
# 0x40137d,
# 0x401399,
# 0x4013c3,
# 0x401240,
# 0x40125e,
# 0x401297,
# 0x4012c5,
# 0x401190,
# 0x4011a9,
# 0x4011c6,
# 0x4012e0,
# 0x4012f1,
# 0x4011e0,
# ]

# path = [
# 0x401310,
# 0x40134b,
# 0x401360,
# 0x40137d,
# 0x401399,
# 0x4013c3,
# 0x401240,
# 0x40125e,
# 0x401264,
# 0x40128e,
# 0x401190,
# 0x4011a9,
# 0x4011c6,
# 0x4012e0,
# 0x4012f1,
# 0x4011e0,
# ]
vuln = path.pop(0)

# concrete execution
subprocess.Popen("gdbserver %s:%s %s" % (GDB_SERVER_IP,GDB_SERVER_PORT,TARGET_BINARY),
                  stdout=subprocess.PIPE,
                  stderr=subprocess.PIPE, shell=True)

avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86_64, GDB_SERVER_IP, GDB_SERVER_PORT)
proj = angr.Project(TARGET_BINARY, main_opts={'base_addr': base_addr}, concrete_target=avatar_gdb, use_sim_procedures=True) 

entry_state = proj.factory.entry_state()

entry_state.options.add(angr.options.SYMBION_SYNC_CLE)
entry_state.options.add(angr.options.SYMBION_KEEP_STUBS_ON_SYNC)

un_init_func_table_addr = 0x404050

simgr = proj.factory.simulation_manager(entry_state)

simgr.use_technique(angr.exploration_techniques.Symbion(find=[vuln]))

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