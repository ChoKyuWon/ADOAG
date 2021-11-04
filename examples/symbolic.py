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

simgr = proj.factory.simulation_manager(entry_state)

simgr.use_technique(angr.exploration_techniques.Symbion(find=[vuln]))

exploration = simgr.run()
vuln_state = None
if len(exploration_techniques.stashes['found']) > 0:
    vuln_state = exploration.stashes['found'][0]

if vuln_state == None:
    print("Something's wrong, I can feel it")
    sys.exit(0)


#symbolic execution
simgr = proj.factory.simulation_manager(vuln_state)


for checkpoint in path:
    simgr.explore(find=checkpoint)
    if len(simgr.found) > 0 and checkpoint != path[-1]:
        simgr = proj.factory.simulation_manager(simgr.found[0])
        print(hex(checkpoint), "Found! move to next checkpoint.")

print(simgr.found[0].posix.dumps(STDIN_FD))
# b'00000000000004199496000000000000041994720000000000'