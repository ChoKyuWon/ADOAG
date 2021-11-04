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
path = [0x401310, 0x401448, 0x401430, 0x401450, 0x4011e0]
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

print(simgr.found[0].posix.dumps(STDIN_FD))
