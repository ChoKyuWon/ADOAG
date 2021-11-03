import angr
import claripy

STDIN_FD = 0

base_addr = 0x400000 # To match addresses to Ghidra

# iCFG will give the path to target
# vuln, first_gate, second_gate, third_gate, target
path = [0x401310, 0x401448, 0x401430, 0x401450, 0x4011e0]

proj = angr.Project("./main.o", main_opts={'base_addr': base_addr}) 

obj = proj.loader.main_object
main = proj.loader.find_symbol('main').rebased_addr

state = proj.factory.call_state(main)
simgr = proj.factory.simulation_manager(state)

for checkpoint in path:
    simgr.explore(find=checkpoint)
    if len(simgr.found) > 0 and checkpoint != path[-1]:
        simgr = proj.factory.simulation_manager(simgr.found[0])

print(simgr.found[0].posix.dumps(STDIN_FD))
