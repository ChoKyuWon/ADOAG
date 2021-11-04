import angr
import claripy

STDIN_FD = 0

base_addr = 0x400000 # To match addresses to Ghidra

# iCFG will give the path to target
# vuln, first_gate, second_gate, third_gate, target
path = [0x401310, 0x401448, 0x401430, 0x401450, 0x4011e0]

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
proj = angr.Project("./main.o", main_opts={'base_addr': base_addr}) 

obj = proj.loader.main_object
main = proj.loader.find_symbol('main').rebased_addr
vuln = proj.loader.find_symbol('vuln').rebased_addr

state = proj.factory.call_state(vuln)
simgr = proj.factory.simulation_manager(state)

for checkpoint in path:
    simgr.explore(find=checkpoint)
    if len(simgr.found) > 0 and checkpoint != path[-1]:
        simgr = proj.factory.simulation_manager(simgr.found[0])
        print(hex(checkpoint), "Found! move to next checkpoint.")

print(simgr.found[0].posix.dumps(STDIN_FD))
# b'00000000000004199496000000000000041994720000000000'