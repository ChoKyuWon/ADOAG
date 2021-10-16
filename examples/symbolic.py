import angr
import claripy

FLAG_LEN = 15
STDIN_FD = 0

base_addr = 0x100000 # To match addresses to Ghidra

proj = angr.Project("./main.o", main_opts={'base_addr': base_addr}) 

obj = proj.loader.main_object
main = proj.loader.find_symbol('main').rebased_addr

state = proj.factory.call_state(main)

simgr = proj.factory.simulation_manager(state)
find_addr  = proj.loader.find_symbol('target').rebased_addr  # SUCCESS
avoid_addr = proj.loader.find_symbol('origin_flow').rebased_addr # FAILURE
simgr.explore(find=find_addr, avoid=avoid_addr)

if (len(simgr.found) > 0):
    for found in simgr.found:
        # for i in range(15):
        #     c = found.posix.stdin.content[0][0].get_bytes(i, 1)
        #     found.solver.add(c >= ord('!'))
        #     found.solver.add(c <= ord('~'))
        print(found.posix.dumps(STDIN_FD))
