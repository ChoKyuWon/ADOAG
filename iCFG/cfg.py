import angr
import networkx
# from angrutils import *
import os

bin_path = os.path.dirname(os.path.abspath(__file__)) + "/../examples/main.o"
proj = angr.Project(bin_path, load_options={'auto_load_libs':False})
p = proj
main = proj.loader.main_object.get_symbol("main")
vuln = proj.loader.main_object.get_symbol("vuln")
target = proj.loader.main_object.get_symbol("target")
start_state = proj.factory.blank_state(addr=main.rebased_addr)
# cfg = proj.analyses.CFGEmulated(fail_fast=True, starts=[main.rebased_addr], initial_state=start_state, enable_symbolic_back_traversal=True)
cfg = proj.analyses.CFGFast(function_starts=[main.rebased_addr])

entry_node = cfg.get_any_node(p.entry)
vuln_node = cfg.get_any_node(vuln.rebased_addr)
target_node = cfg.get_any_node(target.rebased_addr)

# This is our goal!
# paths = networkx.all_simple_paths(cfg.graph, vuln_node, target_node)

paths = networkx.all_simple_paths(cfg.graph, entry_node, vuln_node)
for path in paths:
    for node in path:
        print(hex(node.addr))
    print()

# For print CFG as png
#plot_cfg(cfg, "ais3_cfg", asminst=True, remove_imports=True, remove_path_terminator=True)  