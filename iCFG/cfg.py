import angr
from angrutils import *
import os

bin_path = os.path.dirname(os.path.abspath(__file__)) + "/../examples/main.o"
proj = angr.Project(bin_path, load_options={'auto_load_libs':False})
main = proj.loader.main_object.get_symbol("main")
start_state = proj.factory.blank_state(addr=main.rebased_addr)
# cfg = proj.analyses.CFGEmulated(fail_fast=True, starts=[main.rebased_addr], initial_state=start_state, enable_symbolic_back_traversal=True)
cfg = proj.analyses.CFGFast(function_starts=[main.rebased_addr])
plot_cfg(cfg, "ais3_cfg", asminst=True, remove_imports=True, remove_path_terminator=True)  