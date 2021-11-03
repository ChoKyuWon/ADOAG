import os
import sys
import angr
import angr.analyses.cfg.indirect_jump_resolvers.resolver as resolver
from angrutils import *
import networkx
from find_indirects import Indirects
from jump_resolver import IFCCReslover

def main():
    binary_path = os.path.dirname(os.path.abspath(__file__)) + "/../examples/main.o"
    if len(sys.argv) > 1:
        binary_path = sys.argv[1]
    bin = open(binary_path, 'rb')
    
    indirects = Indirects(bin)
    indirects.indirect_list()
    proj = angr.Project(binary_path, load_options={'auto_load_libs':False})

    main = proj.loader.main_object.get_symbol("main")
    vuln = proj.loader.main_object.get_symbol("vuln")
    target = proj.loader.main_object.get_symbol("target")
    
    indirect_reslover = IFCCReslover(proj, indirects.indirects)
    cfg = proj.analyses.CFGFast(
        function_starts=[main.rebased_addr], 
        indirect_jump_resolvers = tuple(
		angr.analyses.cfg.indirect_jump_resolvers.default_resolvers.default_indirect_jump_resolvers(
			proj.loader.main_object,
			proj
		)) + (indirect_reslover,)
    )

    src_node = cfg.model.get_any_node(vuln.rebased_addr)
    dst_node = cfg.model.get_any_node(target.rebased_addr)
    # entry_node = cfg.get_any_node(proj.entry)

    # This is our goal!
    paths = networkx.all_simple_paths(cfg.graph, src_node, dst_node)

    # paths = networkx.all_simple_paths(cfg.graph, entry_node, vuln_node)
    for path in paths:
        for node in path:
            print(hex(node.addr))
        print()

    # For print CFG as png
    # plot_cfg(cfg, "ais3_cfg", asminst=True, remove_imports=True, remove_path_terminator=True)  
    

if __name__ == "__main__":
    main()