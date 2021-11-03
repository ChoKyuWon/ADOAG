import angr.analyses.cfg.indirect_jump_resolvers.resolver as resolver
from angrutils import *

class IFCCReslover(resolver.IndirectJumpResolver):
    def __init__(self, project, IFCC_table, timeless=False, base_state=None):
        self.IFCC_table = IFCC_table
        super().__init__(project, timeless, base_state)
    
    def filter(self, cfg, addr, func_addr, block, jumpkind):
        return block.instruction_addrs[-1] in self.IFCC_table.keys()
    
    def resolve(self, cfg, addr, func_addr, block, jumpkind):
        return True, tuple(self.IFCC_table[block.instruction_addrs[-1]])