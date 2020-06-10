import claripy
import angr
from angr.sim_options import MEMORY_CHUNK_INDIVIDUAL_READS

import logging
l = logging.getLogger(name=__name__)

class getcwd(angr.SimProcedure):
    #pylint:disable=arguments-differ
    def run(self, buf, size):
        self.state.history.add_simproc_event(self)
        val = self.state.solver.BVS('getcwd', 64, key=('api', 'getcwd'))
        malloc = angr.SIM_PROCEDURES['libc']['malloc']
        addr = self.inline_call(malloc, 100).ret_expr
        self.state.memory.store(addr, val)
        return addr
