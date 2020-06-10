import claripy
import angr
from angr.sim_options import MEMORY_CHUNK_INDIVIDUAL_READS

import logging
l = logging.getLogger(name=__name__)

class time(angr.SimProcedure):
    #pylint:disable=arguments-differ
    def run(self, tloc):
        self.state.history.add_simproc_event(self)
        rval = self.state.solver.BVS('time', 64, key=('api', 'time'))
        self.state.history.add_simproc_event(self)
        return rval
