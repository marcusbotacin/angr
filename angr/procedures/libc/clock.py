import angr

class clock(angr.SimProcedure):
    def run(self):
        rval = self.state.solver.BVS('clock', 64, key=('api', 'clock'))
        self.state.history.add_simproc_event(self)
        return rval

