import angr

class GetCurrentProcessId(angr.SimProcedure):
    def run(self):
        self.state.history.add_simproc_event(self)
        rval = self.state.solver.BVS('pid', 32, key=('api', 'pid'))
        return rval
