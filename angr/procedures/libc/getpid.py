import angr

class getpid(angr.SimProcedure):
    def run(self):
        rval = self.state.solver.BVS('ptrace', 64, key=('api', 'ptrace'))
        self.state.history.add_simproc_event(self)
        return rval

