import angr

class ptrace(angr.SimProcedure):
    def run(self, request, pid, addr, data):
        rval = self.state.solver.BVS('ptrace', 64, key=('api', 'ptrace'))
        self.state.history.add_simproc_event(self)
        return rval

