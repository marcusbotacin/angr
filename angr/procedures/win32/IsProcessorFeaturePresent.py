import angr

class IsProcessorFeaturePresent(angr.SimProcedure):
    def run(self, feature): # pylint: disable=unused-argument,no-self-use,arguments-differ
        self.state.history.add_simproc_event(self)
        rval = self.state.solver.BVS('feature', 32, key=('api', 'feature'))
        return rval
