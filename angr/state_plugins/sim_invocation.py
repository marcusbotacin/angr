import angr
import claripy
import itertools
event_id_count = itertools.count()

class SimInvocation(object):
    def __init__(self, simproc, caller=None, depth=0):
        self.id = next(event_id_count)
        self.simproc = simproc
        self.name = self.__get_name()
        self.prototype = self.__get_prototype()    

    def set_state(self, state):
        self.simproc.state = state

    def __get_name(self):
        # Ugly Tricks
        iso = "__isoc99_"
        name = self.simproc.display_name
        if iso in name:
            return name.split(iso)[-1]
        return name

    def __get_prototype(self):
        lib_name = self.simproc.library_name
        try:
            return angr.procedures.definitions.SIM_LIBRARIES[lib_name].prototypes[self.name]
        except:
            return None

    def __eq__(self, other):
        return self.name == other.name

    def __ne__(self, other):
        return not self.name == other.name

    def __repr__(self):
        return "<SimInvocation %d (%s)>" % (self.id, self.name)

    def __concretize_arg(self, state, arg, bv):
        simtype = angr.sim_type.parse_type(arg.c_repr()).with_arch(self.simproc.state.arch)
        if type(simtype) is angr.sim_type.SimTypeInt or type(simtype) is angr.sim_type.SimTypeLong:
            return simtype.str_from_bv(state=state,bv=bv)
        if type(simtype) is angr.sim_type.SimTypePointer and type(simtype.pts_to) is angr.sim_type.SimTypeChar:
            return angr.sim_type.SimTypeString().str_from_bv(state=state, addr=bv.args[0])
        # Unimplemented Types
        return "??"

    def str_from_ret(self):
        bv = self.simproc.state.memory.load(self.simproc.ret_expr)
        # Ugly tricky, need to fix this
        return str(angr.sim_type.SimTypeString().str_from_bv(state=self.simproc.state, addr=self.simproc.ret_expr).split(bytes.fromhex('00'))[0].decode('utf8'))

    def __format_ret(self, state=None, concretize=False):
        if self.simproc.returns is False:
            return "void"
        try:
            ret = self.simproc.ret_expr
        except:
            return "??"
        if type(ret) is angr.state_plugins.sim_action_object.SimActionObject:
            ret = ret.ast
        if type(ret) is claripy.ast.bv.BV: 
            if ret.symbolic:
                if concretize:
                    _state = self.simproc.state if state is None else state
                    if self.prototype is not None:
                        return self.__concretize_arg(_state, self.prototype.returnty, ret)
                return ret.args[0]
            else:
                return "0x%x" % ret.args[0]

        if type(ret) is int:
            return "0x%x" % ret
        return "TBD"

    def __get_val_from_symbol(state, symbol):
        if type(symbol) is angr.state_plugins.sim_action_object.SimActionObject:
            return symbol.ast.args[0]
        if type(symbol) is claripy.ast.bv.BV:
            return symbol.args[0]
        if type(symbol) is angr.sim_type.SimTypePointer:
            return symbol.ast.args[0]

    def __format_args(self, state=None, concretize=False):
        _state = self.simproc.state if state is None else state
        fmt_args = []
        if concretize and self.prototype is not None:
            for idx, arg in enumerate(self.prototype.args):
                try:
                    _str = self.__concretize_arg(_state, arg, self.simproc.arguments[idx])
                    if type(_str) is bytes:
                        fmt = _str[:_str.find(bytes.fromhex('00'))]
                        fmt = "\"%s\"" % fmt.decode('utf-8','ignore')
                    else:
                        fmt = _str
                except:
                    try:
                        fmt = "0x%x" % self.__get_val_from_symbol(arg)
                    except:
                        fmt = "??"
                fmt_args.append(fmt)

        else:
            for arg in self.simproc.arguments:
                try:
                    fmt_args.append("0x%x" % self.__get_val_from_symbol(arg))
                except:
                    fmt_args.append("??")
        return ",".join(fmt_args)

    def get_ret(self, state=None):
        return int(self.__format_ret(concretize=True,state=state),16)

    def pp_str(self, state=None, concretize=False):
        ret = self.__format_ret(state, concretize)
        args = self.__format_args(state, concretize)
        SIrepr = "<%s> = %s (%s)" % (ret, self.name, args)
        return SIrepr

    def pp(self, state=None, concretize=False):
        print(self.pp_str(state, concretize))
