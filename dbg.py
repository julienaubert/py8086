import os
import sys
import emu8086


class RunToAnyBreakPoint(object):

    def __init__(self, breaks, state_after):
        self._breaks = breaks
        self._breaked = False
        self._next_state = state_after

    def next_state(self):
        return self if not self._breaked else self._next_state

    def update(self, machine):
        if self._breaked:
            return
        if machine.state().regs().ip() not in self._breaks:
            machine.next_instr(emu8086.DisAsm())
        else:
            self._breaked = True


def see_ram(ram, address, length=12):
    return "M {0}: {1} ...".format(hex(address), ram.hexdump(address, length))


class InteractiveDebug(object):

    def __init__(self):
        self._run_to_break = False
        self._breaks = []
        self._next_state = self
        self._done = False

    def next_state(self):
        return self._next_state

    def _run_to_next_state(self):
        if len(self._breaks) != 0:
            self._next_state = RunToAnyBreakPoint(self._breaks, self)
        else:
            self._next_state = self


    def update(self, machine):
        print machine.state()
        if machine.state().halted():
            return
        print emu8086.DisAsm().decode_instr(machine.state().next_instr_bytes())
        machine.next_instr(emu8086.DisAsm())
        print ("[Enter]:step [R]:run [B 0xadr]:add break "
                   "[M 0xadr]:see RAM [Q]:quit")
        while True:
            v = raw_input()
            if len(v) == 0:
                return
            elif v[0] == 'M':
                print see_ram(machine.state().ram(), int(v[1:], 16))
            elif v[0] == 'B':
                self._breaks.append(int(v[1:], 16))
            elif v[0] == 'R':
                self._run_to_next_state()
                return
            elif v[0] == 'Q':
                self._next_state = None
                return


class PrintStateAndRun(object):

    def __init__(self):
        self._next = self

    def next_state(self):
        return self._next

    def update(self, machine):
        print
        print machine.state()
        print emu8086.DisAsm().decode_instr(machine.state().next_instr_bytes())
        machine.next_instr(emu8086.DisAsm())
        if machine.state().halted():
            self._next = None


class Runner(object):

    def __init__(self, initial):
        self._runner = initial
        self._done = False

    def update(self, machine):
        self._runner = self._runner.next_state()
        if self._runner is None:
            return
        self._runner.update(machine)

    def done(self):
        return self._runner is None


def runner_from_opt(interactive):
    if interactive:
        return Runner(InteractiveDebug())
    else:
        return Runner(PrintStateAndRun())

def main(program_path, runner):
    with open(program_path, 'rb') as program_file:
        machine = emu8086.Machine(emu8086.State())
        machine.state().regs().set(emu8086.Register.index_from_name('SP'),
                                      0x100, True)
        machine.load(program_file.read())
        while not runner.done():
            runner.update(machine)

if __name__ == '__main__':
    main(os.path.join(os.path.dirname(__file__), 'codegolf'),
         runner_from_opt(len(sys.argv) == 1),
        )
