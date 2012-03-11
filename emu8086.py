import operator
import re
import os
from itertools import chain



def sgn_ext(value):
    return (value & 0xffff) | (0xff00 if (value & 0x0080) else 0)

def to_2compl(value, is_word):
    if value & (1 << (nr_bits(is_word) - 1)) != 0:
        value = abs(abs(value) - (1 << nr_bits(is_word)))
    return value

def from_2compl(value, is_word):
    if value & (1 << (nr_bits(is_word) - 1)):
        return -((~(value - 1)) & ((1 << nr_bits(is_word)) - 1))
    else:
        return value

def nr_bytes(word):
    return 2 if word else 1

def nr_bits(word):
    return nr_bytes(word) * 8

def unpack_w(byte_stream):
    return byte_stream[0] + (byte_stream[1] << 8)

def sub_2compl(a, b, is_word):
    return (a + to_2compl(-b, is_word))

def hexword(value):
    return "0x{0:0>4}".format(hex(value & 0xffff)[2:])

def hexbyte(value):
    return "0x{0:0>2}".format(hex(value & 0x00ff)[2:])



class Ram():

    def __init__(self, size):
        self._m = [0] * size

    def write(self, start, bytes):
        for p in xrange(start, start + len(bytes)):
            self._m[p] = bytes[p]

    def write_b(self, start, byte):
        self._m[start] = byte & 0xff

    def write_w(self, start, word):
        self._m[start] = word & 0x00ff
        self._m[start + 1] = (word & 0xff00) >> 8

    def write_wb(self, start, value, is_word):
        self.write_w(start, value) if is_word else self.write_b(start, value)

    def read(self, start, length):
        return self._m[start:start + length]

    def read_w(self, pos):
        return unpack_w([self.read_b(pos), self.read_b(pos + 1)])

    def read_b(self, pos):
        return self._m[pos]

    def read_wb(self, start, is_word):
        return self.read_w(start) if is_word else self.read_b(start)

    def hexdump(self, start, length):
        return ' '.join(hexbyte(b) for b in self.read(start, length))


class WordStack():

    def __init__(self, size):
        self._m = Ram(size)
        self._sp = 0

    def push(self, value):
        self._sp -= 2
        self._m.write_w(self._sp, value)

    def pop(self):
        self._sp += 2
        return self._m.read_w(self._sp - 2)

    def pos(self):
        return self._sp

    def set_pos(self, sp):
        self._sp = sp

    def hexdump(self, length):
        return self._m.hexdump(self._sp, length)

    def __str__(self):
        return "stack: {0} ...".format(self.hexdump(8))


class Flags(object):

    def __init__(self):
        self._cf = 0
        self._sf = 0
        self._zf = 0

    def cf(self):
        return self._cf

    def zf(self):
        return self._zf

    def sf(self):
        return self._sf

    def zf_from_result(self, result, is_word):
        return 1 if (result & ((1 << nr_bits(is_word)) - 1)) == 0 else 0

    def sf_from_result(self, res, is_word):
        return (res & (1 << (nr_bits(is_word) - 1))) >> (nr_bits(is_word) - 1)

    def set_from_sub_operands(self, op1, op2, is_word):
        result = sub_2compl(op1, op2, is_word)
        self._cf = int(op2 > op1)
        self._zf = self.zf_from_result(result, is_word)
        self._sf = self.sf_from_result(result, is_word)

    def set_from_add_result(self, result, is_word):
        self._cf = int(result > ((1 << nr_bits(is_word)) - 1))
        self._zf = self.zf_from_result(result, is_word)
        self._sf = self.sf_from_result(result, is_word)

    def set_cf(self, cf):
        self._cf = cf

    def __str__(self):
        return "CF:{0} ZF:{1} SF:{2}".format(self.cf(), self.zf(), self.sf())


class Registers(object):

    def __init__(self):
        self._reg_val = [0] * 8
        self._ip = 0

    def sp(self):
        return self.value(4)

    def ip(self):
        return self._ip

    def move_ip(self, offset):
        self._ip += offset

    def set_ip(self, ip):
        self._ip = ip

    def set(self, reg_index, value, is_word):
        if is_word:
            self._reg_val[reg_index] = value & 0xffff
        else:
            self._reg_val[reg_index] = ((self._reg_val[reg_index] & 0xff00) +
                                         (value & 0xff)
                                       )

    def value(self, reg_index):
        return self._reg_val[reg_index]


    def __str__(self):
        def values(is_word):
            return "  ".join(
                           "{0}:{2}{1}".format(
                                Register.name_from_index(index, is_word),
                                hexword(self.value(index)) if is_word else
                                hexbyte(self.value(index)),
                                '' if is_word else '  '
                               )
                           for index in xrange(8)
                        )

        return ("IP:{0}\n{1}\n{2}"
                "".format(hexword(self.ip()), values(True), values(False))
               )


class State(object):
    def __init__(self, ram=Ram(256 * 1024), stack=WordStack(64 * 1024),
                 flags=Flags(), registers=Registers()):
        self._ram = ram
        self._regs = registers
        self._flags = flags
        self._stack = stack
        self._halted = False

    def next_instr_bytes(self):
        return self._ram.read(self.regs().ip(), 6)

    def ram(self):
        return self._ram

    def state(self):
        return self._flags

    def regs(self):
        return self._regs

    def halt(self):
        self._halted = True

    def halted(self):
        return self._halted

    def push_stack(self, value):
        self._stack.set_pos(self.regs().sp())
        self._stack.push(value)
        self.regs().set(4, self._stack.pos(), True)

    def pop_stack(self):
        self._stack.set_pos(self.regs().sp())
        t = self._stack.pop()
        self.regs().set(4, self._stack.pos(), True)
        return t

    def __str__(self):
        return "{0} {1}\n{2}".format(self.state(), self.regs(), self._stack)


class Machine():

    def __init__(self, state):
        self._state = state

    def load(self, program):
        self._state.ram().write(0, list(ord(c) for c in program))
        self._ip = 0

    def state(self):
        return self._state

    def next_instr(self, disasm):
        if self._state.halted():
            return
        instr = disasm.decode_instr(self._state.next_instr_bytes())
        self._state.regs().move_ip(instr.length())
        instr.execute(self._state)


class Register():
    _wname_from_bits = {
            '000':'AX',
            '001':'CX',
            '010':'DX',
            '011':'BX',
            '100':'SP',
            '101':'BP',
            '110':'SI',
            '111':'DI',
        }
    _bname_from_bits = {
            '000':'AL',
            '001':'CL',
            '010':'DL',
            '011':'BL',
            '100':'AH',
            '101':'CH',
            '110':'DH',
            '111':'BH',
        }

    @classmethod
    def index_from_name(cls, name):
        return int(Register.bits_from_name_dict()[name], 2)

    @classmethod
    def bits_from_name_dict(cls):
        return dict((v, u) for u, v in (chain(cls._wname_from_bits.items(),
                                              cls._bname_from_bits.items(),
                                              )
                                        )
                   )

    @classmethod
    def name_from_index(cls, index, is_word):
        return {
                True: cls._wname_from_bits[bin(index)[2:].rjust(3, '0')],
                False: cls._bname_from_bits[bin(index)[2:].rjust(3, '0')],
                }[is_word]

    def __init__(self, bits):
        self._bits = bits

    def index(self):
        return int(self._bits, 2)

    def name(self, is_word):
        return {
                True:self._wname_from_bits[self._bits],
                False:self._bname_from_bits[self._bits],
            }[is_word]


    def __str__(self):
        return self.name(True)



class EffectiveAddress(object):

    def __init__(self, register1, register2, disp):
        self._reg1 = register1
        self._reg2 = register2
        self._disp = disp
        if self._reg1 is None:
            self.__class__ = EffectiveAddressDispOnly
        elif self._reg2 is None:
            self.__class__ = EffectiveAddressDispAndReg1
        else:
            self.__class__ = EffectiveAddressDispAndReg1AndReg2

    def _str_add_disp(self):
        return '' if self._disp == 0 else ' + {0}'.format(hex(self._disp))


class EffectiveAddressDispAndReg1AndReg2(EffectiveAddress):
    def __str__(self):
        return '[({0}) + ({1}){2}]'.format(self._reg1,
                                           self._reg2,
                                           self._str_add_disp()
                                          )

    def address(self, machine_state):
        return (machine_state.regs().value(self._reg1.index()) +
                machine_state.regs().value(self._reg2.index()) +
                self._disp
                )


class EffectiveAddressDispAndReg1(EffectiveAddress):
    def __str__(self):
        return '[({0}){1}]'.format(self._reg1, self._str_add_disp())

    def address(self, machine_state):
        return machine_state.regs().value(self._reg1.index()) + self._disp


class EffectiveAddressDispOnly(EffectiveAddress):
    def __str__(self):
        return '[{0}]'.format(hex(self._disp))

    def address(self, machine_state):
        return self._disp


class Nop(object):

    def __init__(self, instr_length, name):
        self._instr_length = instr_length
        self._name = name

    def length(self):
        return self._instr_length

    def __str__(self):
        return "nop"

    def execute(self, machine_state):
        pass



def add_carry(f):
    """ decorator, adds carry to the result """
    def g(self, machine_state):
        return f(self, machine_state) + machine_state.state().cf()
    return g

def add_borrow(f):
    """ decorator, adds carry (acts as a borrow) to one operand """
    def g(self, machine_state):
        a, b = f(self, machine_state)
        return a, b + machine_state.state().cf()
    return g


def not_affect_carry(f):
    """ decorator, restore carry after an operation """
    def g(self, machine_state):
        cf = machine_state.state().cf()
        result = f(self, machine_state)
        machine_state.state().set_cf(cf)
        return result
    return g

def set_sub_flags(f):
    """ decorator, sets flags after a subtraction """
    def g(self, machine_state):
        a, b = f(self, machine_state)
        machine_state.state().set_from_sub_operands(a, b, self.is_word())
        return a, b
    return g


def decor_sub_2compl(f):
    """ decorator, subtracts two operands using 2-complement """
    def g(self, machine_state):
        a, b = f(self, machine_state)
        return sub_2compl(a, b, self.is_word())
    return g

def set_logical_flags(f):
    """ decorator, sets flags after a logical result """
    def g(self, machine_state):
        result = f(self, machine_state)
        # at least OK when only considering ZF, SF, CF
        machine_state.state().set_from_add_result(result, self.is_word())
        return result
    return g

def set_add_flags(f):
    """ decorator, sets flags after an addition """
    def g(self, machine_state):
        result = f(self, machine_state)
        machine_state.state().set_from_add_result(result, self.is_word())
        return result
    return g


def store_in_regs_op1_op2(f):
    """ decorator, store values a,b in operand 1 & 2 respectively """
    def g(self, machine_state):
        a, b = f(self, machine_state)
        machine_state.regs().set(self.op1(), a, self.is_word())
        machine_state.regs().set(self.op2(), b, self.is_word())
        return a, b
    return g

def store_in_reg_op1(f):
    """ decorator, store result in operand 1 """
    def g(self, machine_state):
        result = f(self, machine_state)
        machine_state.regs().set(self.op1(), result, self.is_word())
        return result
    return g

def store_in_ea_op1(f):
    """ decorator, store result in ram at effective address """
    def g(self, machine_state):
        result = f(self, machine_state)
        machine_state.ram().write_wb(self.op1(machine_state), result,
                                     self.is_word())
        return result
    return g


class BaseOp(Nop):

    def __init__(self, instr_length, name):
        super(BaseOp, self).__init__(instr_length, name)
        if hasattr(self, "exec_{0}".format(name)):
            self.execute = getattr(self, "exec_{0}".format(name))

    def __str__(self):
        return "{0}".format(self._name)


    def op_values(self, machine_state):
        raise NotImplementedError()


    @set_sub_flags
    def exec_cmp(self, machine_state):
        return self.op_values(machine_state)

    @decor_sub_2compl
    @set_sub_flags
    def exec_sub(self, machine_state):
        return self.op_values(machine_state)

    @set_add_flags
    def exec_add(self, machine_state):
        return operator.add(*self.op_values(machine_state))

    @set_add_flags
    @add_carry
    def exec_adc(self, machine_state):
        return operator.add(*self.op_values(machine_state))

    @set_logical_flags
    def exec_and(self, machine_state):
        return operator.and_(*self.op_values(machine_state))

    @set_logical_flags
    def exec_xor(self, machine_state):
        return operator.xor(*self.op_values(machine_state))

    @set_logical_flags
    def exec_or(self, machine_state):
        return operator.or_(*self.op_values(machine_state))

    @decor_sub_2compl
    @set_sub_flags
    @add_borrow
    def exec_sbb(self, machine_state):
        return self.op_values(machine_state)

    @decor_sub_2compl
    @not_affect_carry
    @set_sub_flags
    def exec_dec(self, machine_state):
        return self.op_values(machine_state), 1

    @not_affect_carry
    @set_add_flags
    def exec_inc(self, machine_state):
        return operator.add(self.op_values(machine_state), 1)



class Op_Reg_Immediate(BaseOp):

    def __init__(self, instr_length, name, register, immediate, is_word):
        super(Op_Reg_Immediate, self).__init__(instr_length, name)
        self._im = immediate
        self._reg = register
        self._is_word = is_word

    def is_word(self):
        return self._is_word

    def op1(self):
        return self._reg.index()

    def op_values(self, machine_state):
        return machine_state.regs().value(self._reg.index()), self._im

    def __str__(self):
        return "{0} {1}, {2}".format(self._name,
                                     self._reg.name(self._is_word),
                                     hex(self._im)
                                     )

    @store_in_reg_op1
    def exec_sub(self, machine_state):
        return super(Op_Reg_Immediate, self).exec_sub(machine_state)

    @store_in_reg_op1
    def exec_add(self, machine_state):
        return super(Op_Reg_Immediate, self).exec_add(machine_state)

    @store_in_reg_op1
    def exec_adc(self, machine_state):
        return super(Op_Reg_Immediate, self).exec_adc(machine_state)

    @store_in_reg_op1
    def exec_and(self, machine_state):
        return super(Op_Reg_Immediate, self).exec_and(machine_state)

    @store_in_reg_op1
    def exec_mov(self, machine_state):
        return self._im


class Op_Reg_Reg(BaseOp):

    def __init__(self, instr_length, name, register1, register2, is_word):
        super(Op_Reg_Reg, self).__init__(instr_length, name)
        self._reg1 = register1
        self._reg2 = register2
        self._is_word = is_word

    def is_word(self):
        return self._is_word

    def op1(self):
        return self._reg1.index()

    def op2(self):
        return self._reg2.index()

    def op_values(self, machine_state):
        return (machine_state.regs().value(self.op1()),
                machine_state.regs().value(self.op2())
               )

    @store_in_reg_op1
    def exec_xor(self, machine_state):
        return super(Op_Reg_Reg, self).exec_xor(machine_state)

    @store_in_reg_op1
    def exec_or(self, machine_state):
        return super(Op_Reg_Reg, self).exec_or(machine_state)

    @store_in_reg_op1
    def exec_and(self, machine_state):
        return super(Op_Reg_Reg, self).exec_and(machine_state)

    @store_in_reg_op1
    def exec_add(self, machine_state):
        return super(Op_Reg_Reg, self).exec_add(machine_state)

    @store_in_reg_op1
    def exec_sbb(self, machine_state):
        return super(Op_Reg_Reg, self).exec_sbb(machine_state)

    @store_in_regs_op1_op2
    def exec_xchg(self, machine_state):
        return reversed(self.op_values(machine_state))

    @store_in_reg_op1
    def exec_mov(self, machine_state):
        return machine_state.regs().value(self._reg2.index())

    def __str__(self):
        if self._name == 'xchg' and self._reg1.index() == self._reg2.index():
            return "nop"
        return "{0} {1}, {2}".format(self._name,
                                     self._reg1.name(self._is_word),
                                     self._reg2.name(self._is_word),
                                     )


class Op_Ea_Immediate(BaseOp):

    def __init__(self, instr_length, name, ea, immediate, is_word):
        super(Op_Ea_Immediate, self).__init__(instr_length, name)
        self._ea = ea
        self._im = immediate
        self._word = is_word

    def is_word(self):
        return self._word

    def op1(self, machine_state):
        return self._ea.address(machine_state)

    def op_values(self, machine_state):
        return (
            machine_state.ram().read_wb(self.op1(machine_state), self._word),
            self._im,
           )

    @store_in_ea_op1
    def exec_add(self, machine_state):
        return super(Op_Ea_Immediate, self).exec_add(machine_state)

    @store_in_ea_op1
    def exec_or(self, machine_state):
        return super(Op_Ea_Immediate, self).exec_or(machine_state)

    @store_in_ea_op1
    def exec_mov(self, machine_state):
        return self._im

    def __str__(self):
        return "{0} {3} {1}, {2}".format(self._name,
                                           self._ea,
                                           hex(self._im),
                                           'word' if self._word else 'byte')



class Op_Ea_Reg(BaseOp):

    def __init__(self, instr_length, name, reg, ea, is_word):
        super(Op_Ea_Reg, self).__init__(instr_length, name)
        self._ea = ea
        self._name = name
        self._reg = reg
        self._word = is_word

    def is_word(self):
        return self._word

    def op1(self, machine_state):
        return self._ea.address(machine_state)

    def op_values(self, machine_state):
        return (
            machine_state.ram().read_wb(self.op1(machine_state), self._word),
            machine_state.regs().value(self._reg.index())
           )

    @store_in_ea_op1
    def exec_mov(self, machine_state):
        return machine_state.regs().value(self._reg.index())

    @store_in_ea_op1
    def exec_and(self, machine_state):
        return super(Op_Ea_Reg, self).exec_and(machine_state)

    @store_in_ea_op1
    def exec_add(self, machine_state):
        return super(Op_Ea_Reg, self).exec_add(machine_state)

    @store_in_ea_op1
    def exec_sub(self, machine_state):
        return super(Op_Ea_Reg, self).exec_sub(machine_state)

    def __str__(self):
        return "{0} {3} {1}, {2}".format(self._name,
                                           self._ea,
                                           self._reg.name(self._word),
                                           'word' if self._word else 'byte')


class Op_Reg_Ea(BaseOp):

    def __init__(self, instr_length, name, reg, ea, is_word):
        super(Op_Reg_Ea, self).__init__(instr_length, name)
        self._ea = ea
        self._reg = reg
        self._word = is_word

    def is_word(self):
        return self._word

    def op1(self):
        return self._reg.index()

    def op2(self, machine_state):
        return self._ea.address(machine_state)

    @store_in_reg_op1
    def exec_mov(self, machine_state):
        return machine_state.ram().read_wb(self.op2(machine_state), self._word)

    def __str__(self):
        return "{0} {3} {2}, {1}".format(self._name,
                                           self._ea,
                                           self._reg.name(self._word),
                                           'word' if self._word else 'byte')


class Op_Reg(BaseOp):

    def __init__(self, instr_length, name, reg, is_word):
        super(Op_Reg, self).__init__(instr_length, name)
        self._reg = reg
        self._word = is_word

    def is_word(self):
        return self._word

    def op1(self):
        return self._reg.index()

    def op_values(self, machine_state):
        return machine_state.regs().value(self._reg.index())

    @store_in_reg_op1
    def exec_dec(self, machine_state):
        return super(Op_Reg, self).exec_dec(machine_state)

    @store_in_reg_op1
    def exec_inc(self, machine_state):
        return super(Op_Reg, self).exec_inc(machine_state)

    def exec_push(self, machine_state):
        machine_state.push_stack(self.op_values(machine_state))

    @store_in_reg_op1
    def exec_pop(self, machine_state):
        return machine_state.pop_stack()

    def __str__(self):
        return "{0} {1}".format(self._name,
                                self._reg.name(self._word))


class Op_Disp(BaseOp):

    def exec_jz(self, machine_state):
        if machine_state.state().zf():
            machine_state.regs().move_ip(self._addr)

    def exec_jc(self, machine_state):
        if machine_state.state().cf():
            machine_state.regs().move_ip(self._addr)

    def exec_jnz(self, machine_state):
        if not machine_state.state().zf():
            machine_state.regs().move_ip(self._addr)

    def exec_jnbe(self, machine_state):
        if not machine_state.state().zf() and not machine_state.state().cf():
            machine_state.regs().move_ip(self._addr)

    def exec_jns(self, machine_state):
        if not machine_state.state().sf():
            machine_state.regs().move_ip(self._addr)

    def exec_jbe(self, machine_state):
        if machine_state.state().cf() or machine_state.state().zf():
            machine_state.regs().move_ip(self._addr)

    def exec_jmp(self, machine_state):
        machine_state.regs().move_ip(self._addr)


    def exec_call(self, machine_state):
        machine_state.push_stack(machine_state.regs().ip())
        machine_state.regs().move_ip(self._addr)


    def __init__(self, instr_length, name, address):
        super(Op_Disp, self).__init__(instr_length, name)
        self._is_word = True if instr_length == 3 else False
        self._addr = from_2compl(address, self._is_word)

    def rel_addr(self):
        return self._addr

    def __str__(self):
        return "{0} {1}".format(self._name, hex(self._addr))


class Op_NoArgs(BaseOp):

    def exec_hlt(self, machine_state):
        machine_state.halt()

    def exec_ret(self, machine_state):
        machine_state.regs().set_ip(machine_state.pop_stack())

    def exec_stc(self, machine_state):
        machine_state.state().set_cf(1)

    def __init__(self, instr_length, name):
        super(Op_NoArgs, self).__init__(instr_length, name)


class Unknown_Op(BaseOp):
    def __init__(self):
        super(Unknown_Op, self).__init__(1, 'UNKNOWN')


class Unpacker():

    def __init__(self, bitstr, byte_offset=0):
        self._bstr = bitstr[byte_offset * 8:]

    def dispatch(self, mod, rm):
        if mod == '00' and rm != '110':
            return 0
        elif mod == '00' and rm == '110':
            return self.unpack_w()
        else:
            return {
                '01':self.unpack_se_b(),
                '10':self.unpack_w()
               }[mod]

    def unpack_w(self, start=0):
        return unpack_w([self._peek(start), self._peek(start + 1)])

    def unpack_b(self, start=0):
        return self._peek(start)

    def unpack_se_b(self, start=0):
        return sgn_ext(self.unpack_b(start))

    def unpack(self, start, is_word, do_sgn_ext=False):
        if is_word:
            return self.unpack_w(start)
        elif do_sgn_ext:
            return self.unpack_se_b(start)
        else:
            return self.unpack_b(start)

    def _peek(self, offset):
        return int(self._bstr[offset * 8:(offset + 1) * 8], 2)


class DisAsm():

    def __init__(self):
        self._dispatch_from_re = dict(
                    (
                     re.compile(
                                p.format(
                                         w="(?P<w>[01]{1})",
                                         sw="(?P<sw>[01]{2})",
                                         dw="(?P<dw>[01]{2})",
                                         mod="(?P<mod>[01]{2})",
                                         reg="(?P<reg>[01]{3})",
                                         rm="(?P<rm>[01]{3})",
                                         disp="(?P<disp>[01]{8})"
                                )
                            ),
                     f
                    )
                    for p, f in self.instruction_dict().items()
               )

    def instruction_dict(self):


        def create_ea(mod, rm, dispatch):

            def reg_by_name(name):
                return Register(Register.bits_from_name_dict()[name])

            def reg1_reg2():
                return {
                        '000': (reg_by_name('BX'), reg_by_name('SI')),
                        '001': (reg_by_name('BX'), reg_by_name('DI')),
                        '010': (reg_by_name('BP'), reg_by_name('SI')),
                        '011': (reg_by_name('BP'), reg_by_name('DI')),
                        '100': (reg_by_name('SI'), None),
                        '101': (reg_by_name('DI'), None),
                        '110': (reg_by_name('BP'), None),
                        '111': (reg_by_name('BX'), None),
                    }[rm]

            if mod == '00' and rm == '110':
                return EffectiveAddress(None, None, dispatch)
            else:
                return EffectiveAddress(reg1_reg2()[0],
                                        reg1_reg2()[1],
                                        dispatch
                                       )

        def _nr_ea_bytes(mod, rm):
            return {
                     '00': 2 if rm == '110' else 0,
                     '01': 1,
                     '10': 2,
                     '11': 0,
             }[mod]

        def _data_byte_offset(mod, rm):
            return _nr_ea_bytes(mod, rm)


        class OpArgs():
            def __init__(self, match, start, end=None):
                self.do_sgn_ext = False
                self.nr_dbytes = 0
                self.mod = None
                self.rm = None
                for g in ['w', 'sw', 'dw', 'reg', 'disp', 'mod', 'rm']:
                    if g in match.groupdict():
                        setattr(self, g, match.group(g))
                self.unpacker = Unpacker(
                                    match.string[start * 8:(start + 6) * 8]
                                )
                if 'w' in match.groupdict():
                    self.is_word = match.group('w') == '1'
                    self.nr_dbytes = nr_bytes(match.group('w') == '1')
                elif 'sw' in match.groupdict():
                    self.is_word = match.group('sw')[1] == '1'
                    self.do_sgn_ext = match.group('sw')[0] == '1'
                    self.nr_dbytes = nr_bytes(match.group('sw') == '01')
                elif 'dw' in match.groupdict():
                    self.is_word = match.group('dw')[1] == '1'
                    self.to_reg = match.group('dw')[0] == '1'
                    self.nr_dbytes = nr_bytes(match.group('dw')[1] == '1')
                if end is not None:
                    self.is_word = end - start == 2

            def nr_totalbytes(self):
                try:
                    return self.nr_eabytes() + self.nr_databytes()
                except:
                    pass
                return self.nr_databytes()

            def nr_eabytes(self):
                return _nr_ea_bytes(self.mod, self.rm)

            def nr_databytes(self):
                return self.nr_dbytes # nr_bytes(self.is_word)


            def unpack_im(self):
                return self.unpacker.unpack(
                            _data_byte_offset(self.mod, self.rm),
                                      self.nr_dbytes == 2, self.do_sgn_ext)

            def unpack(self):
                return self.unpacker.unpack(0, self.is_word)


        def _mnemonic_i_rm(instr_length, name, is_word, mod, i, rm, unpacker):
            if mod == '11':
                return Op_Reg_Immediate(instr_length,
                                        name,
                                        Register(rm),
                                        i,
                                        is_word
                                       )
            else:
                return Op_Ea_Immediate(
                               instr_length,
                               name,
                               create_ea(mod, rm, unpacker.dispatch(mod, rm)),
                               i,
                               is_word
                            )

        def _sw_mod_rm__op_i_rm(name, sw, mod, rm, unpacker):
            return _mnemonic_i_rm(
                      2 + _nr_ea_bytes(mod, rm) + nr_bytes(sw == '01'),
                      name,
                      sw[1] == '1',
                      mod,
                      unpacker.unpack(_data_byte_offset(mod, rm),
                                      sw == '01', sw[0] == '1'),
                      rm,
                      unpacker
                     )


        def op_w_acc(name, op_args):
            return Op_Reg_Immediate(
                    1 + nr_bytes(op_args.is_word),
                    name,
                    Register('000'),
                    op_args.unpack(),
                    op_args.is_word
                   )

        def op_w_mod_rm_im(name, op_args):
            return _mnemonic_i_rm(
                      2 + op_args.nr_totalbytes(),
                      name,
                      op_args.is_word,
                      op_args.mod,
                      op_args.unpack_im(),
                      op_args.rm,
                      op_args.unpacker
                     )

        def op_sw_mod_rm(name, op_args):
            return op_sw_mod_rm_im(name, op_args)

        def op_sw_mod_rm_im(name, op_args):
            return _mnemonic_i_rm(
                      2 + op_args.nr_totalbytes(),
                      name,
                      op_args.is_word,
                      op_args.mod,
                      op_args.unpack_im(),
                      op_args.rm,
                      op_args.unpacker
                     )

        def op_w_mod_rm(name, op_args):
            if op_args.mod == '11':
                return Op_Reg(2, name, Register(op_args.rm), op_args.is_word)
            else:
                raise Exception("Not implemented")

        def op_disp_byte(name, op_args):
            return Op_Disp(2, name, op_args.unpack())

        def op_disp_word(name, op_args):
            return Op_Disp(3, name, op_args.unpack())

        def op_no_args(name):
            return Op_NoArgs(1, name)

        def op_reg(name, m):
            return Op_Reg(1, name, Register(m.reg), is_word=True)

        def op_reg_acc(name, m):
            return Op_Reg_Reg(1, name, Register('000'), Register(m.reg),
                              is_word=True
                             )



        def _mnemonic_rm_r(instr_length, name, to_reg, is_word, mod, rm, r,
                           unpacker):
            if mod == '11':
                return Op_Reg_Reg(instr_length,
                                  name,
                                  Register(rm),
                                  Register(r),
                                  is_word
                                )
            else:
                if to_reg:
                    return Op_Reg_Ea(instr_length,
                             name,
                             Register(r),
                             create_ea(mod, rm, unpacker.dispatch(mod, rm)),
                             is_word
                            )
                else:
                    return Op_Ea_Reg(instr_length,
                             name,
                             Register(r),
                             create_ea(mod, rm, unpacker.dispatch(mod, rm)),
                             is_word
                            )

        def op_dw_mod_reg_rm(name, op_args):
            return _mnemonic_rm_r(
                           2 + _nr_ea_bytes(op_args.mod, op_args.rm),
                           name,
                           op_args.to_reg,
                           op_args.is_word,
                           op_args.mod,
                           op_args.rm,
                           op_args.reg,
                           op_args.unpacker
                          )

        def op_w_mod_reg_rm(name, m):
            return _mnemonic_rm_r(2,
                                  name,
                                  to_reg=True,
                                  is_word=m.is_word,
                                  mod=m.mod,
                                  rm=m.rm,
                                  r=m.reg,
                                  unpacker=m.unpacker
                                 )

        def op_w_reg_im(name, m):
            return _mnemonic_i_rm(1 + m.nr_databytes(),
                                  name,
                                  m.is_word,
                                  '11',
                                  m.unpack(),
                                  m.reg,
                                  m.unpacker
                                 )


        return {
            "100000{sw}{mod}111{rm}":
                                lambda m: op_sw_mod_rm("cmp", OpArgs(m, 2)),
            "01110100{disp}": lambda m: op_disp_byte('jz', OpArgs(m, 1, 2)),
            "01110101{disp}": lambda m: op_disp_byte('jnz', OpArgs(m, 1, 2)),
            "11110100": lambda m: op_no_args("hlt"),
            "1011{w}{reg}": lambda m: op_w_reg_im("mov", OpArgs(m, 1)),
            "01001{reg}": lambda m: op_reg("dec", OpArgs(m, 1)),
            "11101000{reg}": lambda m: op_disp_word("call", OpArgs(m, 1, 3)),
            "01000{reg}": lambda m: op_reg("inc", OpArgs(m, 1)),
            "001100{dw}{mod}{reg}{rm}":
                            lambda m: op_dw_mod_reg_rm("xor", OpArgs(m, 2)),
            "000010{dw}{mod}{reg}{rm}":
                            lambda m: op_dw_mod_reg_rm("or", OpArgs(m, 2)),
            "01110010{disp}": lambda m: op_disp_byte('jc', OpArgs(m, 1, 2)),
            "001110{dw}{mod}{reg}{rm}":
                            lambda m: op_dw_mod_reg_rm("cmp", OpArgs(m, 2)),
            "01110110{disp}": lambda m: op_disp_byte('jbe', OpArgs(m, 1, 2)),
            "000000{dw}{mod}{reg}{rm}":
                            lambda m: op_dw_mod_reg_rm("add", OpArgs(m, 2)),
            "100000{sw}{mod}010{rm}":
                            lambda m: op_sw_mod_rm("adc", OpArgs(m, 2)),
            "01111001{disp}": lambda m: op_disp_byte('jns', OpArgs(m, 1, 2)),
            "01010{reg}": lambda m: op_reg("push", OpArgs(m, 1)),
            "100000{sw}{mod}100{rm}":
# NOTE!! s always 0 according to 
# http://datasheets.chipdb.org/Intel/x86/808x/datashts/8086/231455-006.pdf 
# but not in the codegolf code?
                            lambda m: op_sw_mod_rm("and", OpArgs(m, 2)),
            "01011{reg}": lambda m: op_reg("pop", OpArgs(m, 1)),
            "11111001": lambda m: op_no_args("stc"),
            "000110{dw}{mod}{reg}{rm}":
                            lambda m: op_dw_mod_reg_rm("sbb", OpArgs(m, 2)),
            "11000011": lambda m: op_no_args("ret"),
            "11101011": lambda m: op_disp_byte('jmp', OpArgs(m, 1, 2)),
            "1111111{w}{mod}000{rm}":
                            lambda m: op_w_mod_rm("inc", OpArgs(m, 2)),
            "0011110{w}": lambda m: op_w_acc("cmp", OpArgs(m, 1)),
            "1100011{w}{mod}000{rm}":
                            lambda m: op_w_mod_rm_im("mov", OpArgs(m, 2)),
            "1111111{w}{mod}001{rm}":
                            lambda m: op_w_mod_rm("dec", OpArgs(m, 2)),
            "100000{sw}{mod}000{rm}":
                            lambda m: op_sw_mod_rm("add", OpArgs(m, 2)),
            "10010{reg}": lambda m: op_reg_acc("xchg", OpArgs(m, 1)),
            "100010{dw}{mod}{reg}{rm}":
                            lambda m: op_dw_mod_reg_rm("mov", OpArgs(m, 2)),
            "1000000{w}{mod}001{rm}":
                            lambda m: op_w_mod_rm_im("or", OpArgs(m, 2)),
            "1000011{w}{mod}{reg}{rm}": lambda m:
                            op_w_mod_reg_rm("xchg", OpArgs(m, 2)),
            "001000{dw}{mod}{reg}{rm}":
                            lambda m: op_dw_mod_reg_rm("and", OpArgs(m, 2)),
            "100000{sw}{mod}101{rm}":
                            lambda m: op_sw_mod_rm_im("sub", OpArgs(m, 2)),
            "001010{dw}{mod}{reg}{rm}":
                            lambda m: op_dw_mod_reg_rm("sub", OpArgs(m, 2)),
            "01110111{disp}": lambda m: op_disp_byte('jnbe', OpArgs(m, 1, 2)),
            "0000010{w}": lambda m: op_w_acc("add", OpArgs(m, 1)),
        }


    def decode_instr(self, bytes):
        def instr_bitstr():
            return ''.join(bin(b)[2:].rjust(8, '0') for b in bytes[:6])
        for p, dispatcher in self._dispatch_from_re.iteritems():
            if p.match(instr_bitstr()):
                return dispatcher(p.match(instr_bitstr()))
        return Unknown_Op()

    def instructions(self, program_bytes):
        pc = 0
        while pc < len(program_bytes):
            instr = self.decode_instr(program_bytes[pc:pc + 6])
            pc += instr.length()
            yield instr


def main(program_path, vram_ptr, rows, cols):
    with open(program_path, 'rb') as program_file:
        machine = Machine(State())
        machine.state().regs().set(Register.index_from_name('SP'),
                                      0x100, True)
        machine.load(program_file.read())

        def run(console, machine):
            while True:
                machine.next_instr(DisAsm())
                console.refresh(machine.state().ram().read(vram_ptr,
                                                           rows * cols))

        import console
        console.run(run, machine, rows, cols)


if __name__ == '__main__':
    main(os.path.join(os.path.dirname(__file__), 'codegolf'),
         vram_ptr=int('0x8000', 16),
         rows=25,
         cols=80,
        )
