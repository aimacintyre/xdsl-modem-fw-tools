#!/usr/bin/env python3

# SPDX-License-Identifier: GPL-2.0-or-later

# Copyright (C) 2022 Andrew I MacIntyre <andymac@pcug.org.au>

# Draytek firmware component extractor and decompressor
#
# This script implements the decompression routine described in
# https://github.com/yath/vigor165/blob/main/decompress/decompress.S
# as part of the process of extracting the executable firmware image
# (and the web interface file system) from Draytek modem/router firmware
# files.
#
# The Draytek firmware file structure was understood with information
# from the Draytools project
# (https://github.com/ammonium/draytools/ - now removed; I used the
#  fork at https://github.com/krolinventions/draytools/).
#
# Rather than try and translate MIPS disassembly to Python, this
# script implements a rudimentary MIPS assembly interpreter and
# executes a slightly simplified version of the above assembly code
# sequence for each chunk presented for decompression.
#
# The MIPS assembly interpreter implementation includes support for only
# those instructions required for the decompressor code to execute
# correctly and doesn't strictly observe a number of aspects of standard
# MIPS assembly code, including:
# - the code and data address spaces are separate
# - alignment isn't checked
# - some complex pseudo-opcodes are implemented as single instructions
#
# This script has been tested with both Python 2.7 amd Python 3.8.  The
# script is self contained and has no dependencies on external Python
# libraries.  Operation has been tested only on Linux but I believe it
# should run on Windows too as binary mode file I/O has been explicitly
# stated.  On an I5-3470 system approximately 4MB of compressed data
# can be decompressed per minute.

import os
import sys
import struct



### MIPS simulated CPU - constants

# register naming - source seems to use O32 convention
REG_ZERO = 0
REG_AT = 1
REG_V0 = 2
REG_V1 = 3
REG_A0 = 4
REG_A1 = 5
REG_A2 = 6
REG_A3 = 7
REG_T0 = 8
REG_T1 = 9
REG_T2 = 10
REG_T3 = 11
REG_T4 = 12
REG_T5 = 13
REG_T6 = 14
REG_T7 = 15
REG_S0 = 16
REG_S1 = 17
REG_S2 = 18
REG_S3 = 19
REG_S4 = 20
REG_S5 = 21
REG_S6 = 22
REG_S7 = 23
REG_T8 = 24
REG_T9 = 25
REG_K0 = 26
REG_K1 = 27
REG_GP = 28
REG_SP = 29
REG_FP = 30
REG_RA = 31
MIPS_REG_NAMES = (REG_ZERO, REG_AT, REG_V0, REG_V1,
                  REG_A0, REG_A1, REG_A2, REG_A3,
                  REG_T0, REG_T1, REG_T2, REG_T3, REG_T4, REG_T5, REG_T6, REG_T7,
                  REG_S0, REG_S1, REG_S2, REG_S3, REG_S4, REG_S5, REG_S6, REG_S7,
                  REG_T8, REG_T9, REG_K0, REG_K1,
                  REG_GP, REG_SP, REG_FP, REG_RA)
assert len(MIPS_REG_NAMES) == 32

# various power of 2 limits
MAX_U8 = 255
MAX_U16 = 0xffff
MAX_I16 = 2**15 - 1
MIN_I16 = -2**15
MAX_U32 = 0xffffffff
MAX_I32 = int(2**31 - 1)    # keep as int if Python is 32bit
MIN_I32 = int(-2**31)

# struct data type codes for register data (big-endian target)
REG_DATA_UINT8 = 'B'
REG_DATA_INT16 = '>h'
REG_DATA_UINT16 = '>H'
REG_DATA_INT32 = '>l'
REG_DATA_UINT32 = '>L'

# opcode mnemonics implemented
MIPS_ADDI = 'addi'
MIPS_ADDIU = 'addiu'
MIPS_ADDU = 'addu'
MIPS_ANDI = 'andi'
MIPS_B = 'b'
MIPS_BEQ = 'beq'
MIPS_BNE = 'bne'
MIPS_JR = 'jr'
MIPS_LBU = 'lbu'
MIPS_LI = 'li'
MIPS_LW = 'lw'
MIPS_MOVE = 'move'
MIPS_OR = 'or'
MIPS_SB = 'sb'
MIPS_SLL = 'sll'
MIPS_SLTIU = 'sltiu'
MIPS_SLTU = 'sltu'
MIPS_SRL = 'srl'
MIPS_SUBU = 'subu'
MIPS_SW = 'sw'
MIPS_WSBH = 'wsbh'
MIPS_NOP = 'nop'
MIPS_MEMCPY = 'memcpy'



### Python 2/3 portability helpers

if sys.version_info > (3,):
    xrange = range



### helper routines

# write a message to stdout
LOGLN_FMT_NL = '%s\n'
LOGLN_FMT_RO = '%s\r'
def logln(msg, NL=True):
    if NL:
        fmt = LOGLN_FMT_NL
    else:
        fmt = LOGLN_FMT_RO
    sys.stdout.write(fmt % msg)
    sys.stdout.flush()


# limit a value to a signed range
def limit_signed(v, v_min, v_max, wrap):
    if wrap:
        if v < v_min:
            v -= v_min
            v += v_max + 1
        if v > v_max:
            v -= v_max + 1
            v += v_min
    assert v_min <= v <= v_max
    return v


# limit a value to an unsigned range
def limit_unsigned(v, v_max, clip):
    if v > v_max and clip:
        v &= v_max
    assert 0 <= v <= v_max
    return v


# limit a value to 8bit range (unsigned)
# (don't clip excess bits by default - errors in byte handling
#  should be investigated)
def limit_u8(value, clip_excess=False):
    return limit_unsigned(value, MAX_U8, clip_excess)


# limit a value to 16bit range (signed)
def limit_i16(value, wrap_around=True):
    return limit_signed(value, MIN_I16, MAX_I16, wrap_around)


# limit a value to 16bit range (unsigned)
def limit_u16(value, clip_excess=True):
    return limit_unsigned(value, MAX_U16, clip_excess)


# limit a value to 32bit range (signed)
def limit_i32(value, wrap_around=True):
    return limit_signed(value, MIN_I32, MAX_I32, wrap_around)


# limit a value to 32bit range (unsigned)
def limit_u32(value, clip_excess=True):
    return limit_unsigned(value, MAX_U32, clip_excess)


# sign extend a value to it's unsigned representation
def sign_extend_i16_u32(v):
    r = register()
    r.i32 = limit_i16(v)
    return r.u32



### MIPS simulated CPU classes

# a register with manipulation methods
# - keep the register value unsigned, converting to signed as required
class register(object):

    def __init__(self, read_write=True):
        self._data = 0
        self._read_write = read_write

    @property
    def u8_lsb(self):
        return self._data & MAX_U8

    @property
    def u8(self):
        bits = 8
        v = self._data
        b0 = v & MAX_U8
        v >>= bits
        b1 = v & MAX_U8
        v >>= bits
        b2 = v & MAX_U8
        v >>= bits
        b3 = v & MAX_U8
        return (b3, b2, b1, b0)

    @u8.setter
    def u8(self, bytes):
        assert len(bytes) == 4
        if self._read_write:
            bits = 8
            b3, b2, b1, b0 = bytes
            assert 0 <= b3 <= MAX_U8
            v = b3
            v <<= bits
            assert 0 <= b2 <= MAX_U8
            v += b2
            v <<= bits
            assert 0 <= b1 <= MAX_U8
            v += b1
            v <<= bits
            assert 0 <= b0 <= MAX_U8
            v += b0
            self._data = v

    @property
    def i32(self):
        return limit_signed(self._data, MIN_I32, MAX_I32, True)

    @i32.setter
    def i32(self, value):
        if self._read_write:
            v = limit_signed(value, MIN_I32, MAX_I32, True)
            if v < 0:
                v += MAX_U32
                v += 1
            self._data = v

    @property
    def u32(self):
        return self._data

    @u32.setter
    def u32(self, value):
        if self._read_write:
            self._data = limit_unsigned(value, MAX_U32, True)


# encapsulate the simulation
class MIPS_Core:

    # basic system config
    _RAM_ADDRESS = 0
    _RAM_SIZE = 0x200000

    # internal representation of opcode mnemonic
    _OPCODE = 'instr_%s'
    _OPCODE_SUPPORTED = (MIPS_ADDI, MIPS_ADDIU, MIPS_ADDU, MIPS_ANDI, MIPS_B,
                         MIPS_BEQ, MIPS_BNE, MIPS_JR, MIPS_LBU, MIPS_LI, MIPS_LW,
                         MIPS_MOVE, MIPS_OR, MIPS_SB, MIPS_SLL, MIPS_SLTIU,
                         MIPS_SLTU, MIPS_SRL, MIPS_SUBU, MIPS_SW, MIPS_WSBH,
                         MIPS_NOP, MIPS_MEMCPY)

    # opcode result logging
    _LOG_OPC_RESULTS = False
    _LOG_OPC_FORMAT = '[%04x]  %s\n'
    _LOG_OPC_REGWORD = '%s = 0x%08x'
    _LOG_OPC_MEMBYTE = '@0x%x = 0x%x'
    _LOG_OPC_MEMWORD = '@0x%x = 0x%08x'
    _LOG_OPC_NOBRANCH = '---'
    _LOG_OPC_BRANCHTO = '=> %s'
    _LOG_OPC_SUB_RET = 'RETURN'


    def __init__(self, instruction_seq=[]):

        # setup the register file
        regs = [register(False)]
        regs.extend(register() for rn in MIPS_REG_NAMES[1:])
        self.registers = tuple(regs)

        # set the stack pointer to the top of RAM
        self.registers[REG_SP].u32 = self._RAM_ADDRESS + self._RAM_SIZE

        # configure the RAM
        self.ram = bytearray(0 for i in xrange(self._RAM_SIZE))

        # cache the opcode implementations
        self._opc_cache = {o: getattr(self, self._OPCODE % o) for o in self._OPCODE_SUPPORTED}

        # scan the instruction sequence for labels to build a branch target index
        self.instructions = instruction_seq
        targets = {}
        for i, inst in enumerate(instruction_seq):
            if len(inst) == 3:
                targets[inst[2]] = i
        self.branch_tgts = targets


    # RAM access
    def read_ram(self, address, byte_count):
        ram_addr = address - self._RAM_ADDRESS
        return self.ram[ram_addr: ram_addr + byte_count]

    def write_ram(self, address, byte_seq):
        ram_addr = address - self._RAM_ADDRESS
        byte_count = len(byte_seq)
        self.ram[ram_addr: ram_addr + byte_count] = byte_seq

    # execute instruction sequence
    # - each instruction in sequence has the format
    #   (instr_mnemonic, (arg_1,...), <label>)
    #   where label is optional
    # - routine function call arguments
    def execute(self, a0=0, a1=0, a2=0, a3=0):

        # set the argument registers
        self.registers[REG_A0].u32 = a0
        self.registers[REG_A1].u32 = a1
        self.registers[REG_A2].u32 = a2
        self.registers[REG_A3].u32 = a3

        # start at the beginning
        self.ip = 0
        while True:

            # execute the instruction and check whether there's a branch
            branch_to = self.exec_next_instr()
            self.ip += 1
            if branch_to is not None:

                # execute the instruction in the delay slot
                # NB: branch instructions should not be used in delay slots
                self.exec_next_instr(delay_slot=True)

                # now take the branch
                if branch_to == self._LOG_OPC_SUB_RET:
                    break
                self.ip = self.branch_tgts[branch_to]

        # return the value in the v0 register as the execution result
        return self.registers[REG_V0].i32

    # fetch and execute the next instruction
    def exec_next_instr(self, delay_slot=False):
        try:
            mnemonic, args = self.instructions[self.ip][:2]
        except IndexError:
            raise ValueError('attempted to execute non-existent instruction at [%04x]' % self.ip)
        branch_tgt = self._opc_cache[mnemonic](*args)
        if delay_slot and branch_tgt is not None:
            raise ValueError('%s should not be used in a delay slot' % mnemonic.upper())
        return branch_tgt

    # opcode result logging
    def log_opc_result(self, msg):
        sys.stderr.write(self._LOG_OPC_FMT % (self.ip, msg))
        sys.stderr.flush()

    # instruction implementations
    # - add immediate word
    def instr_addi(self, rt, rs, imm):
        try:
            value = self.registers[rs].i32 + limit_i16(imm)
            assert MIN_I32 <= value <= MAX_I32
        except AssertionError:
            raise ValueError('Overflow exception')
        self.registers[rt].i32 = value
        if self._LOG_OPC_RESULTS:
            self.log_opc_result(self._LOG_OPC_REGWORD % (rt, self.registers[rt].u32))

    # - add immediate unsigned word
    def instr_addiu(self, rt, rs, imm):
        self.registers[rt].i32 = self.registers[rs].i32 + limit_i16(imm)
        if self._LOG_OPC_RESULTS:
            self.log_opc_result(self._LOG_OPC_REGWORD % (rt, self.registers[rt].u32))

    # - add unsigned word
    def instr_addu(self, rd, rs, rt):
        self.registers[rd].i32 = self.registers[rs].i32 + self.registers[rt].i32
        if self._LOG_OPC_RESULTS:
            self.log_opc_result(self._LOG_OPC_REGWORD % (rd, self.registers[rd].u32))

    # - and immediate
    def instr_andi(self, rt, rs, imm):
        self.registers[rt].u32 = self.registers[rs].u32 & limit_u16(imm)
        if self._LOG_OPC_RESULTS:
            self.log_opc_result(self._LOG_OPC_REGWORD % (rt, self.registers[rt].u32))

    # - unconditional branch
    def instr_b(self, label):
        if self._LOG_OPC_RESULTS:
            self.log_opc_result(self._LOG_OPC_BRANCHTO % label)
        return label

    # - branch on equal
    def instr_beq(self, rs, rt, label):
        if self.registers[rs].u32 == self.registers[rt].u32:
            if self._LOG_OPC_RESULTS:
                self.log_opc_result(self._LOG_OPC_BRANCHTO % label)
            return label
        else:
            if self._LOG_OPC_RESULTS:
                self.log_opc_result(self._LOG_OPC_NOBRANCH)

    # - branch on not equal
    def instr_bne(self, rs, rt, label):
        if self.registers[rs].u32 != self.registers[rt].u32:
            if self._LOG_OPC_RESULTS:
                self.log_opc_result(self._LOG_OPC_BRANCHTO % label)
            return label
        else:
            if self._LOG_OPC_RESULTS:
                self.log_opc_result(self._LOG_OPC_NOBRANCH)

    # - jump register
    #   (if register is ra, this is a subroutine return)
    def instr_jr(self, rs):
        if rs == REG_RA:
            if self._LOG_OPC_RESULTS:
                self.log_opc_result(self._LOG_OPC_SUB_RET)
            return self._LOG_OPC_SUB_RET
        raise ValueError('non-returning JR not implemented')

    # - load byte unsigned
    def instr_lbu(self, rt, base, offset):
        address = self.registers[base].u32 + limit_i16(offset) - self._RAM_ADDRESS
        assert 0 <= address <= MAX_U32
        self.registers[rt].u32 = self.ram[address]
        if self._LOG_OPC_RESULTS:
            self.log_opc_result(self._LOG_OPC_REGWORD % (rt, self.registers[rt].u32))

    # - load immediate (pseudo op)
    def instr_li(self, rt, imm):
        self.registers[rt].i32 = imm
        if self._LOG_OPC_RESULTS:
            self.log_opc_result(self._LOG_OPC_REGWORD % (rt, self.registers[rt].u32))

    # - load word
    #   NB: this implementation can be used in place of an lwl/lwr pair in
    #       simple cases because it ignores alignment
    def instr_lw(self, rt, base, offset):
        address = self.registers[base].u32 + limit_i16(offset) - self._RAM_ADDRESS
        assert 0 <= address <= MAX_U32
        self.registers[rt].u32 = struct.unpack_from(REG_DATA_UINT32, self.ram, address)[0]
        if self._LOG_OPC_RESULTS:
            self.log_opc_result(self._LOG_OPC_REGWORD % (rt, self.registers[rt].u32))

    # - move (pseudo op)
    def instr_move(self, rt, rs):
        self.registers[rt].u32 = self.registers[rs].u32
        if self._LOG_OPC_RESULTS:
            self.log_opc_result(self._LOG_OPC_REGWORD % (rt, self.registers[rt].u32))

    # - or
    def instr_or(self, rd, rs, rt):
        self.registers[rd].u32 = self.registers[rs].u32 | self.registers[rt].u32
        if self._LOG_OPC_RESULTS:
            self.log_opc_result(self._LOG_OPC_REGWORD % (rd, self.registers[rd].u32))
        
    # - store byte
    def instr_sb(self, rt, base, offset):
        address = self.registers[base].u32 + limit_i16(offset) - self._RAM_ADDRESS
        assert 0 <= address <= MAX_U32
        self.ram[address] = self.registers[rt].u8_lsb
        if self._LOG_OPC_RESULTS:
            self.log_opc_result(self._LOG_OPC_MEMBYTE % (address, self.registers[rt].u8_lsb))

    # - shift word left logical
    def instr_sll(self, rd, rt, sa):
        self.registers[rd].u32 = self.registers[rt].u32 << sa
        if self._LOG_OPC_RESULTS:
            self.log_opc_result(self._LOG_OPC_REGWORD % (rd, self.registers[rd].u32))

    # - set on less than immediate unsigned
    def instr_sltiu(self, rt, rs, imm):
        v = 0
        if self.registers[rs].u32 < sign_extend_i16_u32(imm):
            v = 1
        self.registers[rt].u32 = v
        if self._LOG_OPC_RESULTS:
            self.log_opc_result(self._LOG_OPC_REGWORD % (rt, self.registers[rt].u32))

    # - set on less than unsigned
    def instr_sltu(self, rd, rs, rt):
        v = 0
        if self.registers[rs].u32 < self.registers[rt].u32:
            v = 1
        self.registers[rd].u32 = v
        if self._LOG_OPC_RESULTS:
            self.log_opc_result(self._LOG_OPC_REGWORD % (rd, self.registers[rd].u32))

    # - shift word right logical
    def instr_srl(self, rd, rt, sa):
        self.registers[rd].u32 = self.registers[rt].u32 >> sa
        if self._LOG_OPC_RESULTS:
            self.log_opc_result(self._LOG_OPC_REGWORD % (rd, self.registers[rd].u32))

    # - substract unsigned word
    def instr_subu(self, rd, rs, rt):
        self.registers[rd].i32 = self.registers[rs].i32 - self.registers[rt].i32
        if self._LOG_OPC_RESULTS:
            self.log_opc_result(self._LOG_OPC_REGWORD % (rd, self.registers[rd].u32))

    # - store word
    #   NB: this implementation can be used in place of an swl/swr pair in
    #       simple cases because it ignores alignment
    def instr_sw(self, rt, base, offset):
        address = self.registers[base].u32 + limit_i16(offset) - self._RAM_ADDRESS
        assert 0 <= address <= MAX_U32
        struct.pack_into(REG_DATA_UINT32, self.ram, address, self.registers[rt].u32)
        if self._LOG_OPC_RESULTS:
            self.log_opc_result(self._LOG_OPC_MEMWORD % (address, self.registers[rt].u32))

    # - word swap bytes within halfwords
    def instr_wsbh(self, rd, rt):
        b3, b2, b1, b0 = self.registers[rt].u8
        self.registers[rd].u8 = (b2, b3, b0, b1)
        if self._LOG_OPC_RESULTS:
            self.log_opc_result(self._LOG_OPC_REGWORD % (rd, self.registers[rd].u32))

    # - no-op
    def instr_nop(self):
        if self._LOG_OPC_RESULTS:
            self.log_opc_result('...')

    # - virtual instruction: copy memory
    #   dst_address is in a0
    #   src_address is in a1
    #   byte_count is in a2
    def instr_memcpy(self):
        copied_bytes = self.read_ram(self.registers[REG_A1].u32, self.registers[REG_A2].u32)
        self.write_ram(self.registers[REG_A0].u32, copied_bytes)
        if self._LOG_OPC_RESULTS:
            self.log_opc_result('memcpy(a0, a1, a2)')



### the code to execute

# each assembly instruction is encoded in a tuple with the following
# layout:
# - instruction mnemonic
# - a tuple of arguments
# - an optional label
#
# The MIPS convention of a base register with immediate offset
# being written as "imm(reg)" is split into 2 arguments as "reg, imm"
# e.g. "addiu sp,-64(sp)" is encoded as ('addiu', ('sp', 'sp', -64))
#
# Draytek decompressor function arguments
# - a0: source buffer base address
# - a1: output buffer base address
# - a2: source byte count
# - a3: output buffer size (in bytes))
#
# returns
# - on success: v0 = number of bytes in the decompressed data chunk
# - on error:   v0 = -1
#
DRAYTEK_DECOMPRESS = ((MIPS_ADDIU,   (REG_SP, REG_SP, -64)                ),
                      (MIPS_LI,      (REG_V0, 3)                          ),
                      (MIPS_LI,      (REG_V1, 2)                          ),
                      (MIPS_SW,      (REG_RA, REG_SP, 60)                 ),
                      (MIPS_ADDU,    (REG_T1, REG_A0, REG_A2)             ),
                      (MIPS_SW,      (REG_S2, REG_SP, 56)                 ),
                      (MIPS_ADDU,    (REG_T7, REG_A1, REG_A3)             ),
                      (MIPS_SW,      (REG_S1, REG_SP, 52)                 ),
                      (MIPS_SW,      (REG_S0, REG_SP, 48)                 ),
                      (MIPS_SW,      (REG_ZERO, REG_SP, 16)               ),
                      (MIPS_SW,      (REG_ZERO, REG_SP, 32)               ),
                      (MIPS_SW,      (REG_V0, REG_SP, 20)                 ),
                      (MIPS_SW,      (REG_V1, REG_SP, 24)                 ),
                      (MIPS_SW,      (REG_V0, REG_SP, 28)                 ),
                      (MIPS_SW,      (REG_ZERO, REG_SP, 36)               ),
                      (MIPS_SW,      (REG_ZERO, REG_SP, 40)               ),
                      (MIPS_BEQ,     (REG_A3, REG_ZERO, 'L.23')           ),
                      (MIPS_SW,      (REG_ZERO, REG_SP, 44)               ),
                      (MIPS_ADDIU,   (REG_T5, REG_T7, -12)                ),
                      (MIPS_LI,      (REG_T3, 15)                         ),
                      (MIPS_LI,      (REG_T2, 255)                        ),
                      (MIPS_ADDIU,   (REG_T6, REG_T1, -8)                 ),
                      (MIPS_ADDIU,   (REG_T8, REG_T1, -6)                 ),
                      (MIPS_ADDIU,   (REG_T4, REG_T7, -8)                 ),
                      (MIPS_ADDIU,   (REG_T9, REG_T7, -5)                 ),
                      (MIPS_MOVE,    (REG_V0, REG_A1)                     ),
                      (MIPS_MOVE,    (REG_A2, REG_A0)                     ),
                      (MIPS_LBU,     (REG_A3, REG_A2, 0),           'L.01'),
                      (MIPS_ADDIU,   (REG_V1, REG_A2, 1),           'L.02'),
                      (MIPS_SRL,     (REG_A2, REG_A3, 0x4)                ),
                      (MIPS_BEQ,     (REG_A2, REG_T3, 'L.10')             ),
                      (MIPS_SLTU,    (REG_T0, REG_V1, REG_T1)             ),
                      (MIPS_ADDU,    (REG_S0, REG_V0, REG_A2),      'L.03'),
                      (MIPS_SLTU,    (REG_T0, REG_T5, REG_S0),      'L.04'),
                      (MIPS_BNE,     (REG_T0, REG_ZERO, 'L.13')           ),
                      (MIPS_ADDU,    (REG_T0, REG_V1, REG_A2)             ),
                      (MIPS_SLTU,    (REG_S1, REG_T6, REG_T0),      'L.05'),
                      (MIPS_BNE,     (REG_S1, REG_ZERO, 'L.13')           ),
                      (MIPS_NOP,     ()                                   ),
                      (MIPS_LW,      (REG_A2, REG_V1, 0),           'L.06'),
                      (MIPS_SW,      (REG_A2, REG_V0, 0)                  ),
                      (MIPS_LW,      (REG_A2, REG_V1, 4)                  ),
                      (MIPS_SW,      (REG_A2, REG_V0, 4)                  ),
                      (MIPS_ADDIU,   (REG_V0, REG_V0, 8)                  ),
                      (MIPS_SLTU,    (REG_A2, REG_V0, REG_S0)             ),
                      (MIPS_BNE,     (REG_A2, REG_ZERO, 'L.06')           ),
                      (MIPS_ADDIU,   (REG_V1, REG_V1, 8)                  ),
                      (MIPS_SUBU,    (REG_V0, REG_V0, REG_S0)             ),
                      (MIPS_SUBU,    (REG_V1, REG_V1, REG_V0)             ),
                      (MIPS_ADDIU,   (REG_A2, REG_V1, 2)                  ),
                      (MIPS_LBU,     (REG_V0, REG_V1, 0)                  ),
                      (MIPS_LBU,     (REG_V1, REG_V1, 1)                  ),
                      (MIPS_SLL,     (REG_V0, REG_V0, 0x8)                ),
                      (MIPS_OR,      (REG_V1, REG_V1, REG_V0)             ),
                      (MIPS_WSBH,    (REG_V1, REG_V1)                     ),
                      (MIPS_ANDI,    (REG_V1, REG_V1, 0xffff)             ),
                      (MIPS_SUBU,    (REG_T0, REG_S0, REG_V1)             ),
                      (MIPS_SLTU,    (REG_V0, REG_T0, REG_A1)             ),
                      (MIPS_BNE,     (REG_V0, REG_ZERO, 'L.15')           ),
                      (MIPS_ANDI,    (REG_V0, REG_A3, 0xf)                ),
                      (MIPS_BEQ,     (REG_V0, REG_T3, 'L.17')             ),
                      (MIPS_NOP,     ()                                   ),
                      (MIPS_SLTIU,   (REG_V1, REG_V1, 4),           'L.07'),
                      (MIPS_BNE,     (REG_V1, REG_ZERO, 'L.19')           ),
                      (MIPS_NOP,     ()                                   ),
                      (MIPS_LW,      (REG_S1, REG_T0, 0),           'L.08'),
                      (MIPS_ADDIU,   (REG_V1, REG_S0, 4)                  ),
                      (MIPS_ADDIU,   (REG_A3, REG_T0, 4)                  ),
                      (MIPS_ADDU,    (REG_V0, REG_V1, REG_V0)             ),
                      (MIPS_SLTU,    (REG_T0, REG_T4, REG_V0)             ),
                      (MIPS_SW,      (REG_S1, REG_S0, 0)                  ),
                      (MIPS_BNE,     (REG_T0, REG_ZERO, 'L.20')           ),
                      (MIPS_NOP,     ()                                   ),
                      (MIPS_LW,      (REG_T0, REG_A3, 0),           'L.09'),
                      (MIPS_SW,      (REG_T0, REG_V1, 0)                  ),
                      (MIPS_LW,      (REG_T0, REG_A3, 4)                  ),
                      (MIPS_SW,      (REG_T0, REG_V1, 4)                  ),
                      (MIPS_ADDIU,   (REG_V1, REG_V1, 8)                  ),
                      (MIPS_SLTU,    (REG_T0, REG_V1, REG_V0)             ),
                      (MIPS_BNE,     (REG_T0, REG_ZERO, 'L.09')           ),
                      (MIPS_ADDIU,   (REG_A3, REG_A3, 8)                  ),
                      (MIPS_LBU,     (REG_A3, REG_A2, 0)                  ),
                      (MIPS_ADDIU,   (REG_V1, REG_A2, 1)                  ),
                      (MIPS_SRL,     (REG_A2, REG_A3, 0x4)                ),
                      (MIPS_BNE,     (REG_A2, REG_T3, 'L.03')             ),
                      (MIPS_SLTU,    (REG_T0, REG_V1, REG_T1)             ),
                      (MIPS_BNE,     (REG_T0, REG_ZERO, 'L.12'),    'L.10'),
                      (MIPS_ADDIU,   (REG_V1, REG_V1, 1)                  ),
                      (MIPS_ADDIU,   (REG_V1, REG_V1, -1)                 ),
                      (MIPS_B,       ('L.04',)                            ),
                      (MIPS_ADDU,    (REG_S0, REG_V0, REG_A2)             ),
                      (MIPS_BNE,     (REG_T0, REG_T2, 'L.04'),      'L.11'),
                      (MIPS_ADDU,    (REG_S0, REG_V0, REG_A2)             ),
                      (MIPS_ADDIU,   (REG_V1, REG_V1, 1)                  ),
                      (MIPS_LBU,     (REG_T0, REG_V1, -1),          'L.12'),
                      (MIPS_BNE,     (REG_T1, REG_V1, 'L.11')             ),
                      (MIPS_ADDU,    (REG_A2, REG_A2, REG_T0)             ),
                      (MIPS_ADDU,    (REG_S0, REG_V0, REG_A2)             ),
                      (MIPS_SLTU,    (REG_T0, REG_T5, REG_S0)             ),
                      (MIPS_BEQ,     (REG_T0, REG_ZERO, 'L.05')           ),
                      (MIPS_ADDU,    (REG_T0, REG_V1, REG_A2)             ),
                      (MIPS_BEQ,     (REG_T1, REG_T0, 'L.24'),      'L.13'),
                      (MIPS_NOP,     ()                                   ),
                      (MIPS_MOVE,    (REG_A2, REG_V1),              'L.14'),
                      (MIPS_SUBU,    (REG_V1, REG_A0, REG_A2),      'L.15'),
                      (MIPS_ADDIU,   (REG_V0, REG_V1, -1)                 ),
                      (MIPS_LW,      (REG_RA, REG_SP, 60),          'L.16'),
                      (MIPS_LW,      (REG_S2, REG_SP, 56)                 ),
                      (MIPS_LW,      (REG_S1, REG_SP, 52)                 ),
                      (MIPS_LW,      (REG_S0, REG_SP, 48)                 ),
                      (MIPS_JR,      (REG_RA,)                            ),
                      (MIPS_ADDIU,   (REG_SP, REG_SP, 64)                 ),
                      (MIPS_LI,      (REG_V0, 15),                  'L.17'),
                      (MIPS_SLTU,    (REG_A3, REG_A2, REG_T8),      'L.18'),
                      (MIPS_BEQ,     (REG_A3, REG_ZERO, 'L.07')           ),
                      (MIPS_NOP,     ()                                   ),
                      (MIPS_ADDIU,   (REG_A2, REG_A2, 1)                  ),
                      (MIPS_LBU,     (REG_A3, REG_A2, -1)                 ),
                      (MIPS_BEQ,     (REG_A3, REG_T2, 'L.18')             ),
                      (MIPS_ADDU,    (REG_V0, REG_V0, REG_A3)             ),
                      (MIPS_SLTIU,   (REG_V1, REG_V1, 4)                  ),
                      (MIPS_BEQ,     (REG_V1, REG_ZERO, 'L.08')           ),
                      (MIPS_NOP,     ()                                   ),
                      (MIPS_LBU,     (REG_S1, REG_T0, 0),           'L.19'),
                      (MIPS_ADDIU,   (REG_A3, REG_T0, 4)                  ),
                      (MIPS_ADDIU,   (REG_V1, REG_S0, 4)                  ),
                      (MIPS_SB,      (REG_S1, REG_S0, 0)                  ),
                      (MIPS_SUBU,    (REG_S1, REG_V1, REG_A3)             ),
                      (MIPS_LBU,     (REG_S2, REG_T0, 1)                  ),
                      (MIPS_ADDU,    (REG_V0, REG_V1, REG_V0)             ),
                      (MIPS_SLL,     (REG_S1, REG_S1, 0x2)                ),
                      (MIPS_SB,      (REG_S2, REG_S0, 1)                  ),
                      (MIPS_ADDIU,   (REG_S2, REG_SP, 16)                 ),
                      (MIPS_ADDU,    (REG_S1, REG_S2, REG_S1)             ),
                      (MIPS_LBU,     (REG_S2, REG_T0, 2)                  ),
                      (MIPS_LW,      (REG_S1, REG_S1, 0)                  ),
                      (MIPS_SB,      (REG_S2, REG_S0, 2)                  ),
                      (MIPS_LBU,     (REG_T0, REG_T0, 3)                  ),
                      (MIPS_SUBU,    (REG_A3, REG_A3, REG_S1)             ),
                      (MIPS_SB,      (REG_T0, REG_S0, 3)                  ),
                      (MIPS_LW,      (REG_T0, REG_A3, 0)                  ),
                      (MIPS_SW,      (REG_T0, REG_S0, 4)                  ),
                      (MIPS_SLTU,    (REG_T0, REG_T4, REG_V0)             ),
                      (MIPS_BEQ,     (REG_T0, REG_ZERO, 'L.09')           ),
                      (MIPS_NOP,     ()                                   ),
                      (MIPS_SLTU,    (REG_T0, REG_T9, REG_V0),      'L.20'),
                      (MIPS_BNE,     (REG_T0, REG_ZERO, 'L.15')           ),
                      (MIPS_NOP,     ()                                   ),
                      (MIPS_LW,      (REG_T0, REG_A3, 0),           'L.21'),
                      (MIPS_SW,      (REG_T0, REG_V1, 0)                  ),
                      (MIPS_LW,      (REG_T0, REG_A3, 4)                  ),
                      (MIPS_SW,      (REG_T0, REG_V1, 4)                  ),
                      (MIPS_ADDIU,   (REG_V1, REG_V1, 8)                  ),
                      (MIPS_SLTU,    (REG_T0, REG_V1, REG_T4)             ),
                      (MIPS_BNE,     (REG_T0, REG_ZERO, 'L.21')           ),
                      (MIPS_ADDIU,   (REG_A3, REG_A3, 8)                  ),
                      (MIPS_SLTU,    (REG_T0, REG_V1, REG_V0)             ),
                      (MIPS_BEQ,     (REG_T0, REG_ZERO, 'L.01')           ),
                      (MIPS_NOP,     ()                                   ),
                      (MIPS_ADDIU,   (REG_A3, REG_A3, 1),           'L.22'),
                      (MIPS_LBU,     (REG_T0, REG_A3, -1)                 ),
                      (MIPS_ADDIU,   (REG_V1, REG_V1, 1)                  ),
                      (MIPS_BEQ,     (REG_V0, REG_V1, 'L.01')             ),
                      (MIPS_SB,      (REG_T0, REG_V1, -1)                 ),
                      (MIPS_ADDIU,   (REG_A3, REG_A3, 1)                  ),
                      (MIPS_LBU,     (REG_T0, REG_A3, -1)                 ),
                      (MIPS_ADDIU,   (REG_V1, REG_V1, 1)                  ),
                      (MIPS_BNE,     (REG_V0, REG_V1, 'L.22')             ),
                      (MIPS_SB,      (REG_T0, REG_V1, -1)                 ),
                      (MIPS_B,       ('L.02',)                            ),
                      (MIPS_LBU,     (REG_A3, REG_A2, 0)                  ),
                      (MIPS_LI,      (REG_V0, 1),                   'L.23'),
                      (MIPS_BNE,     (REG_A2, REG_V0, 'L.25')             ),
                      (MIPS_NOP,     ()                                   ),
                      (MIPS_LBU,     (REG_V0, REG_A0, 0)                  ),
                      (MIPS_SLTU,    (REG_V0, REG_ZERO, REG_V0)           ),
                      (MIPS_B,       ('L.16',)                            ),
                      (MIPS_SUBU,    (REG_V0, REG_ZERO, REG_V0)           ),
                      (MIPS_SLTU,    (REG_T7, REG_T7, REG_S0),      'L.24'),
                      (MIPS_BNE,     (REG_T7, REG_ZERO, 'L.14')           ),
                      (MIPS_MOVE,    (REG_S1, REG_A1)                     ),
                      (MIPS_MOVE,    (REG_A0, REG_V0)                     ),
                      (MIPS_MOVE,    (REG_A1, REG_V1)                     ),
                      (MIPS_MEMCPY,  ()                                   ),
                      (MIPS_B,       ('L.16',)                            ),
                      (MIPS_SUBU,    (REG_V0, REG_S0, REG_S1)             ),
                      (MIPS_B,       ('L.16',),                     'L.25'),
                      (MIPS_LI,      (REG_V0, -1)                         ),
                     )



### assembly execution harness

# package the MIPS core and decompression code into a class instance to
# simplify calling the decompressor for each chunk
# - while the nominal destination buffer size is 64kB according to the
#   information accompanying the decompressor disassembly, some images
#   have compressed chunks slightly larger than this (i.e. apparently
#   the original data was already compressed when fed into Draytek's
#   compressor and is therefore slightly expanded as a result) so allow
#   128kB for both source and output buffers; include some guard space
#   in the source buffer as a safety measure

class DTV_Decompressor:

    # simulated MIPS core memory layout for decompressor routine
    # - source: 128kB, including 4kB of guard space
    _SRC_BUFFER = 0x10000
    _SRC_BUFFSZ = 0x20000
    _SRC_GUARDSPC = 0x1000

    # - output: 128kB
    _DST_BUFFER = _SRC_BUFFER + _SRC_BUFFSZ
    _DST_BUFFSZ = 0x20000

    def __init__(self):
        self._core = MIPS_Core(DRAYTEK_DECOMPRESS)
        self._src_max_size = self._SRC_BUFFSZ - self._SRC_GUARDSPC

    # given a compressed chunk, execute the decompression routine
    #
    # returns
    # - on success: the decompressed byte sequence
    # - on error:   None
    #
    def call(self, compressed_bytes):

        # sanity check the input
        chunk_size = len(compressed_bytes)
        assert chunk_size <= self._src_max_size
        assert chunk_size <= self._DST_BUFFSZ

        # write the chunk data bytes into the source buffer
        self._core.write_ram(self._SRC_BUFFER, compressed_bytes)

        # execute the decompressor
        rc = self._core.execute(self._SRC_BUFFER, self._DST_BUFFER, chunk_size, self._DST_BUFFSZ)
        if rc == -1:
            #logln('decompression failed!!')
            return None
        else:
            assert rc > 0
            assert rc <= self._DST_BUFFSZ
            #logln('decompression succeeded: %d bytes recovered' % rc)
            return self._core.read_ram(self._DST_BUFFER, rc)



### Draytek firmware file handlers

# start-of-firmware markers
DTV_FWS_PRI = b'\xA5\xA5\xA5\x5A\xA5\x5A'
DTV_FWS_ALT = b'\x5A\x5A\xA5\x5A\xA5\x5A'

# Draytek compression magic bytes
DTV_COMP_MAGIC = b'\xAA\x1D\x7F\x50'

# progress spinner
SPINNER = '-\|/'


# decompress a compressed firmware component extracted from a Draytek image
# - the image must start with the magic byte sequence
# - each chunk has a little-endian byte count prefixed
def decompress_image(source_bytes, image_start, image_end, out_file):

    # check for the modern Draytek compression magic bytes
    magic_start = source_bytes.find(DTV_COMP_MAGIC, image_start, image_end)
    if magic_start != image_start:
        logln('expected compression magic bytes not found - aborting!')
        sys.exit(1)

    # grab chunks and decompress one at a time
    chunk_start = image_start + len(DTV_COMP_MAGIC)
    chunk_no = 1
    with open(out_file, 'wb') as out_f:
        decompressor = DTV_Decompressor()
        while chunk_start < image_end:
            chunk_size = struct.unpack_from('<L', source_bytes, chunk_start)[0]
            chunk_start += 4
            chunk_bytes = source_bytes[chunk_start: chunk_start + chunk_size]
            decomp_data = decompressor.call(chunk_bytes)
            if decomp_data is None:
                logln('chunk %d: decompression failed!!' % chunk_no)
                sys.exit(1)
            out_f.write(decomp_data)
            chunk_start += chunk_size
            chunk_no += 1
            logln(SPINNER[chunk_no % 4], NL=False)

    # comfirm there was no overshoot
    assert chunk_start == image_end


# extract and decompress the operating system image in a Draytek modem
# firmware file
# - doesn't matter whether ".all" or ".rst" file suffix
# - only supports modern Draytek firmware files with Draytek custom
#   compression (use Draytools for older LZO compressed files)
def extract_firmware(firmware_file, image_file):

    # read in the file and search for the firmware start marker
    fw_bytes = bytearray(open(firmware_file, 'rb').read())
    marker_start = fw_bytes.find(DTV_FWS_PRI)
    if marker_start < 0:
        marker_start = fw_bytes.find(DTV_FWS_ALT)
        if marker_start < 0:
            logln('firmware start marker not found - aborting!')
            sys.exit(1)

    # decompress the firmware image
    start_offset = marker_start + len(DTV_FWS_PRI)
    image_size = struct.unpack_from('>L', fw_bytes, start_offset)[0]
    start_offset += 4
    end_offset = start_offset + image_size
    if end_offset > len(fw_bytes):
        logln('compressed data length exceeds source data length - aborting!')
        sys.exit(1)
    logln('%s: extracting OS firmware image' % firmware_file)
    decompress_image(fw_bytes, start_offset, end_offset, image_file)
    logln('done!')


# extract and decompress the user interface file system in a Draytek modem
# firmware file
# - doesn't matter whether ".all" or ".rst" file suffix
# - only supports modern Draytek firmware files with Draytek custom
#   compression (use Draytools for older LZO compressed files)
def extract_filesystem(firmware_file, image_file):

    # read in the file and get the offset to the compressed filesystem
    fw_bytes = bytearray(open(firmware_file, 'rb').read())
    start_offset = struct.unpack_from('>L', fw_bytes, 0)[0] + 4

    # decompress the filesystem image
    image_size = struct.unpack_from('>L', fw_bytes, start_offset)[0]
    start_offset += 4
    end_offset = start_offset + image_size
    if end_offset > len(fw_bytes):
        logln('compressed data length exceeds source data length - aborting!')
        sys.exit(1)
    logln('%s: extracting UI file system image' % firmware_file)
    decompress_image(fw_bytes, start_offset, end_offset, image_file)
    logln('done!')



### run as script

# default actions
# - if output option not supplied is to extract firmware
# - abort if output file already exists
if __name__ == '__main__':
    output_opts = ['-fw', '-fs']
    usage = 'usage: %s <source_file> [(-fw)|-fs]' % sys.argv[0]

    try:
        source_file = sys.argv[1]
    except IndexError:
        logln(usage)
        sys.exit(1)
    if not os.path.exists(source_file):
        logln('%s: file not found' % source_file)
        sys.exit(1)

    try:
        out_opt = output_opts.index(sys.argv[2])
    except IndexError:
        out_opt = 0
    except ValueError:
        logln('"%s": output format option not supported' % sys.argv[2])
        sys.exit(1)

    output_file = '%s.%s' % (source_file, output_opts[out_opt][1:])
    if os.path.exists(output_file):
        logln('%s: file already exists' % output_file)
        sys.exit(1)

    if out_opt:
        extract_filesystem(source_file, output_file) 
    else:
        extract_firmware(source_file, output_file) 
