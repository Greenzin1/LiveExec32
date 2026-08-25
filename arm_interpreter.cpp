#include "arm_interpreter.h"

// ============================================================================
// Barrel Shifter
// ============================================================================

u32 ArmInterpreter::shift_reg(u32 val, u32 shift_type, u32 amount, bool &carry_out) {
    if (amount == 0) {
        carry_out = ctx.flag_c();
        return val;
    }
    switch (shift_type) {
        case 0: // LSL
            if (amount < 32) {
                carry_out = (val >> (32 - amount)) & 1;
                return val << amount;
            } else if (amount == 32) {
                carry_out = val & 1;
                return 0;
            } else {
                carry_out = false;
                return 0;
            }
        case 1: // LSR
            if (amount < 32) {
                carry_out = (val >> (amount - 1)) & 1;
                return val >> amount;
            } else if (amount == 32) {
                carry_out = val >> 31;
                return 0;
            } else {
                carry_out = false;
                return 0;
            }
        case 2: // ASR
            if (amount < 32) {
                carry_out = (val >> (amount - 1)) & 1;
                return (u32)((s32)val >> amount);
            } else {
                carry_out = val >> 31;
                return (val >> 31) ? 0xFFFFFFFF : 0;
            }
        case 3: // ROR/RRX
            if (amount == 0) {
                // RRX
                carry_out = val & 1;
                return (ctx.flag_c() << 31) | (val >> 1);
            }
            amount &= 31;
            if (amount == 0) {
                carry_out = val >> 31;
                return val;
            }
            {
                u32 result = (val >> amount) | (val << (32 - amount));
                carry_out = result >> 31;
                return result;
            }
    }
    return val;
}

u32 ArmInterpreter::decode_imm_shift(u32 insn, bool &carry_out) {
    u32 shift_type = (insn >> 5) & 3;
    u32 amount = 0;
    if ((insn >> 4) & 1) {
        // Register shift
        u32 rs = (insn >> 8) & 0xF;
        amount = ctx.regs[rs] & 0xFF;
        // For register shifts, flags are only affected when amount != 0
        return shift_reg(ctx.regs[insn & 0xF], shift_type, amount, carry_out);
    } else {
        // Immediate shift
        amount = (insn >> 7) & 0x1F;
        u32 imm5 = amount;
        if (imm5 == 0 && shift_type == 3) {
            // RRX
            return shift_reg(ctx.regs[insn & 0xF], 3, 0, carry_out);
        }
        return shift_reg(ctx.regs[insn & 0xF], shift_type, imm5, carry_out);
    }
}

// ============================================================================
// ALU Operations
// ============================================================================

u32 ArmInterpreter::alu_adc(u32 a, u32 b, bool carry_in) {
    u64 result64 = (u64)a + b + (carry_in ? 1 : 0);
    u32 result = (u32)result64;
    ctx.set_flag_c(result64 >> 32);
    ctx.set_flag_v(((a ^ result) & (b ^ result)) >> 31);
    ctx.set_nz(result);
    return result;
}

u32 ArmInterpreter::alu_sbc(u32 a, u32 b, bool carry_in) {
    u64 result64 = (u64)a - b - (carry_in ? 0 : 1);
    u32 result = (u32)result64;
    ctx.set_flag_c(!(result64 >> 32));
    ctx.set_flag_v(((a ^ b) & (a ^ result)) >> 31);
    ctx.set_nz(result);
    return result;
}

u32 ArmInterpreter::alu_rsc(u32 a, u32 b, bool carry_in) {
    return alu_sbc(b, a, carry_in);
}

u32 ArmInterpreter::alu_rrx(u32 val) {
    bool carry_out;
    return shift_reg(val, 3, 0, carry_out);
}

// ============================================================================
// CP15 stubs
// ============================================================================

u32 ArmInterpreter::cp15_read(u32 reg) {
    switch (reg) {
        case 0: return 0x00000000; // Main ID
        case 1: return 0x000000D8; // Control
        case 2: return 0x00000000; // Translation table base
        case 3: return 0x00000000; // Domain access control
        case 5: return 0x00000000; // Fault status
        case 6: return 0x00000000; // Fault address
        case 7: return 0x00000000; // Cache operations
        case 8: return 0x00000000; // TLB operations
        case 9: return 0x00000000; // Cache lock-down
        case 10: return 0x00000000; // TLB lock-down
        case 13: return 0x00000000; // FCSE PID
        case 15: return 0x41000000; // Implementer (ARM)
        default: return 0;
    }
}

void ArmInterpreter::cp15_write(u32 reg, u32 val) {
    // Stub - ignore writes
}

// ============================================================================
// ARM Instruction Decode
// ============================================================================

void ArmInterpreter::execute_arm(u32 insn) {
    u32 cond = insn >> 28;
    if (cond != 0xE && !ctx.cond_check(cond))
        return;

    u32 opcode = (insn >> 20) & 0xFF;
    u32 fn = (insn >> 4) & 0xF;

    // Multiplies
    if ((insn & 0xFC000F0) == 0x0000090) {
        arm_multiply(insn);
        return;
    }
    if ((insn & 0xF8000F0) == 0x0800090) {
        arm_multiply_long(insn);
        return;
    }

    // BX, BLX, CLZ, BXJ
    if ((insn & 0x0FFFFFD0) == 0x012FFF10) {
        arm_branch_exchange(insn);
        return;
    }
    if ((insn & 0x0FFFFFD0) == 0x012FFF30) {
        // BLX reg
        arm_branch_exchange(insn);
        return;
    }
    if ((insn & 0x0FFFFFD0) == 0x016F1F10) {
        arm_clz(insn);
        return;
    }
    if ((insn & 0x0FFFFFD0) == 0x012FFF20) {
        arm_bxj(insn);
        return;
    }

    // BLX imm
    if ((insn & 0xFE000000) == 0xFA000000) {
        arm_blx_imm(insn);
        return;
    }

    // Saturation
    if ((insn & 0xFB000F0) == 0x1000050) {
        arm_saturation(insn);
        return;
    }

    // Misc (SSAT, USAT, etc.)
    if ((insn & 0xFB000F0) == 0x1000070) {
        arm_misc(insn);
        return;
    }

    // Coprocessor register transfer (MCR/MRC)
    if ((opcode & 0xF0) == 0xE0 && (fn & 0x1) == 0x1) {
        if ((insn & 0x0F000010) == 0x0E000010) {
            arm_coprocessar_register_transfer(insn);
            return;
        }
    }

    // Coprocessor data operation
    if ((opcode & 0xF0) == 0xE0 && (fn & 0x1) == 0x0) {
        arm_coprocessar_data_operation(insn);
        return;
    }

    // Coprocessor data transfer
    if ((opcode & 0xF0) == 0xD0 || (opcode & 0xF0) == 0xC0) {
        arm_coprocessor_data_transfer(insn);
        return;
    }

    // SWI
    if ((insn & 0x0F000000) == 0x0F000000) {
        arm_swi(insn);
        return;
    }

    // MRS/MSR
    if ((insn & 0x0FB00000) == 0x01000000) {
        arm_mrs(insn);
        return;
    }
    if ((insn & 0x0FB00000) == 0x01200000) {
        arm_msr(insn);
        return;
    }

    // Branch (B/BL)
    if ((insn & 0x0E000000) == 0x0A000000) {
        arm_branch(insn);
        return;
    }

    // Halfword data transfer
    if ((insn & 0x0E400F90) == 0x00000090) {
        arm_halfword_data_transfer(insn);
        return;
    }

    // Block data transfer (LDM/STM)
    if ((insn & 0x0E000000) == 0x08000000) {
        arm_block_data_transfer(insn);
        return;
    }

    // Single data transfer (LDR/STR)
    if ((opcode & 0x0E000000) == 0x04000000) {
        arm_single_data_transfer(insn);
        return;
    }

    // Data processing
    if ((opcode & 0x0C000000) == 0x00000000 || (opcode & 0x0C000000) == 0x04000000) {
        if ((insn & 0x0F900090) == 0x01000090) {
            arm_status_transfer(insn);
            return;
        }
        arm_data_processing(insn);
        return;
    }

    // MSR immediate
    if ((insn & 0x0FB00000) == 0x03200000) {
        arm_msr(insn);
        return;
    }
}

// ============================================================================
// ARM Data Processing
// ============================================================================

void ArmInterpreter::arm_data_processing(u32 insn) {
    u32 op = (insn >> 21) & 0xF;
    u32 s = (insn >> 20) & 1;
    u32 rn = (insn >> 16) & 0xF;
    u32 rd = (insn >> 12) & 0xF;
    bool carry = ctx.flag_c();
    u32 op2;
    u32 result;

    if ((insn >> 25) & 1) {
        // Immediate operand
        u32 imm = insn & 0xFF;
        u32 rot = ((insn >> 8) & 0xF) * 2;
        op2 = (imm >> rot) | (imm << (32 - rot));
        if (rot) carry = op2 >> 31;
    } else {
        op2 = decode_imm_shift(insn, carry);
    }

    u32 operand1 = ctx.regs[rn];

    switch (op) {
        case 0x0: // AND
            result = operand1 & op2;
            ctx.regs[rd] = result;
            if (s) {
                ctx.set_nz(result);
                ctx.set_flag_c(carry);
            }
            break;
        case 0x1: // EOR
            result = operand1 ^ op2;
            ctx.regs[rd] = result;
            if (s) {
                ctx.set_nz(result);
                ctx.set_flag_c(carry);
            }
            break;
        case 0x2: // SUB
            result = operand1 - op2;
            ctx.regs[rd] = result;
            if (s) {
                ctx.set_nz(result);
                ctx.set_flag_c(operand1 >= op2);
                ctx.set_flag_v(((operand1 ^ op2) & (operand1 ^ result)) >> 31);
            }
            break;
        case 0x3: // RSB
            result = op2 - operand1;
            ctx.regs[rd] = result;
            if (s) {
                ctx.set_nz(result);
                ctx.set_flag_c(op2 >= operand1);
                ctx.set_flag_v(((op2 ^ operand1) & (op2 ^ result)) >> 31);
            }
            break;
        case 0x4: // ADD
            {
                u64 result64 = (u64)operand1 + op2;
                result = (u32)result64;
                ctx.regs[rd] = result;
                if (s) {
                    ctx.set_nz(result);
                    ctx.set_flag_c(result64 >> 32);
                    ctx.set_flag_v(((operand1 ^ result) & (op2 ^ result)) >> 31);
                }
            }
            break;
        case 0x5: // ADC
            result = alu_adc(operand1, op2, ctx.flag_c());
            ctx.regs[rd] = result;
            break;
        case 0x6: // SBC
            result = alu_sbc(operand1, op2, ctx.flag_c());
            ctx.regs[rd] = result;
            break;
        case 0x7: // RSC
            result = alu_rsc(operand1, op2, ctx.flag_c());
            ctx.regs[rd] = result;
            break;
        case 0x8: // TST
            result = operand1 & op2;
            if (s) {
                ctx.set_nz(result);
                ctx.set_flag_c(carry);
            }
            break;
        case 0x9: // TEQ
            result = operand1 ^ op2;
            if (s) {
                ctx.set_nz(result);
                ctx.set_flag_c(carry);
            }
            break;
        case 0xA: // CMP
            result = operand1 - op2;
            if (s) {
                ctx.set_nz(result);
                ctx.set_flag_c(operand1 >= op2);
                ctx.set_flag_v(((operand1 ^ op2) & (operand1 ^ result)) >> 31);
            }
            break;
        case 0xB: // CMN
            {
                u64 result64 = (u64)operand1 + op2;
                result = (u32)result64;
                if (s) {
                    ctx.set_nz(result);
                    ctx.set_flag_c(result64 >> 32);
                    ctx.set_flag_v(((operand1 ^ result) & (op2 ^ result)) >> 31);
                }
            }
            break;
        case 0xC: // ORR
            result = operand1 | op2;
            ctx.regs[rd] = result;
            if (s) {
                ctx.set_nz(result);
                ctx.set_flag_c(carry);
            }
            break;
        case 0xD: // MOV
            result = op2;
            ctx.regs[rd] = result;
            if (s) {
                ctx.set_nz(result);
                ctx.set_flag_c(carry);
            }
            break;
        case 0xE: // BIC
            result = operand1 & ~op2;
            ctx.regs[rd] = result;
            if (s) {
                ctx.set_nz(result);
                ctx.set_flag_c(carry);
            }
            break;
        case 0xF: // MVN
            result = ~op2;
            ctx.regs[rd] = result;
            if (s) {
                ctx.set_nz(result);
                ctx.set_flag_c(carry);
            }
            break;
    }

    // If rd == PC and S bit is set, restore CPSR from SPSR
    if (rd == 15 && s) {
        ctx.cpsr = 0x1D3; // Simplified: restore to system mode
    }
}

// ============================================================================
// ARM Multiply
// ============================================================================

void ArmInterpreter::arm_multiply(u32 insn) {
    u32 rd = (insn >> 16) & 0xF;
    u32 rn = (insn >> 12) & 0xF;
    u32 rs = (insn >> 8) & 0xF;
    u32 rm = insn & 0xF;
    u32 op = (insn >> 21) & 0x3;
    u32 s = (insn >> 20) & 1;

    switch (op) {
        case 0x0: // MUL
            ctx.regs[rd] = ctx.regs[rm] * ctx.regs[rs];
            if (s) ctx.set_nz(ctx.regs[rd]);
            break;
        case 0x1: // MLA
            ctx.regs[rd] = ctx.regs[rm] * ctx.regs[rs] + ctx.regs[rn];
            if (s) ctx.set_nz(ctx.regs[rd]);
            break;
        case 0x2: // UMAAL (unofficial opcode space, but exists on some ARM)
            break;
        case 0x3: // MLS
            ctx.regs[rd] = ctx.regs[rn] - ctx.regs[rm] * ctx.regs[rs];
            if (s) ctx.set_nz(ctx.regs[rd]);
            break;
    }
}

// ============================================================================
// ARM Multiply Long
// ============================================================================

void ArmInterpreter::arm_multiply_long(u32 insn) {
    u32 rdhi = (insn >> 16) & 0xF;
    u32 rdlo = (insn >> 12) & 0xF;
    u32 rs = (insn >> 8) & 0xF;
    u32 rm = insn & 0xF;
    u32 op = (insn >> 21) & 0x3;
    u32 s = (insn >> 20) & 1;

    switch (op) {
        case 0x0: { // UMULL
            u64 result = (u64)ctx.regs[rm] * (u64)ctx.regs[rs];
            ctx.regs[rdhi] = result >> 32;
            ctx.regs[rdlo] = (u32)result;
            if (s) ctx.set_nz(ctx.regs[rdhi] | ctx.regs[rdlo]);
            break;
        }
        case 0x1: { // UMLAL
            u64 result = (u64)ctx.regs[rm] * (u64)ctx.regs[rs];
            result += ((u64)ctx.regs[rdhi] << 32) | ctx.regs[rdlo];
            ctx.regs[rdhi] = result >> 32;
            ctx.regs[rdlo] = (u32)result;
            if (s) ctx.set_nz(ctx.regs[rdhi] | ctx.regs[rdlo]);
            break;
        }
        case 0x2: { // SMULL
            s64 result = (s64)(s32)ctx.regs[rm] * (s64)(s32)ctx.regs[rs];
            ctx.regs[rdhi] = result >> 32;
            ctx.regs[rdlo] = (u32)result;
            if (s) ctx.set_nz(ctx.regs[rdhi] | ctx.regs[rdlo]);
            break;
        }
        case 0x3: { // SMLAL
            s64 result = (s64)(s32)ctx.regs[rm] * (s64)(s32)ctx.regs[rs];
            result += ((u64)ctx.regs[rdhi] << 32) | ctx.regs[rdlo];
            ctx.regs[rdhi] = result >> 32;
            ctx.regs[rdlo] = (u32)result;
            if (s) ctx.set_nz(ctx.regs[rdhi] | ctx.regs[rdlo]);
            break;
        }
    }
}

// ============================================================================
// ARM Single Data Transfer (LDR/STR/LDRB/STRB)
// ============================================================================

void ArmInterpreter::arm_single_data_transfer(u32 insn) {
    u32 i = (insn >> 25) & 1;  // immediate offset flag (0=imm, 1=reg)
    u32 p = (insn >> 24) & 1;  // pre/post
    u32 u = (insn >> 23) & 1;  // up/down
    u32 b = (insn >> 22) & 1;  // byte/word
    u32 w = (insn >> 21) & 1;  // writeback
    u32 l = (insn >> 20) & 1;  // load/store
    u32 rn = (insn >> 16) & 0xF;
    u32 rd = (insn >> 12) & 0xF;
    u32 offset = insn & 0xFFF;

    u32 base = ctx.regs[rn];
    u32 addr;

    if (p) {
        // Pre-indexed
        if (u)
            addr = base + offset;
        else
            addr = base - offset;

        if (w) {
            // Writeback
            ctx.regs[rn] = addr;
        }
    } else {
        // Post-indexed
        addr = base;
        u32 new_base = u ? base + offset : base - offset;
        ctx.regs[rn] = new_base;
    }

    if (l) {
        // Load
        if (b)
            ctx.regs[rd] = cb->mem_read(addr, 1);
        else
            ctx.regs[rd] = cb->mem_read(addr, 4);
    } else {
        // Store
        u32 value = ctx.regs[rd];
        if (rd == 15) value += 4; // PC + 12 for STR
        if (b)
            cb->mem_write(addr, value, 1);
        else
            cb->mem_write(addr, value, 4);
    }

    if (l && rd == 15) {
        // LDR PC
        // Would normally switch mode; simplified here
    }
}

// ============================================================================
// ARM Halfword Data Transfer
// ============================================================================

void ArmInterpreter::arm_halfword_data_transfer(u32 insn) {
    u32 p = (insn >> 24) & 1;
    u32 u = (insn >> 23) & 1;
    u32 w = (insn >> 21) & 1;
    u32 l = (insn >> 20) & 1;
    u32 sh = (insn >> 5) & 3;
    u32 rn = (insn >> 16) & 0xF;
    u32 rd = (insn >> 12) & 0xF;

    u32 base = ctx.regs[rn];
    u32 offset;

    if ((insn >> 22) & 1) {
        // Immediate offset
        offset = ((insn >> 4) & 0xF0) | (insn & 0xF);
    } else {
        // Register offset
        offset = ctx.regs[insn & 0xF];
    }

    u32 addr;
    if (p) {
        addr = u ? base + offset : base - offset;
        if (w) ctx.regs[rn] = addr;
    } else {
        addr = base;
        ctx.regs[rn] = u ? base + offset : base - offset;
    }

    switch (sh) {
        case 0: // Unsigned halfword (LDRH/STRH)
            if (l)
                ctx.regs[rd] = cb->mem_read(addr, 2);
            else
                cb->mem_write(addr, ctx.regs[rd], 2);
            break;
        case 1: // Signed halfword (LDRSH)
            if (l) {
                s32 val = (s32)(s16)cb->mem_read(addr, 2);
                ctx.regs[rd] = val;
            } else {
                // STRH in this encoding
                cb->mem_write(addr, ctx.regs[rd], 2);
            }
            break;
        case 2: // Signed byte (LDRSB)
            if (l) {
                s32 val = (s32)(s8)cb->mem_read(addr, 1);
                ctx.regs[rd] = val;
            } else {
                // LDRD/STRD
                if (l) {
                    ctx.regs[rd] = cb->mem_read(addr, 4);
                    ctx.regs[rd + 1 < 15 ? rd + 1 : 0] = cb->mem_read(addr + 4, 4);
                } else {
                    cb->mem_write(addr, ctx.regs[rd], 4);
                    cb->mem_write(addr + 4, ctx.regs[rd + 1 < 15 ? rd + 1 : 0], 4);
                }
            }
            break;
        case 3: // Reserved / LDRD / STRD
            if (l) {
                ctx.regs[rd] = cb->mem_read(addr, 4);
                ctx.regs[rd + 1 < 15 ? rd + 1 : 0] = cb->mem_read(addr + 4, 4);
            } else {
                cb->mem_write(addr, ctx.regs[rd], 4);
                cb->mem_write(addr + 4, ctx.regs[rd + 1 < 15 ? rd + 1 : 0], 4);
            }
            break;
    }
}

// ============================================================================
// ARM Block Data Transfer (LDM/STM)
// ============================================================================

void ArmInterpreter::arm_block_data_transfer(u32 insn) {
    u32 p = (insn >> 24) & 1;
    u32 u = (insn >> 23) & 1;
    u32 s = (insn >> 22) & 1;
    u32 w = (insn >> 21) & 1;
    u32 l = (insn >> 20) & 1;
    u32 rn = (insn >> 16) & 0xF;
    u32 reglist = insn & 0xFFFF;

    u32 base = ctx.regs[rn];
    u32 num_regs = 0;
    u32 temp = reglist;
    while (temp) { num_regs += temp & 1; temp >>= 1; }

    u32 addr;
    if (u) {
        addr = base;
        if (p) addr += 4;
    } else {
        addr = base - num_regs * 4;
        if (!p) addr += 4;
    }

    for (int i = 0; i < 16; i++) {
        if (reglist & (1 << i)) {
            if (l) {
                ctx.regs[i] = cb->mem_read(addr, 4);
            } else {
                u32 val = ctx.regs[i];
                if (i == 15) val += 12;
                cb->mem_write(addr, val, 4);
            }
            addr += 4;
        }
    }

    // Writeback
    if (w && !l) {
        ctx.regs[rn] = u ? base + num_regs * 4 : base - num_regs * 4;
    }
    if (w && l) {
        ctx.regs[rn] = u ? base + num_regs * 4 : base - num_regs * 4;
    }
}

// ============================================================================
// ARM Branch
// ============================================================================

void ArmInterpreter::arm_branch(u32 insn) {
    bool link = (insn >> 24) & 1;
    s32 offset = (s32)(insn & 0x00FFFFFF);
    if (offset & 0x00800000)
        offset |= 0xFF000000; // sign extend

    offset <<= 2;

    if (link) {
        ctx.regs[14] = ctx.regs[15] + 4;
    }
    ctx.regs[15] += offset + 8;
}

// ============================================================================
// ARM Branch Exchange
// ============================================================================

void ArmInterpreter::arm_branch_exchange(u32 insn) {
    u32 rn = insn & 0xF;
    u32 addr = ctx.regs[rn];

    if (addr & 1) {
        // Switch to Thumb
        ctx.thumb = true;
        ctx.regs[15] = addr & ~1;
    } else {
        // Stay in ARM
        ctx.thumb = false;
        ctx.regs[15] = addr;
    }
}

// ============================================================================
// ARM BLX immediate
// ============================================================================

void ArmInterpreter::arm_blx_imm(u32 insn) {
    s32 offset = (s32)(insn & 0x00FFFFFF);
    if (offset & 0x00800000)
        offset |= 0xFF000000;

    offset <<= 2;
    offset |= ((insn >> 24) & 1) << 1;

    ctx.regs[14] = ctx.regs[15] + 4;
    ctx.thumb = true;
    ctx.regs[15] += offset + 8;
}

// ============================================================================
// ARM Status Transfer (MRS/MSR)
// ============================================================================

void ArmInterpreter::arm_status_transfer(u32 insn) {
    if ((insn & 0x0FBF0FFF) == 0x010F0000) {
        arm_mrs(insn);
    } else if ((insn & 0x0FB0FFF0) == 0x0120F00) {
        arm_msr(insn);
    }
}

void ArmInterpreter::arm_mrs(u32 insn) {
    u32 rd = (insn >> 12) & 0xF;
    if ((insn >> 22) & 1) {
        // SPSR
        ctx.regs[rd] = ctx.cpsr;
    } else {
        ctx.regs[rd] = ctx.cpsr;
    }
}

void ArmInterpreter::arm_msr(u32 insn) {
    u32 imm = (insn >> 25) & 1;
    u32 mask = 0;
    u32 field_mask = (insn >> 16) & 0xF;

    if (field_mask & 1) mask |= 0x000000FF;
    if (field_mask & 2) mask |= 0x0000FF00;
    if (field_mask & 4) mask |= 0x00FF0000;
    if (field_mask & 8) mask |= 0xFF000000;

    u32 val;
    if (imm) {
        u32 imm8 = insn & 0xFF;
        u32 rot = ((insn >> 8) & 0xF) * 2;
        val = (imm8 >> rot) | (imm8 << (32 - rot));
    } else {
        val = ctx.regs[insn & 0xF];
    }

    if ((insn >> 22) & 1) {
        // SPSR
        ctx.cpsr = (ctx.cpsr & ~mask) | (val & mask);
    } else {
        ctx.cpsr = (ctx.cpsr & ~mask) | (val & mask);
    }
}

// ============================================================================
// ARM SWI
// ============================================================================

void ArmInterpreter::arm_swi(u32 insn) {
    ctx.regs[14] = ctx.regs[15] + 4;
    halted = true;
    cb->svc_hook(ctx.regs[15]);
}

// ============================================================================
// ARM CLZ
// ============================================================================

void ArmInterpreter::arm_clz(u32 insn) {
    u32 rd = (insn >> 12) & 0xF;
    u32 rm = insn & 0xF;
    u32 val = ctx.regs[rm];

    u32 count = 0;
    if (!(val & 0xFFFF0000)) { count += 16; val <<= 16; }
    if (!(val & 0xFF000000)) { count += 8; val <<= 8; }
    if (!(val & 0xF0000000)) { count += 4; val <<= 4; }
    if (!(val & 0xC0000000)) { count += 2; val <<= 2; }
    if (!(val & 0x80000000)) { count += 1; }

    ctx.regs[rd] = count;
}

// ============================================================================
// ARM BXJ (Branch to Jazelle state - stub)
// ============================================================================

void ArmInterpreter::arm_bxj(u32 insn) {
    // Jazelle not supported; treat as NOP
}

// ============================================================================
// ARM Saturation
// ============================================================================

void ArmInterpreter::arm_saturation(u32 insn) {
    u32 op = (insn >> 20) & 0x3;
    u32 rn = (insn >> 16) & 0xF;
    u32 rd = (insn >> 12) & 0xF;
    u32 shift_imm = (insn >> 7) & 0x1F;
    u32 rm = insn & 0xF;

    s32 val = (s32)ctx.regs[rm];
    if (shift_imm > 0)
        val <<= shift_imm;

    switch (op) {
        case 0: { // QADD
            s64 result = (s64)(s32)ctx.regs[rn] + (s64)val;
            if (result > 0x7FFFFFFF) {
                result = 0x7FFFFFFF;
                ctx.cpsr |= (1u << 27); // set Q flag
            } else if (result < -0x80000000) {
                result = -0x80000000;
                ctx.cpsr |= (1u << 27);
            }
            ctx.regs[rd] = (u32)result;
            break;
        }
        case 1: { // QSUB
            s64 result = (s64)(s32)ctx.regs[rn] - (s64)val;
            if (result > 0x7FFFFFFF) {
                result = 0x7FFFFFFF;
                ctx.cpsr |= (1u << 27);
            } else if (result < -0x80000000) {
                result = -0x80000000;
                ctx.cpsr |= (1u << 27);
            }
            ctx.regs[rd] = (u32)result;
            break;
        }
        case 2: { // QDADD
            s64 mul_result = (s64)(s32)val * 2;
            if (mul_result > 0x7FFFFFFF) {
                mul_result = 0x7FFFFFFF;
                ctx.cpsr |= (1u << 27);
            } else if (mul_result < -0x80000000) {
                mul_result = -0x80000000;
                ctx.cpsr |= (1u << 27);
            }
            s64 result = (s64)(s32)ctx.regs[rn] + mul_result;
            if (result > 0x7FFFFFFF) {
                result = 0x7FFFFFFF;
                ctx.cpsr |= (1u << 27);
            } else if (result < -0x80000000) {
                result = -0x80000000;
                ctx.cpsr |= (1u << 27);
            }
            ctx.regs[rd] = (u32)result;
            break;
        }
        case 3: { // QDSUB
            s64 mul_result = (s64)(s32)val * 2;
            if (mul_result > 0x7FFFFFFF) {
                mul_result = 0x7FFFFFFF;
                ctx.cpsr |= (1u << 27);
            } else if (mul_result < -0x80000000) {
                mul_result = -0x80000000;
                ctx.cpsr |= (1u << 27);
            }
            s64 result = (s64)(s32)ctx.regs[rn] - mul_result;
            if (result > 0x7FFFFFFF) {
                result = 0x7FFFFFFF;
                ctx.cpsr |= (1u << 27);
            } else if (result < -0x80000000) {
                result = -0x80000000;
                ctx.cpsr |= (1u << 27);
            }
            ctx.regs[rd] = (u32)result;
            break;
        }
    }
}

// ============================================================================
// ARM Misc (SSAT/USAT)
// ============================================================================

void ArmInterpreter::arm_misc(u32 insn) {
    u32 op = (insn >> 20) & 0xF;
    u32 rn = (insn >> 16) & 0xF;
    u32 rd = (insn >> 12) & 0xF;
    u32 sat_imm = (insn >> 16) & 0x1F;
    u32 shift_imm = (insn >> 7) & 0x1F;
    u32 shift_type = (insn >> 5) & 3;
    u32 rm = insn & 0xF;

    u32 operand = ctx.regs[rm];
    if (shift_type == 0 && shift_imm > 0) {
        operand <<= shift_imm;
    } else if (shift_type == 1 && shift_imm > 0) {
        operand >>= shift_imm;
    }

    switch (op) {
        case 0x6: { // SSAT
            s32 sat_val = (s32)operand;
            s32 max = (1 << sat_imm) - 1;
            s32 min = -(1 << sat_imm);
            if (sat_val > max) { sat_val = max; ctx.cpsr |= (1u << 27); }
            else if (sat_val < min) { sat_val = min; ctx.cpsr |= (1u << 27); }
            ctx.regs[rd] = (u32)sat_val;
            break;
        }
        case 0x7: { // USAT
            u32 sat_val = operand;
            u32 max = (1 << sat_imm) - 1;
            if (sat_val > max) { sat_val = max; ctx.cpsr |= (1u << 27); }
            else if ((s32)sat_val < 0) { sat_val = 0; ctx.cpsr |= (1u << 27); }
            ctx.regs[rd] = sat_val;
            break;
        }
        default:
            break;
    }
}

// ============================================================================
// ARM Coprocessor (stubs - NOP)
// ============================================================================

void ArmInterpreter::arm_coprocessor_data_transfer(u32 insn) {
    // NOP
}

void ArmInterpreter::arm_coprocessar_data_operation(u32 insn) {
    // NOP
}

void ArmInterpreter::arm_coprocessar_register_transfer(u32 insn) {
    // Check if it's MRC with Rd=15 (flags transfer)
    u32 rd = (insn >> 12) & 0xF;
    u32 cp = (insn >> 8) & 0xF;
    u32 crm = insn & 0xF;
    u32 crn = (insn >> 16) & 0xF;
    u32 opc1 = (insn >> 21) & 0x7;
    u32 opc2 = (insn >> 5) & 0x7;
    bool load = (insn >> 20) & 1;

    if (!load && cp == 15 && rd == 15) {
        // MRC to CPSR flags - treat as NOP for now
        return;
    }

    if (load && cp == 15) {
        // MRC
        ctx.regs[rd] = cp15_read(crn);
        return;
    }

    if (!load && cp == 15) {
        // MCR
        cp15_write(crn, ctx.regs[rd]);
        return;
    }
}

// ============================================================================
// ARM Step
// ============================================================================

bool ArmInterpreter::step() {
    if (halted) return false;

    u32 pc = ctx.regs[15];

    if (ctx.thumb) {
        // Fetch Thumb instruction
        u16 insn16 = (u16)cb->mem_read(pc, 2);

        if ((insn16 >> 11) == 0x1F) {
            // Thumb2 32-bit instruction
            u16 insn16_2 = (u16)cb->mem_read(pc + 2, 2);
            u32 insn32 = ((u32)insn16 << 16) | insn16_2;
            execute_thumb2(insn32);
            ctx.regs[15] += 4;
        } else {
            execute_thumb(insn16);
            ctx.regs[15] += 2;
        }
    } else {
        // Fetch ARM instruction
        u32 insn = cb->mem_read(pc, 4);
        execute_arm(insn);
        ctx.regs[15] += 4;
    }

    return !halted;
}

// ============================================================================
// ARM Execute
// ============================================================================

void ArmInterpreter::execute(u32 start_pc) {
    ctx.regs[15] = start_pc;
    running = true;
    halted = false;

    while (!halted) {
        if (!step()) break;
    }
}

// ============================================================================
// Thumb Instructions
// ============================================================================

void ArmInterpreter::execute_thumb(u16 insn) {
    // Decode top bits
    if ((insn >> 13) == 0) {
        // Shift by immediate / add-sub
        if ((insn >> 11) == 0) {
            // LSL/LSR/ASR immediate
            thumb_data_processing(insn);
        } else if ((insn >> 11) == 1) {
            // Add/subtract
            thumb_data_processing(insn);
        }
    } else if ((insn >> 13) == 1) {
        // Move/compare/add/subtract immediate
        thumb_data_processing(insn);
    } else if ((insn >> 11) == 6) {
        // Hi register operations / BX
        if ((insn >> 8) & 1) {
            thumb_high_register_ops(insn);
        } else {
            thumb_data_processing(insn);
        }
    } else if ((insn >> 11) == 5) {
        // ALU operations
        thumb_data_processing(insn);
    } else if ((insn >> 11) == 4) {
        // PC-relative load
        if ((insn >> 12) == 0x01) {
            thumb_load_pc_relative(insn);
        } else {
            thumb_load_store(insn);
        }
    } else if ((insn >> 12) == 5) {
        // Load/store with register offset
        thumb_load_store(insn);
    } else if ((insn >> 12) == 6) {
        // Load/store sign-extended byte/halfword
        thumb_load_store_sign_extend(insn);
    } else if ((insn >> 12) == 7) {
        // Load/store with immediate offset
        thumb_load_store(insn);
    } else if ((insn >> 12) == 8) {
        // Load/store halfword
        thumb_load_store(insn);
    } else if ((insn >> 12) == 9) {
        // SP-relative load/store
        thumb_load_sp_relative(insn);
    } else if ((insn >> 12) == 0xA) {
        // Load address
        thumb_load_pc_relative(insn);
    } else if ((insn >> 8) == 0xB0) {
        // Add offset to stack pointer
        thumb_add_offset_to_sp(insn);
    } else if ((insn >> 9) == 0x0B) {
        // Push/pop
        thumb_push_pop(insn);
    } else if ((insn >> 8) == 0xC0) {
        // Multiple load/store
        thumb_multiple_load_store(insn);
    } else if ((insn >> 12) == 0xD) {
        // Conditional branch
        thumb_conditional_branch(insn);
    } else if ((insn >> 8) == 0xDF) {
        // SWI
        thumb_swi(insn);
    } else if ((insn >> 11) == 0x0E) {
        // Unconditional branch
        thumb_unconditional_branch(insn);
    } else if ((insn >> 11) == 0x0F) {
        // Long branch with link
        thumb_long_branch_with_link(insn);
    } else if ((insn & 0xFF00) == 0x4700) {
        // BX (high register)
        thumb_branch_with_exchange(insn);
    } else {
        // Unimplemented thumb - NOP
    }
}

// ============================================================================
// Thumb Data Processing
// ============================================================================

void ArmInterpreter::thumb_data_processing(u16 insn) {
    // Format 1: LSL/LSR/ASR immediate
    if ((insn >> 13) == 0 && ((insn >> 11) & 1) == 0) {
        u32 rd = insn & 0x7;
        u32 rs = (insn >> 3) & 0x7;
        u32 shift_imm = (insn >> 6) & 0x1F;
        u32 shift_type = (insn >> 11) & 0x3;
        bool carry = ctx.flag_c();
        u32 result = shift_reg(ctx.regs[rs], shift_type, shift_imm, carry);
        ctx.regs[rd] = result;
        ctx.set_nz(result);
        ctx.set_flag_c(carry);
        return;
    }

    // Format 2: Add/subtract
    if ((insn >> 13) == 0 && ((insn >> 11) & 1) == 1) {
        u32 rd = insn & 0x7;
        u32 rn_or_imm3 = (insn >> 3) & 0x7;
        u32 rs = (insn >> 6) & 0x7;
        u32 op = (insn >> 9) & 0x3;
        u32 operand2 = rn_or_imm3;
        if (op < 2)
            operand2 = ctx.regs[rn_or_imm3];

        switch (op) {
            case 0: { // ADD
                u64 result64 = (u64)ctx.regs[rs] + operand2;
                u32 result = (u32)result64;
                ctx.regs[rd] = result;
                ctx.set_nz(result);
                ctx.set_flag_c(result64 >> 32);
                ctx.set_flag_v(((ctx.regs[rs] ^ result) & (operand2 ^ result)) >> 31);
                break;
            }
            case 1: { // SUB
                u32 result = ctx.regs[rs] - operand2;
                ctx.regs[rd] = result;
                ctx.set_nz(result);
                ctx.set_flag_c(ctx.regs[rs] >= operand2);
                ctx.set_flag_v(((ctx.regs[rs] ^ operand2) & (ctx.regs[rs] ^ result)) >> 31);
                break;
            }
            case 2: { // ADD immediate
                u64 result64 = (u64)ctx.regs[rs] + rn_or_imm3;
                u32 result = (u32)result64;
                ctx.regs[rd] = result;
                ctx.set_nz(result);
                ctx.set_flag_c(result64 >> 32);
                ctx.set_flag_v(((ctx.regs[rs] ^ result) & (rn_or_imm3 ^ result)) >> 31);
                break;
            }
            case 3: { // SUB immediate
                u32 result = ctx.regs[rs] - rn_or_imm3;
                ctx.regs[rd] = result;
                ctx.set_nz(result);
                ctx.set_flag_c(ctx.regs[rs] >= rn_or_imm3);
                ctx.set_flag_v(((ctx.regs[rs] ^ rn_or_imm3) & (ctx.regs[rs] ^ result)) >> 31);
                break;
            }
        }
        return;
    }

    // Format 3: Move/compare/add/subtract immediate
    if ((insn >> 13) == 1) {
        u32 op = (insn >> 11) & 0x3;
        u32 rd = (insn >> 8) & 0x7;
        u32 imm8 = insn & 0xFF;

        switch (op) {
            case 0: // MOV
                ctx.regs[rd] = imm8;
                ctx.set_nz(imm8);
                break;
            case 1: // CMP
            {
                u32 result = ctx.regs[rd] - imm8;
                ctx.set_nz(result);
                ctx.set_flag_c(ctx.regs[rd] >= imm8);
                ctx.set_flag_v(((ctx.regs[rd] ^ imm8) & (ctx.regs[rd] ^ result)) >> 31);
                break;
            }
            case 2: // ADD
            {
                u64 result64 = (u64)ctx.regs[rd] + imm8;
                u32 result = (u32)result64;
                ctx.regs[rd] = result;
                ctx.set_nz(result);
                ctx.set_flag_c(result64 >> 32);
                ctx.set_flag_v(((ctx.regs[rd] ^ result) & (imm8 ^ result)) >> 31);
                break;
            }
            case 3: // SUB
            {
                u32 result = ctx.regs[rd] - imm8;
                ctx.regs[rd] = result;
                ctx.set_nz(result);
                ctx.set_flag_c(ctx.regs[rd] >= imm8);
                ctx.set_flag_v(((ctx.regs[rd] ^ imm8) & (ctx.regs[rd] ^ result)) >> 31);
                break;
            }
        }
        return;
    }

    // Format 4: ALU operations
    if ((insn >> 10) == 0x10 && ((insn >> 8) & 0xF) == 0x5) {
        u32 rd = insn & 0x7;
        u32 rs = (insn >> 3) & 0x7;
        u32 op = (insn >> 6) & 0xF;

        switch (op) {
            case 0x0: // AND
                ctx.regs[rd] &= ctx.regs[rs];
                ctx.set_nz(ctx.regs[rd]);
                break;
            case 0x1: // EOR
                ctx.regs[rd] ^= ctx.regs[rs];
                ctx.set_nz(ctx.regs[rd]);
                break;
            case 0x2: { // LSL
                u32 shift_val = ctx.regs[rs] & 0xFF;
                bool carry = ctx.flag_c();
                ctx.regs[rd] = shift_reg(ctx.regs[rd], 0, shift_val, carry);
                ctx.set_nz(ctx.regs[rd]);
                ctx.set_flag_c(carry);
                break;
            }
            case 0x3: { // LSR
                u32 shift_val = ctx.regs[rs] & 0xFF;
                bool carry = ctx.flag_c();
                ctx.regs[rd] = shift_reg(ctx.regs[rd], 1, shift_val, carry);
                ctx.set_nz(ctx.regs[rd]);
                ctx.set_flag_c(carry);
                break;
            }
            case 0x4: { // ASR
                u32 shift_val = ctx.regs[rs] & 0xFF;
                bool carry = ctx.flag_c();
                ctx.regs[rd] = shift_reg(ctx.regs[rd], 2, shift_val, carry);
                ctx.set_nz(ctx.regs[rd]);
                ctx.set_flag_c(carry);
                break;
            }
            case 0x5: { // ADC
                u32 result = alu_adc(ctx.regs[rd], ctx.regs[rs], ctx.flag_c());
                ctx.regs[rd] = result;
                break;
            }
            case 0x6: { // SBC
                u32 result = alu_sbc(ctx.regs[rd], ctx.regs[rs], ctx.flag_c());
                ctx.regs[rd] = result;
                break;
            }
            case 0x7: { // ROR
                u32 shift_val = ctx.regs[rs] & 0xFF;
                bool carry = ctx.flag_c();
                ctx.regs[rd] = shift_reg(ctx.regs[rd], 3, shift_val, carry);
                ctx.set_nz(ctx.regs[rd]);
                ctx.set_flag_c(carry);
                break;
            }
            case 0x8: // TST
            {
                u32 result = ctx.regs[rd] & ctx.regs[rs];
                ctx.set_nz(result);
                break;
            }
            case 0x9: // NEG
            {
                u32 result = 0 - ctx.regs[rs];
                ctx.regs[rd] = result;
                ctx.set_nz(result);
                ctx.set_flag_c(0 >= ctx.regs[rs]);
                ctx.set_flag_v(((0 ^ ctx.regs[rs]) & (0 ^ result)) >> 31);
                break;
            }
            case 0xA: // CMP
            {
                u32 result = ctx.regs[rd] - ctx.regs[rs];
                ctx.set_nz(result);
                ctx.set_flag_c(ctx.regs[rd] >= ctx.regs[rs]);
                ctx.set_flag_v(((ctx.regs[rd] ^ ctx.regs[rs]) & (ctx.regs[rd] ^ result)) >> 31);
                break;
            }
            case 0xB: // CMN
            {
                u64 result64 = (u64)ctx.regs[rd] + ctx.regs[rs];
                u32 result = (u32)result64;
                ctx.set_nz(result);
                ctx.set_flag_c(result64 >> 32);
                ctx.set_flag_v(((ctx.regs[rd] ^ result) & (ctx.regs[rs] ^ result)) >> 31);
                break;
            }
            case 0xC: // ORR
                ctx.regs[rd] |= ctx.regs[rs];
                ctx.set_nz(ctx.regs[rd]);
                break;
            case 0xD: // MUL
                ctx.regs[rd] *= ctx.regs[rs];
                ctx.set_nz(ctx.regs[rd]);
                break;
            case 0xE: // BIC
                ctx.regs[rd] &= ~ctx.regs[rs];
                ctx.set_nz(ctx.regs[rd]);
                break;
            case 0xF: // MVN
                ctx.regs[rd] = ~ctx.regs[rs];
                ctx.set_nz(ctx.regs[rd]);
                break;
        }
        return;
    }

    // Format 11a: MOV high register
    if ((insn >> 10) == 0x10 && ((insn >> 8) & 0xF) == 0x4) {
        thumb_high_register_ops(insn);
        return;
    }

    // Format 5: Hi register operations / BX
    if ((insn >> 10) == 0x10 && ((insn >> 8) & 0xF) == 0x5) {
        thumb_high_register_ops(insn);
        return;
    }
}

// ============================================================================
// Thumb Load/Store
// ============================================================================

void ArmInterpreter::thumb_load_store(u16 insn) {
    // Format 5 (Load/store with register offset)
    if ((insn >> 12) == 0x5 && !((insn >> 9) & 1)) {
        u32 rd = insn & 0x7;
        u32 rb = (insn >> 3) & 0x7;
        u32 ro = (insn >> 6) & 0x7;
        u32 op = (insn >> 9) & 0x3;
        u32 addr = ctx.regs[rb] + ctx.regs[ro];

        switch (op) {
            case 0: // STR
                cb->mem_write(addr, ctx.regs[rd], 4);
                break;
            case 1: // STRB
                cb->mem_write(addr, ctx.regs[rd], 1);
                break;
            case 2: // LDR
                ctx.regs[rd] = cb->mem_read(addr, 4);
                break;
            case 3: // LDRB
                ctx.regs[rd] = cb->mem_read(addr, 1);
                break;
        }
        return;
    }

    // Format 6: Load/store with immediate offset
    if ((insn >> 12) == 0x6) {
        u32 rd = insn & 0x7;
        u32 rb = (insn >> 3) & 0x7;
        u32 offset = ((insn >> 6) & 0x1F) << 2;
        bool load = (insn >> 11) & 1;
        u32 addr = ctx.regs[rb] + offset;

        if (load)
            ctx.regs[rd] = cb->mem_read(addr, 4);
        else
            cb->mem_write(addr, ctx.regs[rd], 4);
        return;
    }

    // Format 7: Load/store sign-extended byte/halfword
    if ((insn >> 12) == 0x5 && ((insn >> 9) & 1)) {
        u32 rd = insn & 0x7;
        u32 rb = (insn >> 3) & 0x7;
        u32 ro = (insn >> 6) & 0x7;
        u32 op = (insn >> 10) & 0x3;
        u32 addr = ctx.regs[rb] + ctx.regs[ro];

        switch (op) {
            case 0: // STRH
                cb->mem_write(addr, ctx.regs[rd], 2);
                break;
            case 1: // LDRSB
                ctx.regs[rd] = (u32)(s32)(s8)cb->mem_read(addr, 1);
                break;
            case 2: // LDRH
                ctx.regs[rd] = cb->mem_read(addr, 2);
                break;
            case 3: // LDRSH
                ctx.regs[rd] = (u32)(s32)(s16)cb->mem_read(addr, 2);
                break;
        }
        return;
    }

    // Format 8: Load/store halfword
    if ((insn >> 12) == 0x8) {
        u32 rd = insn & 0x7;
        u32 rb = (insn >> 3) & 0x7;
        u32 offset = ((insn >> 6) & 0x1F) << 1;
        bool load = (insn >> 11) & 1;
        u32 addr = ctx.regs[rb] + offset;

        if (load)
            ctx.regs[rd] = cb->mem_read(addr, 2);
        else
            cb->mem_write(addr, ctx.regs[rd], 2);
        return;
    }

    // Format 7 (register offset): LDR/STR/LDRB/STRB
    if ((insn >> 12) == 0x5 && ((insn >> 9) & 1) == 0) {
        u32 rd = insn & 0x7;
        u32 rb = (insn >> 3) & 0x7;
        u32 ro = (insn >> 6) & 0x7;
        u32 op = (insn >> 9) & 0x3;
        u32 addr = ctx.regs[rb] + ctx.regs[ro];

        switch (op) {
            case 0: cb->mem_write(addr, ctx.regs[rd], 4); break;
            case 1: cb->mem_write(addr, ctx.regs[rd], 1); break;
            case 2: ctx.regs[rd] = cb->mem_read(addr, 4); break;
            case 3: ctx.regs[rd] = cb->mem_read(addr, 1); break;
        }
        return;
    }

    // SP-relative load/store
    if ((insn >> 12) == 0x9) {
        thumb_load_sp_relative(insn);
        return;
    }

    // Format 9: Load/store with immediate offset (byte)
    if ((insn >> 12) == 0x7) {
        u32 rd = insn & 0x7;
        u32 rb = (insn >> 3) & 0x7;
        u32 offset = (insn >> 6) & 0x1F;
        bool load = (insn >> 11) & 1;
        u32 addr = ctx.regs[rb] + offset;

        if (load)
            ctx.regs[rd] = cb->mem_read(addr, 1);
        else
            cb->mem_write(addr, ctx.regs[rd], 1);
        return;
    }
}

// ============================================================================
// Thumb Load Store Sign Extended
// ============================================================================

void ArmInterpreter::thumb_load_store_sign_extend(u16 insn) {
    u32 rd = insn & 0x7;
    u32 rb = (insn >> 3) & 0x7;
    u32 ro = (insn >> 6) & 0x7;
    u32 op = (insn >> 10) & 0x3;
    u32 addr = ctx.regs[rb] + ctx.regs[ro];

    switch (op) {
        case 0: // STRH
            cb->mem_write(addr, ctx.regs[rd], 2);
            break;
        case 1: // LDRSB
            ctx.regs[rd] = (u32)(s32)(s8)cb->mem_read(addr, 1);
            break;
        case 2: // LDRH
            ctx.regs[rd] = cb->mem_read(addr, 2);
            break;
        case 3: // LDRSH
            ctx.regs[rd] = (u32)(s32)(s16)cb->mem_read(addr, 2);
            break;
    }
}

// ============================================================================
// Thumb PC-Relative Load
// ============================================================================

void ArmInterpreter::thumb_load_pc_relative(u16 insn) {
    // Format 6: LDR Rd, [PC, #imm]
    u32 rd = (insn >> 8) & 0x7;
    u32 imm = (insn & 0xFF) << 2;
    u32 addr = (ctx.regs[15] & ~3) + imm;
    ctx.regs[rd] = cb->mem_read(addr, 4);
}

// ============================================================================
// Thumb SP-Relative Load/Store
// ============================================================================

void ArmInterpreter::thumb_load_sp_relative(u16 insn) {
    u32 rd = (insn >> 8) & 0x7;
    u32 offset = (insn & 0xFF) << 2;
    bool load = (insn >> 11) & 1;
    u32 addr = ctx.regs[13] + offset;

    if (load)
        ctx.regs[rd] = cb->mem_read(addr, 4);
    else
        cb->mem_write(addr, ctx.regs[rd], 4);
}

// ============================================================================
// Thumb Add Offset to SP
// ============================================================================

void ArmInterpreter::thumb_add_offset_to_sp(u16 insn) {
    u32 offset = (insn & 0x7F) << 2;
    bool sub = (insn >> 7) & 1;

    if (sub)
        ctx.regs[13] -= offset;
    else
        ctx.regs[13] += offset;
}

// ============================================================================
// Thumb SWP (not in Thumb; stub)
// ============================================================================

void ArmInterpreter::thumb_swp(u16 insn) {
    // SWP not available in Thumb mode
}

// ============================================================================
// Thumb Push/Pop
// ============================================================================

void ArmInterpreter::thumb_push_pop(u16 insn) {
    bool load = (insn >> 11) & 1;
    bool pclr = (insn >> 8) & 1;
    u32 reglist = insn & 0xFF;

    if (load) {
        // POP
        u32 addr = ctx.regs[13];
        for (int i = 0; i < 8; i++) {
            if (reglist & (1 << i)) {
                ctx.regs[i] = cb->mem_read(addr, 4);
                addr += 4;
            }
        }
        if (pclr) {
            u32 pc = cb->mem_read(addr, 4);
            addr += 4;
            if (pc & 1) {
                ctx.thumb = true;
                ctx.regs[15] = pc & ~1;
            } else {
                ctx.thumb = false;
                ctx.regs[15] = pc;
            }
        }
        ctx.regs[13] = addr;
    } else {
        // PUSH
        u32 num_regs = 0;
        for (int i = 0; i < 8; i++)
            if (reglist & (1 << i)) num_regs++;
        if (pclr) num_regs++;

        u32 addr = ctx.regs[13] - num_regs * 4;
        ctx.regs[13] = addr;

        for (int i = 0; i < 8; i++) {
            if (reglist & (1 << i)) {
                cb->mem_write(addr, ctx.regs[i], 4);
                addr += 4;
            }
        }
        if (pclr) {
            cb->mem_write(addr, ctx.regs[14], 4);
        }
    }
}

// ============================================================================
// Thumb Multiple Load/Store
// ============================================================================

void ArmInterpreter::thumb_multiple_load_store(u16 insn) {
    bool load = (insn >> 11) & 1;
    u32 rb = (insn >> 8) & 0x7;
    u32 reglist = insn & 0xFF;

    u32 addr = ctx.regs[rb];

    for (int i = 0; i < 8; i++) {
        if (reglist & (1 << i)) {
            if (load)
                ctx.regs[i] = cb->mem_read(addr, 4);
            else
                cb->mem_write(addr, ctx.regs[i], 4);
            addr += 4;
        }
    }

    // Writeback only if rb is in the list and it's a store
    if (!load || !(reglist & (1 << rb))) {
        ctx.regs[rb] = addr;
    }
}

// ============================================================================
// Thumb Branch with Exchange
// ============================================================================

void ArmInterpreter::thumb_branch_with_exchange(u16 insn) {
    u32 rs = (insn >> 3) & 0x7;
    u32 addr = ctx.regs[rs];

    if (addr & 1) {
        ctx.thumb = true;
        ctx.regs[15] = addr & ~1;
    } else {
        ctx.thumb = false;
        ctx.regs[15] = addr;
    }
}

// ============================================================================
// Thumb High Register Ops
// ============================================================================

void ArmInterpreter::thumb_high_register_ops(u16 insn) {
    u32 op = (insn >> 8) & 0x3;
    u32 rd = (insn & 0x7) | ((insn >> 4) & 0x8);
    u32 rs = (insn >> 3) & 0xF;

    switch (op) {
        case 0: // ADD
        {
            u32 result = ctx.regs[rd] + ctx.regs[rs];
            ctx.regs[rd] = result;
            break;
        }
        case 1: // CMP
        {
            u32 result = ctx.regs[rd] - ctx.regs[rs];
            ctx.set_nz(result);
            ctx.set_flag_c(ctx.regs[rd] >= ctx.regs[rs]);
            ctx.set_flag_v(((ctx.regs[rd] ^ ctx.regs[rs]) & (ctx.regs[rd] ^ result)) >> 31);
            break;
        }
        case 2: // MOV
            ctx.regs[rd] = ctx.regs[rs];
            break;
        case 3: // BX
        {
            u32 addr = ctx.regs[rs];
            if (addr & 1) {
                ctx.thumb = true;
                ctx.regs[15] = addr & ~1;
            } else {
                ctx.thumb = false;
                ctx.regs[15] = addr;
            }
            break;
        }
    }
}

// ============================================================================
// Thumb Conditional Branch
// ============================================================================

void ArmInterpreter::thumb_conditional_branch(u16 insn) {
    u32 cond = (insn >> 8) & 0xF;
    s32 offset = (s32)(s8)(insn & 0xFF) << 1;

    if (ctx.cond_check(cond)) {
        ctx.regs[15] += offset;
    }
}

// ============================================================================
// Thumb SWI
// ============================================================================

void ArmInterpreter::thumb_swi(u16 insn) {
    ctx.regs[14] = ctx.regs[15] + 2;
    halted = true;
    cb->svc_hook(ctx.regs[15]);
}

// ============================================================================
// Thumb Unconditional Branch
// ============================================================================

void ArmInterpreter::thumb_unconditional_branch(u16 insn) {
    s32 offset = (s32)(s16)((insn & 0x7FF) << 1);
    ctx.regs[15] += offset;
}

// ============================================================================
// Thumb Long Branch with Link
// ============================================================================

void ArmInterpreter::thumb_long_branch_with_link(u16 insn) {
    u32 high = (insn >> 11) & 0x1;

    if (high) {
        // Second instruction: BLX
        u32 offset = (insn & 0x7FF) << 1;
        u32 lr = ctx.regs[14] + offset;
        ctx.regs[14] = (ctx.regs[15] + 2) | 1;
        ctx.regs[15] = lr;
    } else {
        // First instruction: set LR
        s32 offset = (s32)(s8)((insn & 0x7F) << 2) << 3;
        ctx.regs[14] = ctx.regs[15] + offset + 2;
    }
}

// ============================================================================
// Thumb2 Instructions (32-bit Thumb)
// ============================================================================

void ArmInterpreter::execute_thumb2(u32 insn) {
    u16 hw1 = insn >> 16;
    u16 hw2 = insn & 0xFFFF;

    // BL/BLX (T1 encoding)
    if ((hw1 & 0xF800) == 0xF000 && (hw2 & 0xD000) == 0xD000) {
        s32 offset = ((s32)(hw1 & 0x7FF) << 12) | ((s32)(hw2 & 0x7FF) << 1);
        if (offset & 0x100000) offset |= ~0x1FFFFF;
        bool blx = !(hw2 & 0x1000);

        if (blx) {
            ctx.regs[14] = (ctx.regs[15] + 2) | 1;
            u32 target = ctx.regs[15] + offset;
            if (target & 1) {
                ctx.thumb = true;
                target &= ~1;
            } else {
                ctx.thumb = false;
            }
            ctx.regs[15] = target;
        } else {
            ctx.regs[14] = (ctx.regs[15] + 2) | 1;
            ctx.regs[15] += offset;
        }
        return;
    }

    // B.W (T2 encoding)
    if ((hw1 & 0xF800) == 0xF000 && (hw2 & 0xD000) == 0x9000) {
        s32 offset = ((s32)(hw1 & 0x7FF) << 12) | ((s32)(hw2 & 0x3FF) << 1);
        if (offset & 0x100000) offset |= ~0x1FFFFF;
        ctx.regs[15] += offset;
        return;
    }

    // IT (If-Then) - simplified: treat as NOP (only next instruction conditionally executed)
    if ((hw1 & 0xFFF0) == 0xBF00) {
        // IT block - simplified: ignore for now
        return;
    }

    // MRS/MSR (Thumb-2)
    if ((hw1 & 0xFFF0) == 0xF380) {
        u32 rd = hw2 & 0xF;
        if ((hw1 & 0x000F) == 0x0000) {
            // MRS
            ctx.regs[rd] = ctx.cpsr;
        } else if ((hw1 & 0x000F) == 0x0001) {
            // MSR
            ctx.cpsr = ctx.regs[rd];
        }
        return;
    }

    // BLX (T2)
    if ((hw1 & 0xF800) == 0xF000 && (hw2 & 0xD001) == 0xC000) {
        s32 offset = ((s32)(hw1 & 0x7FF) << 12) | ((s32)(hw2 & 0x7FF) << 1);
        if (offset & 0x100000) offset |= ~0x1FFFFF;
        ctx.regs[14] = (ctx.regs[15] + 2) | 1;
        u32 target = ctx.regs[15] + (offset & ~3);
        ctx.thumb = false;
        ctx.regs[15] = target;
        return;
    }

    // DMB/DSB/ISB (barrier instructions - NOP for now)
    if ((hw1 & 0xFFF0) == 0xF3B0) {
        return;
    }

    // Unimplemented Thumb2: skip 4 bytes
}
