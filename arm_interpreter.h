#pragma once

#include <cstdint>
#include <cstring>
#include <functional>

typedef int8_t s8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

// Memory access callbacks
class ArmCallbacks {
public:
    virtual ~ArmCallbacks() = default;
    virtual u32 mem_read(u32 addr, int size) = 0;
    virtual void mem_write(u32 addr, u32 value, int size) = 0;
    virtual void svc_hook(u32 pc) = 0;
};

struct ArmContext {
    u32 regs[16];    // R0-R15 (R13=SP, R14=LR, R15=PC)
    u32 cpsr;
    u32 fpscr;
    u32 extRegs[64]; // VFP/Neon registers
    bool thumb;

    // CPSR flag helpers
    bool flag_n() const { return (cpsr >> 31) & 1; }
    bool flag_z() const { return (cpsr >> 30) & 1; }
    bool flag_c() const { return (cpsr >> 29) & 1; }
    bool flag_v() const { return (cpsr >> 28) & 1; }

    void set_flag_n(bool v) { cpsr = (cpsr & ~(1u<<31)) | ((u32)v << 31); }
    void set_flag_z(bool v) { cpsr = (cpsr & ~(1u<<30)) | ((u32)v << 30); }
    void set_flag_c(bool v) { cpsr = (cpsr & ~(1u<<29)) | ((u32)v << 29); }
    void set_flag_v(bool v) { cpsr = (cpsr & ~(1u<<28)) | ((u32)v << 28); }

    void set_nz(u32 result) {
        set_flag_n(result >> 31);
        set_flag_z(result == 0);
    }

    bool cond_check(u32 cond) const {
        bool n = flag_n(), z = flag_z(), c = flag_c(), v = flag_v();
        switch (cond & 0xE) {
            case 0x0: return z;
            case 0x2: return c;
            case 0x4: return n;
            case 0x6: return v;
            case 0x8: return c && !z;
            case 0xA: return (n == v);
            case 0xC: return !z && (n == v);
            case 0xE: return true;
        }
        switch (cond) {
            case 0x1: return !z;
            case 0x3: return !c;
            case 0x5: return !n;
            case 0x7: return !v;
            case 0x9: return !c || z;
            case 0xB: return (n != v);
            case 0xD: return z || (n != v);
            case 0xF: return false;
        }
        return true;
    }
};

class ArmInterpreter {
public:
    ArmContext ctx;
    ArmCallbacks *cb;
    bool running;
    bool halted;

    ArmInterpreter() : cb(nullptr), running(false), halted(false) {
        memset(&ctx, 0, sizeof(ctx));
    }

    void set_callbacks(ArmCallbacks *callbacks) { cb = callbacks; }

    void reset() {
        memset(&ctx.regs, 0, sizeof(ctx.regs));
        ctx.cpsr = 0x1D3; // System mode, IRQ/FIQ disabled
        ctx.thumb = false;
        running = false;
        halted = false;
    }

    // Execute from PC until SVC or halted
    void execute(u32 start_pc);

    // Single step - returns true if should continue
    bool step();

private:
    // Instruction decode & execute
    void execute_arm(u32 insn);
    void execute_thumb(u16 insn);
    void execute_thumb2(u32 insn);

    // ARM data processing
    void arm_data_processing(u32 insn);
    void arm_multiply(u32 insn);
    void arm_multiply_long(u32 insn);
    void arm_single_data_transfer(u32 insn);
    void arm_halfword_data_transfer(u32 insn);
    void arm_block_data_transfer(u32 insn);
    void arm_branch(u32 insn);
    void arm_branch_exchange(u32 insn);
    void arm_status_transfer(u32 insn);
    void arm_coprocessor_data_transfer(u32 insn);
    void arm_coprocessar_data_operation(u32 insn);
    void arm_coprocessar_register_transfer(u32 insn);
    void arm_mrs(u32 insn);
    void arm_msr(u32 insn);
    void arm_swi(u32 insn);
    void arm_clz(u32 insn);
    void arm_bxj(u32 insn);
    void arm_blx_imm(u32 insn);
    void arm_saturation(u32 insn);
    void arm_misc(u32 insn);

    // Thumb data processing
    void thumb_data_processing(u16 insn);
    void thumb_load_store(u16 insn);
    void thumb_load_store_sign_extend(u16 insn);
    void thumb_load_pc_relative(u16 insn);
    void thumb_load_sp_relative(u16 insn);
    void thumb_add_offset_to_sp(u16 insn);
    void thumb_swp(u16 insn);
    void thumb_push_pop(u16 insn);
    void thumb_multiple_load_store(u16 insn);
    void thumb_branch_with_exchange(u16 insn);
    void thumb_high_register_ops(u16 insn);
    void thumb_conditional_branch(u16 insn);
    void thumb_swi(u16 insn);
    void thumb_unconditional_branch(u16 insn);
    void thumb_long_branch_with_link(u16 insn);

    // ALU operations
    u32 alu_adc(u32 a, u32 b, bool carry_in);
    u32 alu_sbc(u32 a, u32 b, bool carry_in);
    u32 alu_rsc(u32 a, u32 b, bool carry_in);
    u32 alu_rrx(u32 val);

    // Barrel shifter
    u32 shift_reg(u32 val, u32 shift_type, u32 amount, bool &carry_out);
    u32 decode_imm_shift(u32 insn, bool &carry_out);

    // CP15 registers (simplified)
    u32 cp15_read(u32 reg);
    void cp15_write(u32 reg, u32 val);
};
