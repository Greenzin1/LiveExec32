#pragma once

#include <array>
#include <vector>

#include "khash.h"
#include "filesystem.h"
#include "32bit.h"
#include "arm_interpreter.h"

// TSB (thread local variables)
#define ARM_REG_C13_C0_3 113
#define ARM_REG_SP 13
#define ARM_REG_PC 15

#define PAGE_TABLE_ADDRESS_SPACE_BITS 36
#define DYN_PAGE_BITS 12 // 4k
#define DYN_PAGE_SIZE (1ULL << DYN_PAGE_BITS)
#define DYN_PAGE_MASK (DYN_PAGE_SIZE-1)
#define UC_PROT_WRITE 2

#define ALIGN_DYN_SIZE(len) (((DYN_PAGE_SIZE-1)&len) ? ((len+DYN_PAGE_SIZE) & ~(DYN_PAGE_SIZE-1)):len)
#define ALIGN_SIZE(len) (((PAGE_SIZE-1)&len) ? ((len+PAGE_SIZE) & ~(PAGE_SIZE-1)):len)

#define DYLD_PROCESS_INFO_NOTIFY_LOAD_ID 0x1000
#define DYLD_PROCESS_INFO_NOTIFY_UNLOAD_ID 0x2000
#define DYLD_PROCESS_INFO_NOTIFY_MAIN_ID 0x3000

// cpsr flags
#define A32_BIT 4
#define THUMB_BIT 5
#define NEGATIVE_BIT 31
#define ZERO_BIT 30
#define CARRY_BIT 29
#define OVERFLOW_BIT 28
#define MODE_MASK 0x1f

#define PRE_CALLBACK_SYSCALL_NUMBER 0x8866
#define POST_CALLBACK_SYSCALL_NUMBER 0x8888
#define DARWIN_SWI_SYSCALL 0x80

#define LC32HaltReasonSVC 1
#define LC32HaltReasonRetFromGuest 2

struct guest_file_mapping {
    const char *name;
    uint64_t hostAddr;
    uint32_t start;
    uint32_t end;
};
extern int guestMappingLen;
extern guest_file_mapping guestMappings[1000];

typedef struct memory_page {
  void *addr;
  int perms;
} *t_memory_page;

KHASH_MAP_INIT_INT64(memory, t_memory_page)

using Vector = std::array<std::uint64_t, 2>;

typedef struct context32 {
  std::array<std::uint32_t, 16> regs;
  std::array<std::uint32_t, 64> extRegs;
  std::uint32_t cpsr;
  std::uint32_t fpscr;
  std::uint32_t uro;
} *t_context32;


#include "arm_dynarmic_cp15.h"

// Compatibility class that wraps our interpreter
class DynarmicCpsr {
public:
    DynarmicCpsr(ArmInterpreter *interp)
        : cpu{interp} {}

    bool hasBit(int offset) {
        return ((cpu->ctx.cpsr >> offset) & 1) == 1;
    }

    void setBit(int offset) {
        int mask = 1 << offset;
        cpu->ctx.cpsr = cpu->ctx.cpsr | mask;
    }

    void clearBit(int offset) {
        int mask = ~(1 << offset);
        cpu->ctx.cpsr = cpu->ctx.cpsr & mask;
    }

    bool isA32() { return hasBit(A32_BIT); }
    bool isThumb() { return hasBit(THUMB_BIT); }
    bool isNegative() { return hasBit(NEGATIVE_BIT); }
    void setNegative(bool on) { on ? setBit(NEGATIVE_BIT) : clearBit(NEGATIVE_BIT); }
    bool isZero() { return hasBit(ZERO_BIT); }
    void setZero(bool on) { on ? setBit(ZERO_BIT) : clearBit(ZERO_BIT); }
    bool hasCarry() { return hasBit(CARRY_BIT); }
    void setCarry(bool on) { on ? setBit(CARRY_BIT) : clearBit(CARRY_BIT); }
    bool isOverflow() { return hasBit(OVERFLOW_BIT); }
    void setOverflow(bool on) { on ? setBit(OVERFLOW_BIT) : clearBit(OVERFLOW_BIT); }
    int getMode() { return cpu->ctx.cpsr & MODE_MASK; }
    int getEL() { return (cpu->ctx.cpsr >> 2) & 3; }

    ArmInterpreter *cpu;
};

__BEGIN_DECLS

// Forward declarations
char *get_memory_page(u64 vaddr);
void *get_memory(u64 vaddr);

static inline u8 mem_read8(u32 vaddr) {
    u8 *dest = (u8 *)get_memory(vaddr);
    return dest ? *dest : 0;
}
static inline u16 mem_read16(u32 vaddr) {
    if(vaddr & 1) return (u16)mem_read8(vaddr) | ((u16)mem_read8(vaddr+1) << 8);
    u16 *dest = (u16 *)get_memory(vaddr);
    return dest ? *dest : 0;
}
static inline u32 mem_read32(u32 vaddr) {
    if(vaddr & 3) return (u32)mem_read16(vaddr) | ((u32)mem_read16(vaddr+2) << 16);
    u32 *dest = (u32 *)get_memory(vaddr);
    return dest ? *dest : 0;
}
static inline u64 mem_read64(u32 vaddr) {
    if(vaddr & 7) return (u64)mem_read32(vaddr) | ((u64)mem_read32(vaddr+4) << 32);
    u64 *dest = (u64 *)get_memory(vaddr);
    return dest ? *dest : 0;
}
static inline void mem_write8(u32 vaddr, u8 val) {
    u8 *dest = (u8 *)get_memory(vaddr);
    if(dest) *dest = val;
}
static inline void mem_write16(u32 vaddr, u16 val) {
    if(vaddr & 1) { mem_write8(vaddr, val); mem_write8(vaddr+1, val>>8); return; }
    u16 *dest = (u16 *)get_memory(vaddr);
    if(dest) *dest = val;
}
static inline void mem_write32(u32 vaddr, u32 val) {
    if(vaddr & 3) { mem_write16(vaddr, val); mem_write16(vaddr+2, val>>16); return; }
    u32 *dest = (u32 *)get_memory(vaddr);
    if(dest) *dest = val;
}
static inline void mem_write64(u32 vaddr, u64 val) {
    if(vaddr & 7) { mem_write32(vaddr, val); mem_write32(vaddr+4, val>>32); return; }
    u64 *dest = (u64 *)get_memory(vaddr);
    if(dest) *dest = val;
}

class DynarmicCallbacks32;
typedef struct {
  khash_t(memory) *memory;
  size_t num_page_table_entries;
  void **page_table;
  DynarmicCallbacks32 *cb;
  LC32Filesystem *fs;
  u32 guest_dlsym, guest_LC32InvokeGuestC;
  dyld_all_image_infos_32 *dyld_info_section;
} dynarmic;

typedef struct {
  ArmInterpreter *interp;
  DynarmicCpsr *cpsr;
} dynarmic_thread;

// Handles
extern dynarmic sharedHandle;
extern __thread dynarmic_thread threadHandle;

char *get_memory_page(u64 vaddr);
void *get_memory(u64 vaddr);

bool Dynarmic_nativeInitialize();
void Dynarmic_nativeDestroy();
int Dynarmic_munmap(u64 address, u64 size);
u32 Dynarmic_direct_mmap(u32 address, u32 size, int protection, int flags, void *src, u64 off);
u32 Dynarmic_mmap(u32 address, u32 size, int protection, int flags, int fildes, u64 off, u64 mask = DYN_PAGE_MASK);
int Dynarmic_mprotect(u64 address, u64 size, int perms);
int Dynarmic_mem_1write(u64 address, u64 size, char* src);
int Dynarmic_mem_1read(u64 address, u64 size, char* dest);
int Dynarmic_reg_1write(int index, u32 value);
u32 Dynarmic_reg_1read(int index);
int Dynarmic_reg_1read_1cpsr();
int Dynarmic_reg_1write_1cpsr(int value);
int Dynarmic_reg_1write_1c13_1c0_13(int value);
int Dynarmic_emu_1start(u32 pc);
int Dynarmic_emu_1stop();
void* Dynarmic_context_1alloc();
void Dynarmic_context_1restore(t_context32 ctx);
void Dynarmic_context_1save(t_context32 ctx);
void Dynarmic_free(void *ctx);

u64 LC32Dlsym(u32 guest_name, bool isFunction);
u64 LC32GetHostObject(u32 guest_self, u32 guest_class, bool returnClass);
u64 LC32GetHostSelector(u32 guest_selector);
u64 LC32InvokeHostSelector(u64 host_self, u64 host_cmd, u64 va_args);
u32 LC32HostToGuestCopyClassName(u32 guest_output, size_t length, u64 host_object);

__END_DECLS

#define U64_MASK (sizeof(u64)-1)
class DynarmicGuestStackString {
public:
    ~DynarmicGuestStackString() {
        threadHandle.interp->ctx.regs[13] += totalLen;
    }

    DynarmicGuestStackString(const char *hostPtr) {
        totalLen = (strlen(hostPtr) + 1 + U64_MASK) &~ U64_MASK;
        guestPtr = (threadHandle.interp->ctx.regs[13] -= totalLen);
        Dynarmic_mem_1write(guestPtr, totalLen, (char *)hostPtr);
    }

    u32 guestPtr;
    size_t totalLen;
};

#define DynarmicHostString_NEED_FREE (1ull << 63)
class DynarmicHostString {
public:
    ~DynarmicHostString() {
        if(shouldFree) {
            if(dirty) {
                Dynarmic_mem_1write(guestPtr, totalLen, hostPtr);
            }
            free(hostPtr);
        }
    }

    DynarmicHostString(u32 guestPtr, u32 len = 0) : dirty{false}, guestPtr{guestPtr} {
         char *dest = (char *)get_memory(guestPtr);
         if(!dest) { abort(); }

         totalLen = len ?: strlen(dest);
         u32 pageOff = guestPtr & DYN_PAGE_MASK;
         shouldFree = pageOff + totalLen >= DYN_PAGE_SIZE;
         if(!shouldFree) {
             hostPtr = dest;
         } else {
             if(!len) {
                 totalLen = DYN_PAGE_SIZE - pageOff;
                 for(u64 vaddr = (guestPtr - pageOff) + DYN_PAGE_SIZE;; vaddr += DYN_PAGE_SIZE) {
                     char *page = get_memory_page(vaddr);
                     if(!page) abort();
                     size_t len = strlen(page);
                     totalLen += len;
                     if(len < DYN_PAGE_SIZE) break;
                 }
             }
             hostPtr = (char *)malloc(totalLen + 1);
             hostPtr[totalLen] = '\0';
             Dynarmic_mem_1read(guestPtr, totalLen, hostPtr);
        }
    }

    const char *hostPtrForGuest() {
        if(shouldFree) {
            hostPtr = (char *)((u64)hostPtr | DynarmicHostString_NEED_FREE);
        }
        shouldFree = false;
        return hostPtr;
    }

    char *hostPtrForWriting() {
        dirty = true;
        return hostPtr;
    }

    bool shouldFree, dirty;
    size_t totalLen;
    u32 guestPtr;
    char *hostPtr;
};
