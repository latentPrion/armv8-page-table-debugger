/*
 * Copyright 2017, Data61
 * Commonwealth Scientific and Industrial Research Organisation (CSIRO)
 * ABN 41 687 119 230.
 *
 * This software may be distributed and modified according to the terms of
 * the GNU General Public License version 2. Note that NO WARRANTY is provided.
 * See "LICENSE_GPLv2.txt" for details.
 *
 * @TAG(DATA61_GPL)
 */

#include <config.h>
#include <model/statedata.h>
#include <arch/fastpath/fastpath.h>
#include <arch/kernel/traps.h>
#include <api/syscall.h>
#include <linker.h>
#include <machine/fpu.h>

#include <benchmark/benchmark_track.h>
#include <benchmark/benchmark_utilisation.h>

bool_t s1_l0_l2_entry_is_ok(uint64_t entry, int rwx, bool_t *is_leaf);
bool_t
s1_l0_l2_entry_is_ok(uint64_t entry, int rwx, bool_t *is_leaf)
{
    assert(is_leaf != NULL);
    *is_leaf = 0;

    // Present bit.
    if (!(entry & BIT(0))) {
        userError("s1: Entry is not present.");
        return 0;
    }

    // Check block bit.
    if (!(entry & BIT(1))) {
        *is_leaf = 1;
        return 1;
    }

    return 1;
}

/* ARMv8 manual: D4.3.3:
 * "Table descriptors for stage 2 translations do not include any attribute 
 * field."
 */
bool_t s2_l0_l2_entry_is_ok(uint64_t entry, int rwx, bool_t *is_leaf);
bool_t
s2_l0_l2_entry_is_ok(uint64_t entry, int rwx, bool_t *is_leaf)
{
    assert(is_leaf != NULL);
    *is_leaf = 0;

    // Present bit.
    if ((entry & BIT(0)) == 0) {
        userError("s2: Entry is not present.");
    }

    // Check for block address (large page).
    if ((entry & BIT(1)) == 0) {
        *is_leaf = 1;
        return 1;
    }

    // Always return true since there's nothing else to validate.
    return 1;
}

bool_t s2_block_entry_is_ok(uint64_t entry, int rwx);
bool_t
s2_block_entry_is_ok(uint64_t entry, int rwx)
{
    // TODO: Implement me.
    return 0;
}

bool_t s2_l3_entry_is_ok(uint64_t entry, int rwx);
bool_t
s2_l3_entry_is_ok(uint64_t entry, int rwx)
{
    // Check that bit 1 is set on leaf entries (must be 1 at leaf).
    if ((entry & BIT(1)) == 0) {
        userError("ERR: L3 leaf table doesn't have bit1 set.");
        return 0;
    }

    if ((entry & BIT(0)) == 0) {
        userError("ERR: Entry is not present.");
        return 0;
    }

    // Reserved bits.
    assert((entry & BIT(11)) == 0);

    // Get s2ap;
    word_t s2ap = (entry >> 6) & 3;
    // Get XN;
    word_t xn = (entry >> 53) & 3;

    if (rwx & 4) {
        if (s2ap == 2) {
            userError("s2: entry is readable but s2ap is %lu", s2ap);
            return 0;
        }
    }
    if (rwx & 2) {
        // If s2AP == readonly, error.
        if (s2ap == 0 || s2ap == 1) {
            userError("s2: entry is writeable but s2ap is %lu", s2ap);
            return 0;
        }
        // We don't care about PXN. Only UXN/XN.
        if ((xn & 1) == 0) {
            userError("WARN: entry is writeable but XN is %lu", xn);
        }
    }
    // rw
    if (rwx == 6) {
        if (s2ap != 3) {
            userError("s2: entry is read-write but s2ap is %lu", s2ap);
            return 0;
        }
        // We don't care about PXN. Only UXN/XN.
        if ((xn & 1) == 0) {
            userError("WARN: entry is writeable but XN is %lu", xn);
        }
    }
    if (rwx & 1) {
    }
    // rx
    if (rwx == 5) {
        if (s2ap == 2 || s2ap == 3) {
            userError("s2: entry is read-exec but s2ap is %lu", s2ap);
            return 0;
        }
        // We don't care about PXN. Only UXN/XN.
        if ((xn & 1) == 1) {
            userError("WARN: entry is read-exec but XN is %lu", xn);
        }
    }

    return 1;
}

/* Simulates a walk from the current pt root. */
typedef struct _walk_ret {
    uint64_t vroot_paddr, *vroot_pptr;
    int l0_idx, l1_idx, l2_idx, l3_idx;
    uint64_t l0_entry, l1_entry, l2_entry, l3_entry;
    int error;
    word_t page_size_bits;
} walk_ret_t;

walk_ret_t walk_s2(void *vaddr, int rwx, bool_t vroot_is_el1,
                   uint64_t *vroot_pptr_to_compare_against);
walk_ret_t
walk_s2(void *vaddr, int rwx, bool_t vroot_is_el1,
        uint64_t *vroot_pptr_to_compare_against)
{
    /* Assumes 4K translation granularity. */
    const int BITS_PER_LVL_MASK = 0x7F;
    walk_ret_t r;
    bool_t is_leaf;
    word_t vaddr_i = (word_t)vaddr;

    r.page_size_bits = seL4_PageBits;

    // Not supported yet.
    assert(!vroot_is_el1);

    asm volatile ("mrs %0, vttbr_el2\n": "=r" (r.vroot_paddr));
    // Unset the bits for VMID and CnP.
    r.vroot_paddr &= ~(0xFFFF000000000000 | BIT(0));
    assert((r.vroot_paddr & 0xFFF) == 0);

    r.vroot_pptr = paddr_to_pptr(r.vroot_paddr);

    if (vroot_pptr_to_compare_against != 0) {
        if (r.vroot_pptr != vroot_pptr_to_compare_against) {
            userError("The Vspace loaded in TTBR is not the one the user "
                      "intended to walk! User desired vspace is %lx, but "
                      "TTBR contains %llx.",
                      pptr_to_paddr(vroot_pptr_to_compare_against),
                      r.vroot_paddr);

            r.error = -2;
            return r;
        }
    }

    r.l0_idx = (vaddr_i >> (12 + 9 + 9 + 9)) & BITS_PER_LVL_MASK;
    r.l1_idx = (vaddr_i >> (12 + 9 + 9)) & BITS_PER_LVL_MASK;
    r.l2_idx = (vaddr_i >> (12 + 9)) & BITS_PER_LVL_MASK;
    r.l3_idx = (vaddr_i >> (12)) & BITS_PER_LVL_MASK;

    // Index to get l1.
    r.l0_entry = r.vroot_pptr[r.l0_idx];

    // Validate r.l0_entry bits.
    if (!s2_l0_l2_entry_is_ok(r.l0_entry, rwx, &is_leaf)) {
        r.error = -1; return r;
    }
    if (is_leaf) {
        if (!s2_block_entry_is_ok(r.l0_entry, rwx)) {
            r.error = -1; return r;
        }
        // Exit early, page size is 512GiB.
        r.page_size_bits = 12+9+9+9;
        r.error = 0; return r;
    }

    // Extract l1 table paddr:
    uint64_t l1_paddr, *l1_pptr;
    l1_paddr = r.l0_entry & 0xFFFFFFFFFFFFF000;
    l1_pptr = paddr_to_pptr(l1_paddr);

    r.l1_entry = l1_pptr[r.l1_idx];

    // Validate r.l1_entry bits.
    if (!s2_l0_l2_entry_is_ok(r.l1_entry, rwx, &is_leaf)) {
        r.error = 1; return r;
    }
    if (is_leaf) {
        if (!s2_block_entry_is_ok(r.l0_entry, rwx)) {
            r.error = -1; return r;
        }
        // Exit early, page size is 512GiB.
        r.page_size_bits = 12+9+9;
        r.error = 0; return r;
    }

    // Extract l2 table paddr:
    uint64_t l2_paddr, *l2_pptr;
    l2_paddr = r.l1_entry & 0xFFFFFFFFFFFFF000;
    l2_pptr = paddr_to_pptr(l2_paddr);

    r.l2_entry = l2_pptr[r.l2_idx];

    // Validate r.l2_entry bits.
    if (!s2_l0_l2_entry_is_ok(r.l2_entry, rwx, &is_leaf)) {
        r.error = 2; return r;
    }
    if (is_leaf) {
        if (!s2_block_entry_is_ok(r.l0_entry, rwx)) {
            r.error = -1; return r;
        }
        // Exit early, page size is 512GiB.
        r.page_size_bits = 12+9;
        r.error = 0; return r;
    }

    // Extract l3 table paddr:
    uint64_t l3_paddr, *l3_pptr;
    l3_paddr = r.l2_entry & 0xFFFFFFFFFFFFF000;
    l3_pptr = paddr_to_pptr(l3_paddr);

    r.l3_entry = l3_pptr[r.l3_idx];

    // Validate r.l3_entry bits.
    if (!s2_l3_entry_is_ok(r.l3_entry, rwx)) {
        r.error = 3; return r;
    }

    r.page_size_bits = 12;
    r.error = 0;
    return r;
}

word_t ats12e1r(word_t vaddr);
word_t ats12e1r(word_t vaddr)
{
    word_t par_el1;

    asm volatile("at s12e1r, %0\n"
		"mrs %1, par_el1\n"
		: "=r" (par_el1)
		: "r"(vaddr));

    return par_el1;
}

/** DONT_TRANSLATE */
void VISIBLE NORETURN restore_user_context(void)
{
    NODE_UNLOCK_IF_HELD;

cleanInvalidateL1Caches(); 
invalidateLocalTLB(); 
if (config_set(CONFIG_ARM_HYPERVISOR_SUPPORT)) { 
invalidateHypTLB(); 
}
    c_exit_hook();

if (NODE_STATE(ksCurThread)->tcbArch.tcbVCPU != NULL) {
//word_t elr_el2;
//asm volatile("mrs %0, elr_el2\n\t":"=r"(elr_el2));
//word_t spsr_el2;
//asm volatile("mrs %0, spsr_el2\n\t":"=r"(elr_el2));
walk_ret_t w;

cap_t threadRoot;
pgde_t *pgd;
threadRoot = TCB_PTR_CTE_PTR(NODE_STATE(ksCurThread), tcbVTable)->cap;
pgd = PGD_PTR(cap_page_global_directory_cap_get_capPGDBasePtr(threadRoot));

w = walk_s2((void*)NODE_STATE(ksCurThread)->tcbArch.tcbContext.registers[ELR_EL1],
            4+1, 0, (uint64_t *)pgd);

userError("Switching to VCPU thread: faultInstr is %lx, ELR_EL1 is %lx, spsr is %lx, SP is %lx. ATS12e1r: %lx, ATS1SE2: %lx.",
	NODE_STATE(ksCurThread)->tcbArch.tcbContext.registers[FaultInstruction],
	NODE_STATE(ksCurThread)->tcbArch.tcbContext.registers[ELR_EL1],
	NODE_STATE(ksCurThread)->tcbArch.tcbContext.registers[SPSR_EL1],
	NODE_STATE(ksCurThread)->tcbArch.tcbContext.registers[SP_EL0],
	ats12e1r(NODE_STATE(ksCurThread)->tcbArch.tcbContext.registers[ELR_EL1]),
	ats1e2r(NODE_STATE(ksCurThread)->tcbArch.tcbContext.registers[ELR_EL1]));

userError("Walk result: err=%d; l0_ent %llx, l1_ent %llx, l2_ent %llx, l3_ent %llx.\n",
    w.error, w.l0_entry, w.l1_entry, w.l2_entry, w.l3_entry);

} else {
/*
userError("Switching to NATIVE thread: FaultInstr is %lx, ats12e1 is %lx, ats1e2 is %lx.",
	NODE_STATE(ksCurThread)->tcbArch.tcbContext.registers[FaultInstruction],
	ats12e1r(NODE_STATE(ksCurThread)->tcbArch.tcbContext.registers[ELR_EL1]),
	ats1e2r(NODE_STATE(ksCurThread)->tcbArch.tcbContext.registers[ELR_EL1]));
*/
}

#ifdef CONFIG_HAVE_FPU
    lazyFPURestore(NODE_STATE(ksCurThread));
#endif /* CONFIG_HAVE_FPU */

    writeTPIDRURW(getRegister(NODE_STATE(ksCurThread), TPIDRURW));

    asm volatile(
        "mov     sp, %0                     \n"

        /* Restore thread's SPSR, LR, and SP */
        "ldp     x21, x22, [sp, %[SP_EL0]] \n"
        "ldr     x23, [sp, %[SPSR_EL1]]    \n"
        "msr     sp_el0, x21                \n"
#ifdef CONFIG_ARM_HYPERVISOR_SUPPORT
        "msr     elr_el2, x22               \n"
        "msr     spsr_el2, x23              \n"
#else
        "msr     elr_el1, x22               \n"
        "msr     spsr_el1, x23              \n"
#endif
        /* Restore remaining registers */
        "ldp     x0,  x1,  [sp, #16 * 0]    \n"
        "ldp     x2,  x3,  [sp, #16 * 1]    \n"
        "ldp     x4,  x5,  [sp, #16 * 2]    \n"
        "ldp     x6,  x7,  [sp, #16 * 3]    \n"
        "ldp     x8,  x9,  [sp, #16 * 4]    \n"
        "ldp     x10, x11, [sp, #16 * 5]    \n"
        "ldp     x12, x13, [sp, #16 * 6]    \n"
        "ldp     x14, x15, [sp, #16 * 7]    \n"
        "ldp     x16, x17, [sp, #16 * 8]    \n"
        "ldp     x18, x19, [sp, #16 * 9]    \n"
        "ldp     x20, x21, [sp, #16 * 10]   \n"
        "ldp     x22, x23, [sp, #16 * 11]   \n"
        "ldp     x24, x25, [sp, #16 * 12]   \n"
        "ldp     x26, x27, [sp, #16 * 13]   \n"
        "ldp     x28, x29, [sp, #16 * 14]   \n"
        "ldr     x30, [sp, %[LR]]          \n"
        "eret"
        :
        : "r" (NODE_STATE(ksCurThread)->tcbArch.tcbContext.registers),
        [SP_EL0] "i" (PT_SP_EL0), [SPSR_EL1] "i" (PT_SPSR_EL1), [LR] "i" (PT_LR)
        : "memory"
    );
    UNREACHABLE();
}
