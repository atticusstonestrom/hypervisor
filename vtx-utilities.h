#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/io.h>
#include "x64-utilities.h"

#ifndef VT_X_UTILITIES
#define VT_X_UTILITIES


#define VMXON(paddr, lhf)	\
__asm__ __volatile__(		\
	"vmxon %1;"		\
	"lahf;"			\
	"shr $8, %%rax;"	\
	"movb %%al, %0;"	\
	:"=r"(lhf.val)		\
	:"m"(paddr)		\
	:"rax", "memory")

#define VMCLEAR(paddr, lhf)	\
__asm__ __volatile__(		\
	"vmclear %1;"		\
	"lahf;"			\
	"shr $8, %%rax;"	\
	"movb %%al, %0;"	\
	:"=r"(lhf.val)		\
	:"m"(paddr)		\
	:"rax", "memory")

#define VMPTRLD(paddr, lhf)	\
__asm__ __volatile__(		\
	"vmptrld %1;"		\
	"lahf;"			\
	"shr $8, %%rax;"	\
	"movb %%al, %0;"	\
	:"=r"(lhf.val)		\
	:"m"(paddr)		\
	:"rax", "memory")

#define VMWRITE(src, code, lhf)	\
__asm__ __volatile__(		\
	"vmwrite %1, %2;"	\
	"lahf;"			\
	"shr $8, %%rax;"	\
	"movb %%al, %0;"	\
	:"=r"(lhf.val)		\
	:"r"((long)(src)),	\
	 "r"((long)(code))	\
	:"rax", "memory")

#define VMREAD(dst, code, lhf)	\
__asm__ __volatile__(		\
	"vmread %2, %%rbx;"	\
	"lahf;"			\
	"shr $8, %%rax;"	\
	"movb %%al, %0;"	\
	:"=r"(lhf.val),		\
	 "=b"(dst)		\
	:"r"((long)(code))	\
	:"rax", "memory")

#define VMLAUNCH(lhf)		\
__asm__ __volatile__(		\
	"vmlaunch;"		\
	"lahf;"			\
	"shr $8, %%rax;"	\
	"movb %%al, %0;"	\
	:"=r"(lhf.val)		\
	::"rax", "memory")

#define VMRESUME(lhf)		\
__asm__ __volatile__(		\
	"vmresume;"		\
	"lahf;"			\
	"shr $8, %%rax;"	\
	"movb %%al, %0;"	\
	:"=r"(lhf.val)		\
	::"rax", "memory")

#define VMXOFF   __asm__ __volatile__("vmxoff")


//lower half flags
//much better performance
//than pushf/popf
typedef union __attribute__((packed)) {
	struct __attribute__((packed)) {
		unsigned char cf:1;
		unsigned char rsv_1:1;
		unsigned char pf:1;
		unsigned char rsv_3:1;
		unsigned char af:1;
		unsigned char rsv_5:1;
		unsigned char zf:1;
		unsigned char sf:1; };
	unsigned char val;
} lhf_t;

#define VMsucceed(lhf)		(!(lhf).cf && !(lhf).zf)
#define VMfailInvalid(lhf)	((lhf).cf && !(lhf).zf)
#define VMfailValid(lhf)	(!(lhf).cf && (lhf).zf)
////////////////////////////////////////////////////////
enum vm_instruction_error_numbers {
	VMCALL_VMX_ROOT =	1,
	VMCLEAR_INVL_PADDR =	2,
	VMCLEAR_VMXON_PTR =	3,
	VMLAUNCH_LAUNCH_VMCS =	4,
	VMRESUME_CLEAR_VMCS =	5,
	VMRESUME_AFTER_VMXOFF =	6,
	VMENTRY_INVL_CTLS =	7,
	VMENTRY_INVL_HOST =	8,
	VMPTRLD_INVL_PADDR =	9,
	VMPTRLD_VMXON_PTR =	10,
	VMPTRLD_WRONG_REV_ID =	11,
	VMRW_BAD_ENCODING =	12,
	VMWRITE_TO_READ_ONLY =	13,
	VMXON_VMX_ROOT =	15,
	VM_ENTRY_INVL_EV_PTR =	16,	//executive vmcs
	VM_ENTRY_CLEAR_EV_PTR =	17,
	VM_ENTRY_EV_NOT_VMXON =	18,
	VMCALL_LAUNCH_VMCS =	19,
	VMCALL_INVL_CTLS =	20,
	VMCALL_BAD_MSEG_ID =	22,
	VMXOFF_DUAL_MONITOR =	23,
	VMCALL_INVL_SMM =	24,
	VM_ENTRY_INVL_CTLS_EV =	25,
	VM_ENTRY_MOV_SS =	26,
	INVL_INV_OP =		28 };	//invept,invvpid
////////////////////////////////////////////////////////

typedef union __attribute__((packed)) {
	struct __attribute__((packed)) {
		unsigned long caching_type:3;
		unsigned long page_walk_length:3;	//minus 1
		unsigned long accessed_dirty_control:1;
		unsigned long rsv_7_11:5;
		unsigned long pml4_addr:40;	//bits 12 to 51
		unsigned long rsv_52_63:12; };
	unsigned long val;
} eptp_t;

typedef union __attribute__((packed)) {
	struct __attribute__((packed)) {
		unsigned long r:1;
		unsigned long w:1;
		unsigned long x:1;
		unsigned long caching_type:3;
		unsigned long ignore_pat:1;
		unsigned long page_size:1;
		unsigned long accessed:1;
		unsigned long dirty:1;
		unsigned long ux:1;	//user-mode x access
		unsigned long rsv_11:1;
		unsigned long addr:40;
		unsigned long rsv_52_62:11; 
		unsigned long suppress_ve:1; };
	struct __attribute__((packed)) {
		unsigned long rsv_4kb_0_11:12;
		unsigned long addr_4kb:40;	//bits 12 to 51
		unsigned long rsv_4kb_52_63:12; };
	struct __attribute__((packed)) {
		unsigned long rsv_1gb_0_29:30;
		unsigned long addr_1gb:22;	//bits 30 to 51
		unsigned long rsv_1gb_52_63:12; };
	struct __attribute__((packed)) {
		unsigned long rsv_2mb_0_20:21;
		unsigned long addr_2mb:31;	//bits 21 to 51
		unsigned long rsv_2mb_52_63:12; };
	unsigned long val;
} epse_t;


#endif
