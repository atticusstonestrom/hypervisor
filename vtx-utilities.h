#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/io.h>
#include "x64-utilities.h"

#ifndef VT_X_UTILITIES
#define VT_X_UTILITIES


#define VMXON(paddr, rflags)	\
__asm__ __volatile__(		\
	"vmxon %1;"		\
	"pushf;"		\
	"popq %0;"		\
	:"=r"(rflags.val)	\
	:"m"(paddr)		\
	:"memory")

#define VMCLEAR(paddr, rflags)	\
__asm__ __volatile__(		\
	"vmclear %1;"		\
	"pushf;"		\
	"popq %0;"		\
	:"=r"(rflags.val)	\
	:"m"(paddr)		\
	:"memory")

#define VMPTRLD(paddr, rflags)	\
__asm__ __volatile__(		\
	"vmptrld %1;"		\
	"pushf;"		\
	"popq %0;"		\
	:"=r"(rflags.val)	\
	:"m"(paddr)		\
	:"memory")

#define VMLAUNCH __asm__ __volatile__("vmlaunch")
#define VMRESUME __asm__ __volatile__("vmresume")
#define VMXOFF   __asm__ __volatile__("vmxoff")
	

#define VMsucceed(rflags)	(!(rflags).cf && !(rflags).pf && !(rflags).af && !(rflags).zf && !(rflags).sf && !(rflags).of)
#define VMfailInvalid(rflags)	((rflags).cf && !(rflags).pf && !(rflags).af && !(rflags).zf && !(rflags).sf && !(rflags).of)
#define VMfailValid(rflags)	(!(rflags).cf && !(rflags).pf && !(rflags).af && (rflags).zf && !(rflags).sf && !(rflags).of)

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
