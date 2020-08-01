#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/io.h>
#include "vtx-utilities.h"
#include "x64-utilities.h"

#ifndef __VMCS
#define __VMCS


typedef struct {
	unsigned long cr0;
	unsigned long cr3;
	unsigned long cr4;
	unsigned long dr7;
	unsigned long rsp;
	unsigned long rip;
	unsigned long rflags;
	
	struct __attribute__((packed)) {
		unsigned int segment_type:4;
		unsigned int s:1;	//descriptor type. 0=system, 1=code_or_data
		unsigned int dpl:2;
		unsigned int p:1;
		unsigned int rsv_8_11:4;
		unsigned int avl:1;
		unsigned int l:1;	//64 bit mode active (for only CS)
		unsigned int db:1;	//default operation size: 0=16 bit segment, 1=32 bit segment
		unsigned int g:1;	//granularity
		unsigned int unusable:1;
		unsigned int rsv_17_31:15; }
		access_rights;

	unsigned short cs_selector;
	unsigned long cs_base;
	unsigned int cs_lim;
	unsigned int cs_access_rights;
	
	unsigned short ss_selector;
	unsigned long ss_base;
	unsigned int ss_lim;
	unsigned int ss_access_rights;
	
	unsigned short ds_selector;
	unsigned long ds_base;
	unsigned int ds_lim;
	unsigned int ds_access_rights;
	
	unsigned short es_selector;
	unsigned long es_base;
	unsigned int es_lim;
	unsigned int es_access_rights;
	
	unsigned short fs_selector;
	unsigned long fs_base;
	unsigned int fs_lim;
	unsigned int fs_access_rights;
	
	unsigned short gs_selector;
	unsigned long gs_base;
	unsigned int gs_lim;
	unsigned int gs_access_rights;
	
	unsigned short ldtr_selector;
	unsigned long ldtr_base;
	unsigned int ldtr_lim;
	unsigned int ldtr_access_rights;
	
	unsigned short tr_selector;
	unsigned long tr_base;
	unsigned int tr_lim;
	unsigned int tr_access_rights;
	
	gdtr_t gdtr;
	idtr_t idtr;
	
	msr_t ia32_debugctl;
	msr_t ia32_sysenter_cs;
	msr_t ia32_sysenter_esp;
	msr_t ia32_sysenter_eip;
	msr_t ia32_perf_global_ctrl;
	msr_t ia32_pat;
	msr_t ia32_efer;
	msr_t ia32_bndcfgs;

	unsigned int smbase;

	////////////////////////////////////////////////
	
	unsigned int activity_state;
		//active, HLT, shutdown, wait-for-sipi
	
	struct __attribute__((packed)) {
		unsigned int sti:1;
		unsigned int mov_ss:1;
		unsigned int smi:1;
		unsigned int nmi:1;
		unsigned int enclave_interruption:1;
		unsigned int rsv_5_31:27; }	//must be 0
		interruptibility_state;
	
	struct __attribute__((packed)) {
		unsigned long b0_b3:4;
		unsigned long rsv_4_11:8;	//must be 0
		unsigned long enabled_bp:1;
		unsigned long rsv_13:1;		//must be 0
		unsigned long bs:1;
		unsigned long rsv_15:1;		//must be 0
		unsigned long rtm:1;
		unsigned long rsv_17_63:47; }	//must be 0
		pending_dbg_exceptions;
	
	unsigned long vmcs_link_pointer;	//for vmcs shadowing
	unsigned int preemption_timer;
	unsigned long pdpte0;
	unsigned long pdpte1;
	unsigned long pdpte2;
	unsigned long pdpte3;

	struct __attribute__((packed)) {
		unsigned char rvi;	//rewuesting virtual interrupt
		unsigned char svi; }	//servicing virtual interrupt
		guest_interrupt_status;
	
	unsigned short pml_index;
} guest_state_area;

typedef struct {
	unsigned long cr0;
	unsigned long cr3;
	unsigned long cr4;
	unsigned long rsp;
	unsigned long rip;
	
	struct __attribute__((packed)) {
		unsigned int segment_type:4;
		unsigned int s:1;	//descriptor type. 0=system, 1=code_or_data
		unsigned int dpl:2;
		unsigned int p:1;
		unsigned int rsv_8_11:4;
		unsigned int avl:1;
		unsigned int l:1;	//64 bit mode active (for only CS)
		unsigned int db:1;	//default operation size: 0=16 bit segment, 1=32 bit segment
		unsigned int g:1;	//granularity
		unsigned int unusable:1;
		unsigned int rsv_17_31:15; }
		access_rights;

	unsigned short cs_selector;
	unsigned short ss_selector;
	unsigned short ds_selector;
	unsigned short es_selector;
	
	unsigned short fs_selector;
	unsigned long fs_base;
	
	unsigned short gs_selector;
	unsigned long gs_base;
	
	unsigned short tr_selector;
	unsigned long tr_base;
	
	unsigned long gdtr_base;
	unsigned long idtr_base;
	
	msr_t ia32_sysenter_cs;
	msr_t ia32_sysenter_esp;
	msr_t ia32_sysenter_eip;
	msr_t ia32_perf_global_ctrl;
	msr_t ia32_pat;
	msr_t ia32_efer;
} host_state_area;

//for reserved bits, consult
//ia32_vmx_pinbased_ctls
//ia32_vmx_true_pinbased_ctls
typedef struct __attribute__((packed)) {
	unsigned int external_interrupt_exiting:1;
	unsigned int rsv_1_2:2;
	unsigned int nmi_exiting:1;
	unsigned int rsv_4:1;
	unsigned int virtual_nmis:1;
	unsigned int preemption_timer_active:1;
	unsigned int process_posted_interrupts:1;
	unsigned int rsv_8_31:24;
} pin_based_execution_controls;

//for reserved bits, consult
//ia32_vmx_procbased_ctls
//ia32_vmx_true_procbased_ctls
typedef struct __attribute__((packed)) {
	unsigned int rsv_0_1:2;
	unsigned int interrupt_window_exiting:1;
	unsigned int use_tsc_offsetting:1;
	unsigned int rsv_4_6:3;
	unsigned int hlt_exiting:1;
	unsigned int rsv_8:1;
	unsigned int invlpg_exiting:1;
	unsigned int mwait_exiting:1;
	unsigned int rdpmc_exiting:1;
	unsigned int rdtsc_exiting:1;
	unsigned int rsv_13_14:2;
	unsigned int cr3_load_exiting:1;
	unsigned int cr3_store_exiting:1;
	unsigned int rsv_17_18:2;
	unsigned int cr8_load_exiting:1;
	unsigned int cr8_store_exiting:1;
	unsigned int use_tpr_shadow:1;
	unsigned int nmi_window_exiting:1;
	unsigned int mov_dr_exiting:1;
	unsigned int unconditional_io_exiting:1;
	unsigned int use_io_bitmaps:1;
	unsigned int rsv_26:1;
	unsigned int monitor_trap_flag:1;
	unsigned int use_msr_bitmaps:1;
	unsigned int monitor_exiting:1;
	unsigned int pause_exiting:1;
	unsigned int activate_secondary_controls:1;
} primary_cpu_based_execution_controls;

//for reserved bits, consult
//ia32_vmx_procbased_ctls2
typedef struct __attribute__((packed)) {
	unsigned int virtualize_apic_accesses:1;
	unsigned int enable_ept:1;
	unsigned int descriptor_table_exiting:1;
	unsigned int enable_rdtscp:1;
	unsigned int virtualize_x2apic_mode:1;
	unsigned int enable_vpid:1;
	unsigned int wbinvd_exiting:1;
	unsigned int unrestricted_guest:1;
	unsigned int apic_register_virtualization:1;
	unsigned int virtual_interrupt_delivery:1;
	unsigned int pause_loop_exiting:1;
	unsigned int rdrand_exiting:1;
	unsigned int enable_invpcid:1;
	unsigned int enable_vm_functions:1;
	unsigned int vmcs_shadowing:1;
	unsigned int enable_encls_exiting:1;
	unsigned int rdseed_exiting:1;
	unsigned int enable_pml:1;
	unsigned int ept_violation_ve:1;
	unsigned int conceal_vmx_nonroot:1;
	unsigned int enable_xsaves_srstors:1;
	unsigned int rsv_21:1;
	unsigned int mode_based_x_control_ept:1;
	unsigned int rsv_23_24:2;
	unsigned int use_tsc_scaling:1;
	unsigned int rsv_26_31:6;
} secondary_cpu_based_execution_controls;

typedef struct __attribute__((packed)) {
	unsigned int zd:1;
	unsigned int single_step:1;
	unsigned int nmi:1;
	unsigned int bp:1;
	unsigned int overflow:1;
	unsigned int bounds:1;
	unsigned int invalid_opcode:1;
	unsigned int coprocessor_not_available:1;
	unsigned int double_fault:1;
	unsigned int rsv_9:1;
	unsigned int invalid_tss:1;
	unsigned int segment_not_present:1;
	unsigned int stack_fault:1;
	unsigned int gp:1;
	unsigned int pf:1;
	unsigned int rsv_15:1;
	unsigned int math_fault:1;
	unsigned int alignment_check:1;
	unsigned int machine_check:1;
	unsigned int simd_fp_exception:1;
	unsigned int ve:1;
	unsigned int control_protection_exception:1;
	unsigned int rsv_22_31:10;
} exception_bitmap;

#endif
