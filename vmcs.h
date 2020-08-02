#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/io.h>
#include "vtx-utilities.h"
#include "x64-utilities.h"

#ifndef __VMCS
#define __VMCS

//////////////////////////////
//write ia32_vmx_basic.revision_identifier
//disable shadow vmcs (bit 31)
//check ia32_vmx_ept_vpid_cap for accessed/dirty
//
//
//////////////////////////////


////////////////////////////////////////////////////////
enum VMCS_ENCODINGS {
	VPID=				0x00000000,
	PINV=				0x00000002,	//posted-interrupt notification vector
	EPTP_INDEX=			0x00000004,

	GUEST_ES_SS=			0x00000800,
	GUEST_CS_SS=			0x00000802,
	GUEST_SS_SS=			0x00000804,
	GUEST_DS_SS=			0x00000806,
	GUEST_FS_SS=			0x00000808,
	GUEST_GS_SS=			0x0000080a,
	GUEST_LDTR_SS=			0x0000080c,
	GUEST_TR_SS=			0x0000080e,

	GUEST_INTERRUPT_STATUS=		0x00000810,
	PML_INDEX=			0x00000812,

	HOST_ES_SS=			0x00000c00,
	HOST_CS_SS=			0x00000c02,
	HOST_SS_SS=			0x00000c04,
	HOST_DS_SS=			0x00000c06,
	HOST_FS_SS=			0x00000c08,
	HOST_GS_SS=			0x00000c0a,
	HOST_TR_SS=			0x00000c0c,

	IO_BMP_A_F=			0x00002000,
	IO_BMP_A_H=			0x00002001,
	IO_BMP_B_F=			0x00002002,
	IO_BMP_B_H=			0x00002003,

	MSR_BMP_ADDR_F=			0x00002004,
	MSR_BMP_ADDR_H=			0x00002005,

	EXIT_MSR_STR_ADDR_F=		0x00002006,
	EXIT_MSR_STR_ADDR_H=		0x00002007,
	EXIT_MSR_LD_ADDR_F= 		0x00002008,
	EXIT_MSR_LD_ADDR_H= 		0x00002009,
	ENTRY_MSR_LD_ADDR_F=		0x0000200a,
	ENTRY_MSR_LD_ADDR_H=		0x0000200b,

	EXECUTIVE_VMCS_PTR_F=		0x0000200c,
	EXECUTIVE_VMCS_PTR_H=		0x0000200d,

	PML_ADDR_F=			0x0000200e,
	PML_ADDR_H=			0x0000200f,

	TSC_OFFSET_F=			0x00002010,
	TSC_OFFSET_H=			0x00002011,

	VAPIC_ADDR_F=			0x00002012,	//virtual apic
	VAPIC_ADDR_H=			0x00002013,	//virtual apic
	APICA_ADDR_F=			0x00002014,	//apic access
	APICA_ADDR_H=			0x00002015,	//apic access

	PIDA_F=				0x00002016,	//posted-interrupt descriptor address
	PIDA_H=				0x00002017,	//posted-interrupt descriptor address

	VMFUNC_CTRLS_F=			0x00002018,
	VMFUNC_CTRLS_H=			0x00002019,

	EPTP_F=				0x0000201a,
	EPTP_H=				0x0000201b,

	EOI_EXIT0_F=			0x0000201c,
	EOI_EXIT0_H=			0x0000201d,
	EOI_EXIT1_F=			0x0000201e,
	EOI_EXIT1_H=			0x0000201f,
	EOI_EXIT2_F=			0x00002020,
	EOI_EXIT2_H=			0x00002021,
	EOI_EXIT3_F=			0x00002022,
	EOI_EXIT3_H=			0x00002023,

	EPTP_LIST_ADDR_F=		0x00002024,
	EPTP_LIST_ADDR_H=		0x00002025,

	VMREAD_BMP_ADDR_F=		0x00002026,
	VMREAD_BMP_ADDR_H=		0x00002027,
	VMWRITE_BMP_ADDR_F=		0x00002028,
	VMWRITE_BMP_ADDR_H=		0x00002029,

	VE_INFO_ADDR_F=			0x0000202a,	//virtualization exception
	VE_INFO_ADDR_F=			0x0000202b,	//virtualization exception

	XSS_EXITING_BMP_F=		0x0000202c,
	XSS_EXITING_BMP_F=		0x0000202d,

	ENCLS_EXITING_BMP_F=		0x0000202e,
	ENCLS_EXITING_BMP_H=		0x0000202f,

	SPPT_PTR_F=			0x00002030,	//sub-page-permission-table pointer
	SPPT_PTR_H=			0x00002031,	//sub-page-permission-table pointer

	TSC_MULTIPLIER_F=		0x00002032,
	TSC_MULTIPLIER_H=		0x00002033,

	ENCLS_EXITING_BMP_F=		0x00002036,
	ENCLS_EXITING_BMP_H=		0x00002037,

	GUEST_PADDR_F=			0x00002400,
	GUEST_PADDR_H=			0x00002401,

	VMCS_LINK_PTR_F=		0x00002800,
	VMCS_LINK_PTR_H=		0x00002801,

	GUEST_IA32_DEBUGCTL_F=		0x00002802,
	GUEST_IA32_DEBUGCTL_H=		0x00002803,
	GUEST_IA32_PAT_F=		0x00002804,
	GUEST_IA32_PAT_H=		0x00002805,
	GUEST_IA32_EFER_F=		0x00002806,
	GUEST_IA32_EFER_H=		0x00002807,

	GUEST_IA32_PERF_GLOBAL_CTRL_F=	0x00002808,
	GUEST_IA32_PERF_GLOBAL_CTRL_H=	0x00002809,

	GUEST_PDPTE0_F=			0x000280a,
	GUEST_PDPTE0_H=			0x000280b,
	GUEST_PDPTE1_F=			0x000280c,
	GUEST_PDPTE1_H=			0x000280d,
	GUEST_PDPTE2_F=			0x000280e,
	GUEST_PDPTE2_H=			0x000280f,
	GUEST_PDPTE3_F=			0x0002810,
	GUEST_PDPTE3_H=			0x0002811,
	GUEST_IA32_BNDCFGS_F=		0x00002812,
	GUEST_IA32_BNDCFGS_H=		0x00002813,
	GUEST_IA32_RTIT_CTL_F=		0x00002814,
	GUEST_IA32_RTIT_CTL_H=		0x00002815,
	GUEST_IA32_PKRS_F=		0x00002818,
	GUEST_IA32_PKRS_H=		0x00002819,
	
	HOST_IA32_PAT_F=		0x00002c00,
	HOST_IA32_PAT_H=		0x00002c01,
	HOST_IA32_EFER_F=		0x00002c02,
	HOST_IA32_EFER_H=		0x00002c03,
	HOST_IA32_PERF_GLOBAL_CTRL_F=	0x00002c04,
	HOST_IA32_PERF_GLOBAL_CTRL_H=	0x00002c05,
	HOST_IA32_PKRS_F=		0x00002c06,
	HOST_IA32_PKRS_H=		0x00002c07,
	
	PIN_BASED_EXECUTION_CTLS
typedef union __attribute__((packed)) {
	struct __attribute__((packed)) {
		unsigned int access_type:1;	//0=full, 1=high
		unsigned int index:9;
		unsigned int type:2;
			#define VMCS_TYPE_CONTROL	0
			#define VMCS_TYPE_EXIT_INFO	1
			#define VMCS_TYPE_GUEST_STATE	2
			#define VMCS_TYPE_HOST_STATE	3
		unsigned int rsv_12:1;		//must be 0
		unsigned int width:2;
			#define VMCS_WIDTH_16		0
			#define VMCS_WIDTH_32		1
			#define VMCS_WIDTH_64		2
			#define VMCS_WIDTH_NATURAL	3
		unsigned int rsv_15_31:17; };	//must be 0
	unsigned int val;
} vmcs_component_encoding;
////////////////////////////////////////////////////////

////////////////////////////////////////////////////////
void initialize_vpcs(unsigned long vmcs) {
	*(unsigned int *)vmcs &= 0x7fffffff;	//not a shadow vmcs
	
////////////////////////////////////////////////////////

////////////////////////////////////////////////////////

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


typedef struct {
	
	//for reserved bits, consult
	//ia32_vmx_pinbased_ctls
	//ia32_vmx_true_pinbased_ctls
	struct __attribute__((packed)) {
		unsigned int external_interrupt_exiting:1;
		unsigned int rsv_1_2:2;
		unsigned int nmi_exiting:1;
		unsigned int rsv_4:1;
		unsigned int virtual_nmis:1;
		unsigned int preemption_timer_active:1;
		unsigned int process_posted_interrupts:1;
		unsigned int rsv_8_31:24; }
		pin_based_execution_controls;

	//for reserved bits, consult
	//ia32_vmx_procbased_ctls
	//ia32_vmx_true_procbased_ctls
	struct __attribute__((packed)) {
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
		unsigned int activate_secondary_controls:1; }
	primary_cpu_based_execution_controls;

	//all bits reserved to zero
	//for bits settable to 1, consult
	//ia32_vmx_procbased_ctls2
	struct __attribute__((packed)) {
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
		unsigned int rsv_26_31:6; }
		secondary_cpu_based_execution_controls;

	struct __attribute__((packed)) {
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
		unsigned int rsv_22_31:10; }
		exception_bitmap;

	struct {
		unsigned long io_bitmap_a;	//ports 0000 to 7fff
		unsigned long bitmap_a_paddr;
		unsigned long io_bitmap_b;	//ports 8000 to ffff
		unsigned long bitmap_b_paddr; }
		io_bitmap_addrs;

	struct {
		unsigned long tsc_offset;
		unsigned long tsc_multiplier; }
		tsc_fields;

	struct {
		unsigned long cr0_mask;
		unsigned long cr0_shadow;
		unsigned long cr4_mask;
		unsigned long cr4_shadow; }
		cr_masks_and_shadows;

	//read ia32_vmx_misc for supported count
	struct {
		unsigned int cr3_target_count;
		unsigned long cr3_target_0;
		unsigned long cr3_target_1;
		unsigned long cr3_target_2;
		unsigned long cr3_target_3; }
		cr3_target_controls;

	struct {
		unsigned long apic_access_page;
		unsigned long apic_access_paddr;

		unsigned long virtual_apic_page;
		unsigned long virtual_apic_paddr;

		unsigned int tpr_threshold;

		unsigned long eoi_exit0;
		unsigned long eoi_exit1;
		unsigned long eoi_exit2;
		unsigned long eoi_exit3;

		unsigned short posted_interrupt_notification_vector;
		unsigned long posted_interrupt_descriptor_addr; }
		apic_virtualization_controls;

	struct {
		//read bitmap for low msrs	00000000 to 00001fff
		//read bitmap for high msrs	c0000000 to c0001fff
		//write bitmap for low msrs
		//write bitmap for high msrs
		unsigned long msr_bitmap_addr;
		unsigned long msr_bitmap_paddr; }
		msr_bitmap_controls;

	unsigned long executive_vmcs_pointer;

	//consult ia32_vmx_ept_vpid_cap
	//to determine whether accessed/
	//dirty flags are supported
	eptp_t eptp;

	unsigned short virtual_processor_identifier;

	struct {
		unsigned int ple_gap;
		unsigned int ple_window; }
	pause_loop_exiting_controls;

	//for reserved bits, consult
	//ia32_vmx_vmfunc
	//all reserved bits reserved to 0
	struct __attribute__((packed)) {
		unsigned long eptp_switching:1;
		unsigned long rsv_1_63:63; }
		vm_function_controls;

	struct {
		unsigned long vmread_bitmap_addr;
		unsigned long vmread_bitmap_paddr;
		unsigned long vmwrite_bitmap_addr;
		unsigned long vmwrite_bitmap_paddr; }
	vmcs_shadowing_bitmaps;

	unsigned long encls_exiting_bitmap;
	
	unsigned long page_modification_log;			//paddr?
	
	struct {
		unsigned long virtualization_exception_info_area;
		unsigned long virtualization_exception_info_paddr;
		unsigned short eptp_index; }
	virtualization_exception_controls;
	
	unsigned long xss_exiting_bitmap;
} vm_execution_controls;

typedef struct {
	//for reserved bits, consult
	//ia32_vmx_exit_ctls
	//ia32_vmx_true_exit_ctls
	struct __attribute__((packed)) {
		unsigned int rsv_0_1:2;
		unsigned int save_dbg_controls:1;
		unsigned int rsv_3_8:6;
		unsigned int host_addr_space_size:1;
		unsigned int rsv_10_11:2;
		unsigned int load_ia32_perf_global_ctrl:1;
		unsigned int rsv_13_14:2;
		unsigned int acknowledge_interrupt:1;
		unsigned int rsv_16_17:2;
		unsigned int save_ia32_pat:1;
		unsigned int load_ia32_pat:1;
		unsigned int save_ia32_efer:1;
		unsigned int load_ia32_efer:1;
		unsigned int save_preemption_timer:1;
		unsigned int clear_ia32_bndcfgs:1;
		unsigned int conceal_vm_exits:1;
		unsigned int rsv_25_31:7; }
		vm_exit_controls;
	
	struct {
		struct __attribute__((packed)) {
			unsigned int msr_index;
			unsigned int rsv_32_63;
			unsigned long msr_data; }
			msr_entry;
		//ia32_vmx_misc gives maximum supported count
		//section 27.4
		unsigned int msr_store_count;
		unsigned long msr_store_addr;
		unsigned long msr_store_paddr;
		
		//section 27.6
		unsigned int msr_load_count;
		unsigned long msr_load_addr;
		unsigned long msr_load_paddr;
	} msr_entry_controls;
} vm_exit_control_fields;


typedef struct {
	//for reserved bits, consult
	//ia32_vmx_entry_ctls
	//ia32_vmx_true_entry_ctls
	struct __attribute__((packed)) {
		unsigned int rsv_0_1:2;
		unsigned int load_dbg_controls:1;
		unsigned int rsv_3_8:6;
		unsigned int ia_32e_mode_guest:1;
		unsigned int entry_to_smm:1;
		unsigned int deactivate_dual_monitor_treatment:1;
		unsigned int rsv_12:1;
		unsigned int load_ia32_perf_global_ctrl:1;
		unsigned int load_ia32_pat:1;
		unsigned int load_ia32_efer:1;
		unsigned int load_ia32_bndcfgs:1;
		unsigned int conceal_vm_entries:1;
		unsigned int rsv_18_31:14; }
		vm_entry_controls;
	
	struct {
		//ia32_vmx_misc gives maximum supported count
		//section 26.4
		unsigned int msr_load_count;
		unsigned long msr_load_addr;
		unsigned long msr_load_paddr;
	} msr_entry_controls;
	
	struct {
		struct __attribute__((packed)) {
			unsigned int vector:8;
			unsigned int type:3;
				//external interrupt:	0
				//nmi:			2
				//hardware exception:	3
				//software interrupt:	4
				//privilege sw except:	5
				//software exception:	6
				//other event:		7
			unsigned int deliver_error_code:1;
			unsigned int rsv_12_30:19;	//set to 0??
			unsigned int valid:1; }
			vm_entry_interruption_info;
		
		unsigned int vm_entry_exception_error_code;
		unsigned int vm_entry_instruction_length;
	} event_injection_entry_controls;
} vm_entry_control_fields;

typedef struct {
	struct {
		struct __attribute__((packed)) {
			unsigned int basic_exit_reason:16;	//appendix C
			unsigned int rsv_16_26:11;	//must be 0
			unsigned int enclave_incident:1;
			unsigned int pending_mtf_vm_exit:1;
			unsigned int vmx_root_exit:1;
			unsigned int rsv_30:1;		//must be 0
			unsigned int vm_entry_failure:1; }
			exit_reason;

		unsigned long exit_qualification;	//section 27.2.1
		unsigned long guest_linear_addr;
		unsigned long guest_paddr;
	} basic_vm_exit_info;
	
	struct {
		struct __attribute__((packed)) {
			unsigned int vector:8;
			unsigned int type:3;
				//external interrupt:	0
				//nmi:			2
				//hardware exception:	3
				//software exception:	6
			unsigned int error_code_valid:1;
			unsigned int iret_nmi_unblocking:1;
			unsigned int rsv_13_30:18;	//set to 0
			unsigned int valid:1; }
			vm_exit_interruption_info;

		unsigned int interruption_error_code;
	} vector_vm_exit_info;
	
	struct {
		struct __attribute__((packed)) {
			unsigned int vector:8;
			unsigned int type:3;
				//external interrupt:	0
				//nmi:			2
				//hardware exception:	3
				//software interrupt:	4
				//privilege sw except:	5
				//software exception:	6
			unsigned int error_code_valid:1;
			unsigned int rsv_12_30:19;	//set to 0
			unsigned int valid:1; }
			idt_vectoring_info;
		
		unsigned int idt_vectoring_error_code;
	} event_delivery_vm_exit_info;
	
	struct {
		unsigned int instruction_length;
		unsigned int instruction_info;	//27.2.4
		
		unsigned long io_rcx;
		unsigned long io_rsi;
		unsigned long io_rdi;
		unsigned long io_rip;
	} instruction_execution_vm_exit_info;
	
	unsigned int vm_instruction_error_field;
} vm_exit_information_fields;

////////////////////////////////////////////////////////

#endif
