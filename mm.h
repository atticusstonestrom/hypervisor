#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/io.h>

#ifndef MEM_MANAGE
#define MEM_MANAGE
#include "x64-utilities.h"
#include "vtx-utilities.h"
#include "hvc.h"

#define MTRR_MSR_ID(paddr)		\
({if( (unsigned)(paddr)<0x80000 ) {	\
	IA32_MTRR_FIX64K_00000; }	\
else if( (unsigned)(paddr)<0xa0000 ) {	\
	IA32_MTRR_FIX16K_80000; }	\
else if( (unsigned)(paddr)<0xc0000 ) {	\
	IA32_MTRR_FIX16K_A0000; }	\
else if( (unsigned)(paddr)<0xc80000 ) {	\
	IA32_MTRR_FIX4K_C0000; }	\
else if( (unsigned)(paddr)<0xd00000 ) {	\
	IA32_MTRR_FIX4K_C8000; }	\
else if( (unsigned)(paddr)<0xd80000 ) {	\
	IA32_MTRR_FIX4K_D0000; }	\
else if( (unsigned)(paddr)<0xe0000 ) {	\
	IA32_MTRR_FIX4K_D8000; }	\
else if( (unsigned)(paddr)<0xe80000 ) {	\
	IA32_MTRR_FIX4K_E0000; }	\
else if( (unsigned)(paddr)<0xf0000 ) {	\
	IA32_MTRR_FIX4K_E8000; }	\
else if( (unsigned)(paddr)<0xf8000 ) {	\
	IA32_MTRR_FIX4K_F0000; }	\
else if( (unsigned)(paddr)<0x100000 ) {	\
	IA32_MTRR_FIX4K_F8000; }	\
else {					\
	0; }})

/*#define MTRR_INDEX(paddr) \
({if( (paddr)<0x80000 ) {		\
	((paddr)&0xf0000)>>16; }	\
else if( (paddr)<0xa0000 ) {			\	don't need to and	\
	( ((paddr)-0x80000) & 0xff000 )>>14; }	\	????	\
else if( (paddr)<0xc0000 ) {			\
	( ((paddr)-0xa0000) & 0xf0000 )>>14; }	\*/
	
#define get_caching_type(paddr, msr)			\
({if( (unsigned)(paddr)>0xfffff ) { 0xff; }		\
else {	READ_MSR(msr, MTRR_MSR_ID(paddr));		\
	msr.mtrr_fixed.entries[MTRR_INDEX(paddr)]; }})

static void check_msrrs(void) {
	int i=0;
	int vcnt;
	cpuid_t cpuid;
	msr_t msr;
	CPUID(cpuid, 0x80000008);
	printk("[*] maxphyaddr: %d\n", cpuid.leaf_80000008.maxphyaddr);
	CPUID(cpuid, 1);
	if(cpuid.leaf_1.mtrr) {
		printk("[*] mtrrs enabled\n"); }
	else {
		return; }
	if(cpuid.leaf_1.pat) {
		printk("[*] pat enabled\n"); }
	READ_MSR(msr, IA32_MTRRCAP);
	printk("[*] mtrrcap: 0x%lx\n", msr.val);
	vcnt=msr.mtrrcap.vcnt;
	if(msr.mtrrcap.fix) {
		READ_MSR(msr, IA32_MTRR_FIX64K_00000);
		printk("fix64k_00000: 0x%lx\n", msr.val);
		READ_MSR(msr, IA32_MTRR_FIX16K_80000);
		printk("fix16k_80000: 0x%lx\n", msr.val);
		READ_MSR(msr, IA32_MTRR_FIX16K_A0000);
		printk("fix16k_a0000: 0x%lx\n", msr.val);
		READ_MSR(msr, IA32_MTRR_FIX4K_C0000);
		printk("fix4k_c0000: 0x%lx\n", msr.val);
		READ_MSR(msr, IA32_MTRR_FIX4K_C8000);
		printk("fix4k_c8000: 0x%lx\n", msr.val);
		READ_MSR(msr, IA32_MTRR_FIX4K_D0000);
		printk("fix4k_d0000: 0x%lx\n", msr.val);
		READ_MSR(msr, IA32_MTRR_FIX4K_D8000);
		printk("fix4k_d8000: 0x%lx\n", msr.val);
		READ_MSR(msr, IA32_MTRR_FIX4K_E0000);
		printk("fix4k_e0000: 0x%lx\n", msr.val);
		READ_MSR(msr, IA32_MTRR_FIX4K_E8000);
		printk("fix4k_e8000: 0x%lx\n", msr.val);
		READ_MSR(msr, IA32_MTRR_FIX4K_F0000);
		printk("fix4k_f0000: 0x%lx\n", msr.val);
		READ_MSR(msr, IA32_MTRR_FIX4K_F8000);
		printk("fix4k_f8000: 0x%lx\n", msr.val); }
	READ_MSR(msr, IA32_MTRR_DEF_TYPE);
	printk("[*] mtrr_def_type: 0x%lx\n", msr.val);
	for(i=0; i<vcnt; i++) {
		READ_MSR(msr, IA32_MTRR_PHYSBASE(i));
		printk("[*] physbase%d: 0x%lx\n", i, msr.val);
		READ_MSR(msr, IA32_MTRR_PHYSMASK(i));
		printk("[*] physmask%d: 0x%lx\n", i, msr.val); }
	return; }

static int alloc_wb_page(unsigned long *vaddr, unsigned long *paddr) {
	msr_t msr;
	READ_MSR(msr, IA32_PAT);
	
	vtp_t vtp_s=(vtp_t){0};
	int ret=0;
	*vaddr=get_zeroed_page(GFP_KERNEL);
	if(!(*vaddr)) {
		//printk("[*]  no free page available\n");
		return -ENOMEM; }
	//printk("[**] page:\t0x%lx\n", *vaddr);
	if( (ret=vtp(*vaddr, paddr, &vtp_s)) ) {
		//printk("[*]  vtp failed\n");
		return ret; }
	/*if(vtp_s.pml5e_p) {
		printk("[**] &pml5e:\t0x%px\n", vtp_s.pml5e_p);
		printk("[**] pml5e:\t0x%lx\n", *(unsigned long *)(vtp_s.pml5e_p)); }
	if(vtp_s.pml4e_p) {
		printk("[**] &pml4e:\t0x%px\n", vtp_s.pml4e_p);
		printk("[**] pml4e:\t0x%lx\n", *(unsigned long *)(vtp_s.pml4e_p)); }
	if(vtp_s.pdpte_p) {
		printk("[**] &pdpte:\t0x%px\n", vtp_s.pdpte_p);
		printk("[**] pdpte:\t0x%lx\n", *(unsigned long *)(vtp_s.pdpte_p)); }
	if(vtp_s.pde_p) {
		printk("[**] &pde:\t0x%px\n", vtp_s.pde_p);
		printk("[**] pde:\t0x%lx\n", *(unsigned long *)(vtp_s.pde_p)); }
	if(vtp_s.pte_p) {
		printk("[**] &pte:\t0x%px\n", vtp_s.pte_p);
		printk("[**] pte:\t0x%lx\n", *(unsigned long *)(vtp_s.pte_p)); }
	printk("[**] paddr:\t0x%lx\n", *paddr);
	printk("[*]  allocated successfully\n\n");*/
	
	//printk("[*]  checking caching type\n");
	if(vtp_s.pte_p) {
		/*printk("[**] 4kb page\n");
		printk("[**] pat:\t%d\n", vtp_s.pte_p->pat_4kb);
		printk("[**] pcd:\t%d\n", vtp_s.pte_p->pcd);
		printk("[**] pwt:\t%d\n", vtp_s.pte_p->pwt);
		printk("[**] pat type:\t0x%02x\n",
		       msr.pat.entries[4*vtp_s.pte_p->pat_4kb+2*vtp_s.pte_p->pcd+vtp_s.pte_p->pwt]);*/
		if(vtp_s.pte_p->pcd || vtp_s.pte_p->pwt) {
			DISABLE_RW_PROTECTION;
			vtp_s.pte_p->pcd=0;
			vtp_s.pte_p->pwt=0;
			ENABLE_RW_PROTECTION;
			/*printk("[**] new pte:\t0x%lx\n", *(unsigned long *)vtp_s.pte_p);
			printk("[**] invalidating tlb\n");*/
			INVLPG(*vaddr); }}
	else if(vtp_s.pde_p) {
		/*printk("[**] 2mb page\n");
		printk("[**] pat: %d\n", vtp_s.pde_p->pat_2mb);
		printk("[**] pcd: %d\n", vtp_s.pde_p->pcd);
		printk("[**] pwt: %d\n", vtp_s.pde_p->pwt);
		printk("[**] current cache type: 0x%x\n",
		       msr.pat.entries[4*vtp_s.pde_p->pat_2mb+2*vtp_s.pde_p->pcd+vtp_s.pde_p->pwt]);*/
		if(vtp_s.pde_p->pcd || vtp_s.pde_p->pwt) {
			DISABLE_RW_PROTECTION;
			vtp_s.pde_p->pcd=0;
			vtp_s.pde_p->pwt=0;
			ENABLE_RW_PROTECTION;
			/*printk("[**] new pte:\t0x%lx\n", *(unsigned long *)vtp_s.pde_p);
			printk("[**] invalidating tlb\n");*/
			INVLPG(*vaddr); }}
	else if(vtp_s.pdpte_p) {
		/*printk("[**] 1gb page\n");
		printk("[**] pat: %d\n", vtp_s.pdpte_p->pat_1gb);
		printk("[**] pcd: %d\n", vtp_s.pdpte_p->pcd);
		printk("[**] pwt: %d\n", vtp_s.pdpte_p->pwt);
		printk("[**] current cache type: 0x%x\n",
		       msr.pat.entries[4*vtp_s.pdpte_p->pat_1gb+2*vtp_s.pdpte_p->pcd+vtp_s.pdpte_p->pwt]);*/
		if(vtp_s.pdpte_p->pcd || vtp_s.pdpte_p->pwt) {
			DISABLE_RW_PROTECTION;
			vtp_s.pdpte_p->pcd=0;
			vtp_s.pdpte_p->pwt=0;
			ENABLE_RW_PROTECTION;
			/*printk("[**] new pte:\t0x%lx\n", *(unsigned long *)vtp_s.pdpte_p);
			printk("[**] invalidating tlb\n");*/
			INVLPG(*vaddr); }}
	//else {	//vtp must have failed
	//printk("[*]  caching type set to writeback\n\n");
	return ret; }

typedef struct pt_node {
	struct pt_node *next;
	unsigned long base;
} pt_node;
typedef struct {
	eptp_t eptp;
	unsigned long pml4;
	unsigned long pdpt;
	struct {
		unsigned long base;
		unsigned int order; }
		pds;
	pt_node *pts;
} ept_data_t;

void free_ept(ept_data_t *ept) {
	if(ept->pml4) {
		gprint("pml4:\t\t0x%lx", ept->pml4);
		free_page(ept->pml4);
		ept->pml4=0; }
	
	if(ept->pdpt) {
		gprint("pdpt:\t\t0x%lx", ept->pdpt);
		free_page(ept->pdpt);
		ept->pdpt=0; }
	
	if(ept->pds.base) {
		gprint("pd memory pool:\t0x%lx (%d pages)", ept->pds.base, 1<<ept->pds.order);
		free_pages(ept->pds.base, ept->pds.order);
		ept->pds.base=0; }
	
	pt_node *next=NULL;
	while(ept->pts!=NULL) {
		gprint("pt node:\t\t\t0x%px", ept->pts);
		gprint("\tpt page:\t0x%lx", ept->pts->base);
		free_page(ept->pts->base);
		
		next=(ept->pts)->next;
		kfree(ept->pts);
		ept->pts=next; }
	
	ept->eptp.pml4_addr=0;
	return; }



//make initialize
//and allocate
//different


//~1gb for each page directory
static int allocate_ept(ept_data_t *data) {
	unsigned char maxphyaddr=32;
	//number of pdptes required:	(1<<maxphyaddr)>>30;
	//number of pdes required: 	(1<<maxphyaddr)>>21;
	*data=(ept_data_t) {0};
	
	data->pml4=get_zeroed_page(GFP_KERNEL);
	gprint("pml4:\t\t0x%lx", data->pml4);
	
	data->pdpt=get_zeroed_page(GFP_KERNEL);
	gprint("pdpt:\t\t0x%lx", data->pdpt);
	
	data->pds.order=maxphyaddr-30;	//log base 2 of number of gigabytes
	data->pds.base=__get_free_pages(__GFP_ZERO, data->pds.order);
	gprint("pd memory pool:\t0x%lx (%d pages)",
	       (data->pds).base, 1<<((data->pds).order));
	
	data->pts=NULL;
	
	if(!data->pml4 || !data->pdpt || !(data->pds).base) {
		gprint("no free pages available");
		return -ENOMEM; }
	return 0; }

//~1gb for each page directory
static int initialize_ept(ept_data_t *data) {
	unsigned char maxphyaddr=32;
	
	//number of pdptes required:	(1<<maxphyaddr)>>30;
	//number of pdes required: 	(1<<maxphyaddr)>>21;
	
	msr_t msr;
	READ_MSR(msr, IA32_VMX_EPT_VPID_CAP);
	if(!(msr.vmx_ept_vpid_cap.accessed_dirty_flags_allowed)) {
		gprint("accessed/dirty ept bits not supported\n");
		return -EOPNOTSUPP; }
		//eptp_p->accessed_dirty_control=0; }
	
	(void)memset((void *)data->pml4, 0, 4096);
	(void)memset((void *)data->pdpt, 0, 4096);
	(void)memset((void *)data->pds.base, 0, (1<<12)<<(data->pds.order));
	gprint("zeroed:\tpml4: 0x%lx\tpdpt: 0x%lx\tpds: 0x%lx (%d pages)",
	       data->pml4, data->pdpt, data->pds.base, 1<<(data->pds).order);
	pt_node *next=NULL;
	while(data->pts!=NULL) {
		//gprint("pt node:\t\t\t0x%px", data->pts);
		//gprint("\tpt page:\t0x%lx", data->pts->base);
		free_page(data->pts->base);
		
		next=(data->pts)->next;
		kfree(data->pts);
		data->pts=next; }
	gprint("freed pt linked list");
	
	epse_t *epse_p;
	unsigned long i=0;
	
	epse_p=(void *)data->pds.base;
	for(i=0; i<( (1<<maxphyaddr)>>21 ); i++) {
		epse_p[i]=(epse_t) {
			.r=1, .w=1, .x=1, .ux=0,
			.caching_type=PAT_WB, .ignore_pat=0,
			.accessed=0, .dirty=0, .suppress_ve=0,
			.addr_2mb=(i<<21), .page_size=1}; }
	
	epse_p=(void *)data->pdpt;
	for(i=0; i<( (1<<maxphyaddr)>>30 ); i++) {
		epse_p[i]=(epse_t) {
			.r=1, .w=1, .x=1, .ux=0,
			.addr=i+(virt_to_phys((void *)data->pds.base)>>12) }; }
	
	epse_p=(void *)data->pml4;
	epse_p[0]=(epse_t) {
		.r=1, .w=1, .x=1, .ux=0,
		.addr=virt_to_phys((void *)data->pdpt)>>12 };
	
	gprint("epses:\tpd: 0x%lx\tpdpt: 0x%lx\tpml4: 0x%lx",
	       ((epse_t *)(data->pds.base))[0].val, ((epse_t *)(data->pdpt))[0].val,
	       ((epse_t *)(data->pml4))->val);
	

	/*msr_t msr;
	READMSR(msr, IA32_VMX_PROCBASED_CTLS);
	if( ((primary_cpu_based_execution_ctls)(msr.)).
	READMSR(msr, IA32_VMX_EPT_VPID_CAP);*/
	data->eptp=(eptp_t) {0};
	data->eptp.accessed_dirty_control=1;
	data->eptp.caching_type=PAT_WB;
	data->eptp.page_walk_length=3;
	data->eptp.pml4_addr=virt_to_phys((void *)data->pml4)>>12;
	gprint("eptp: 0x%lx", data->eptp.val);
	
	//printk("[*]  initialization complete\n\n");
	
	return 0; }

#endif
