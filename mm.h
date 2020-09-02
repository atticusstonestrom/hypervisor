#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/io.h>
#include <linux/slab.h>

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
	unsigned long base;
	for(i=0; i<vcnt; i++) {
		READ_MSR(msr, IA32_MTRR_PHYSBASE(i));
		base=msr.mtrr_variable.addr<<12;
		printk("[*] physbase%d: 0x%lx\n", i, msr.val);
		printk("BASE: 0x%lx\n", base);
		READ_MSR(msr, IA32_MTRR_PHYSMASK(i));
		if(msr.mtrr_variable.v) {
			printk("END : 0x%llx\n", base+(1ULL<<__builtin_ctzl(msr.mtrr_variable.addr<<12))-1); }
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
	unsigned long base_2mb;		//base of 2mb region mapped by it
	unsigned long page_addr;	//base of page
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

extern ept_data_t ept_data;

void free_ept(void) {
	if(ept_data.pml4) {
		gprint("pml4:\t\t0x%lx", ept_data.pml4);
		free_page(ept_data.pml4);
		ept_data.pml4=0; }
	
	if(ept_data.pdpt) {
		gprint("pdpt:\t\t0x%lx", ept_data.pdpt);
		free_page(ept_data.pdpt);
		ept_data.pdpt=0; }
	
	if(ept_data.pds.base) {
		gprint("pd memory pool:\t0x%lx (%lld pages)", ept_data.pds.base, 1ULL<<ept_data.pds.order);
		free_pages(ept_data.pds.base, ept_data.pds.order);
		ept_data.pds.base=0; }
	
	pt_node *next=NULL;
	while(ept_data.pts!=NULL) {
		gprint("pt node:\t\t\t0x%px", ept_data.pts);
		gprint("\tpt page:\t0x%lx", ept_data.pts->page_addr);
		free_page(ept_data.pts->page_addr);
		
		next=(ept_data.pts)->next;
		kfree(ept_data.pts);
		ept_data.pts=next; }
	
	ept_data.eptp.pml4_addr=0;
	return; }

#define INVEPT_TYPE_SINGLE_CONTEXT 1
#define INVEPT_TYPE_GLOBAL 2
void invept(void *info) {
	volatile struct __attribute__((packed)) {
		unsigned long eptp;
		unsigned long zeros; }
		invept_descriptor;
	invept_descriptor.eptp=ept_data.eptp.val;
	invept_descriptor.zeros=0;
	//lhf_t lhf;	//can fail due to invalid eptp
	__asm__ __volatile__("invept %1, %0"::"r"((long)INVEPT_TYPE_SINGLE_CONTEXT), "m"(invept_descriptor));
	return; }

//perm_flag determines whether function is
//intended to change only r/w/x permissions
int set_ept_permissions(epse_t template, unsigned long paddr, int perm_flag) {
	pt_node *node=ept_data.pts;
	epse_t *epse_p;
	template.addr_4kb=paddr>>12;
	while(node!=NULL) {
		if(node->base_2mb==(paddr&~(0x1fffffULL))) {
			epse_p=(void *)node->page_addr;
			if(!perm_flag) { epse_p[(paddr&0x1fffffULL)>>12]=template; }
			else {
				epse_p[(paddr&0x1fffffULL)>>12].r=template.r;
				epse_p[(paddr&0x1fffffULL)>>12].w=template.w;
				epse_p[(paddr&0x1fffffULL)>>12].x=template.x; }
			on_each_cpu(invept, NULL, 1);
			return 0; }
		node=node->next; }
	
	node=kmalloc(sizeof(pt_node), __GFP_ZERO);
	if(node==NULL) {
		return -ENOMEM; }
	node->page_addr=get_zeroed_page(GFP_KERNEL);
	if(!node->page_addr) {
		kfree(node);
		return -ENOMEM; }
	
	epse_p=(void *)ept_data.pds.base;
	epse_t old_template=epse_p[(paddr&~(0x1fffffULL))>>21];
	epse_p[(paddr&~(0x1fffffULL))>>21].page_size=0;
	epse_p[(paddr&~(0x1fffffULL))>>21].addr=(node->page_addr)>>12;
	//old_template.page_size=0;
	//old_template.accessed=0;	//???
	//old_template.dirty=0;
	
	old_template.addr_4kb=(paddr&~(0x1fffffULL))>>12;
	epse_p=(void *)node->page_addr;
	int i=0;
	//for(i=0; i<512; ++i && old_template.addr+=1);
	for(i=0; i<512; i++) {
		epse_p[i]=old_template;
		if(old_template.addr_4kb==paddr>>12) {
			if(!perm_flag) { epse_p[i]=template; }
			epse_p[i].r=template.r;
			epse_p[i].w=template.w;
			epse_p[i].x=template.x; }
		old_template.addr_4kb++; }
	
	node->base_2mb=paddr&~(0x1fffffULL);
	node->next=ept_data.pts;
	ept_data.pts=node;
	on_each_cpu(invept, NULL, 1);
	return 0; }



#define MAXPHYADDR 35;

//~1gb for each page directory
int allocate_ept(void) {
	unsigned char maxphyaddr=MAXPHYADDR;
	//number of pdptes required:	(1ULL<<maxphyaddr)>>30;
	//number of pdes required: 	(1ULL<<maxphyaddr)>>21;
	ept_data=(ept_data_t) {0};
	
	ept_data.pml4=get_zeroed_page(GFP_KERNEL);
	gprint("pml4:\t\t0x%lx", ept_data.pml4);
	
	ept_data.pdpt=get_zeroed_page(GFP_KERNEL);
	gprint("pdpt:\t\t0x%lx", ept_data.pdpt);
	
	ept_data.pds.order=maxphyaddr-30;	//log base 2 of number of gigabytes
	ept_data.pds.base=__get_free_pages(__GFP_ZERO, ept_data.pds.order);
	gprint("pd memory pool:\t0x%lx (%lld pages)",
	       (ept_data.pds).base, 1ULL<<((ept_data.pds).order));
	
	ept_data.pts=NULL;
	
	if(!ept_data.pml4 || !ept_data.pdpt || !(ept_data.pds).base) {
		gprint("no free pages available");
		return -ENOMEM; }
	return 0; }

//~1gb for each page directory
int initialize_ept(void) {
	unsigned char maxphyaddr=MAXPHYADDR;
	
	//number of pdptes required:	(1ULL<<maxphyaddr)>>30;
	//number of pdes required: 	(1ULL<<maxphyaddr)>>21;
	
	msr_t msr;
	READ_MSR(msr, IA32_VMX_EPT_VPID_CAP);
	if(!(msr.vmx_ept_vpid_cap.accessed_dirty_flags_allowed)) {
		gprint("accessed/dirty ept bits not supported");
		//eptp_p->accessed_dirty_control=0;
		return -EOPNOTSUPP; }
	if(!(msr.vmx_ept_vpid_cap.two_mb_pages_allowed)) {
		gprint("2mb pages not allowed");
		return -EOPNOTSUPP; }
	if(!(msr.vmx_ept_vpid_cap.invept_supported) ||
	   !(msr.vmx_ept_vpid_cap.single_context_invept_supported)) {
		gprint("single context invept not supported");
		return -EOPNOTSUPP; }
	
	(void)memset((void *)ept_data.pml4, 0, 4096);
	(void)memset((void *)ept_data.pdpt, 0, 4096);
	(void)memset((void *)ept_data.pds.base, 0, (1ULL<<12)<<(ept_data.pds.order));
	gprint("zeroed:\tpml4: 0x%lx\tpdpt: 0x%lx\tpds: 0x%lx (%lld pages)",
	       ept_data.pml4, ept_data.pdpt, ept_data.pds.base, 1ULL<<(ept_data.pds).order);
	pt_node *next=NULL;
	while(ept_data.pts!=NULL) {
		//gprint("pt node:\t\t\t0x%px", data->pts);
		//gprint("\tpt page:\t0x%lx", data->pts->base);
		free_page(ept_data.pts->page_addr);
		
		next=(ept_data.pts)->next;
		kfree(ept_data.pts);
		ept_data.pts=next; }
	gprint("freed pt linked list");
	
	epse_t template, *epse_p;
	unsigned long i=0;
	
	template=(epse_t) {
		.r=1, .w=1, .x=1, .ux=0,
		.caching_type=PAT_WB, .ignore_pat=0,
		.accessed=0, .dirty=0, .page_size=1 };
	epse_p=(void *)ept_data.pds.base;
	for(i=0; i<( (1ULL<<maxphyaddr)>>21 ); i++) {
		epse_p[i]=template;
		epse_p[i].addr_2mb=i; }
	
	template=(epse_t) { .r=1, .w=1, .x=1, .ux=0 };
	epse_p=(void *)ept_data.pdpt;
	for(i=0; i<( (1ULL<<maxphyaddr)>>30 ); i++) {
		epse_p[i]=template;
		epse_p[i].addr=i+(virt_to_phys((void *)ept_data.pds.base)>>12); }
	
	epse_p=(void *)ept_data.pml4;
	epse_p[0]=(epse_t) {
		.r=1, .w=1, .x=1, .ux=0,
		.addr=virt_to_phys((void *)ept_data.pdpt)>>12 };
	
	
	READ_MSR(msr, IA32_MTRRCAP);
	int vcnt=msr.mtrrcap.vcnt;
	msr_t def_type;
	READ_MSR(def_type, IA32_MTRR_DEF_TYPE);
	if(def_type.mtrr_def_type.type!=PAT_WB) {
		gprint("default caching type not writeback: 0x%02x\n", def_type.mtrr_def_type.type);
		return -EOPNOTSUPP; }
	
	unsigned long base, top;
	epse_p=(void *)ept_data.pds.base;
	
	//ensure var takes priority over fixed
	/*int j=0;
	#define PARSE_FIXED_MTRR(msr_id, name, base, inc)
	READ_MSR(msr, msr_id);
	gprint("name:\t%02x %02x %02x %02x %02x %02x %02x %02x",
	       msr.mtrr_fixed.entries[0], msr.mtrr_fixed.entries[1], 
	       msr.mtrr_fixed.entries[2], msr.mtrr_fixed.entries[3], 
	       msr.mtrr_fixed.entries[4], msr.mtrr_fixed.entries[5], 
	       msr.mtrr_fixed.entries[6], msr.mtrr_fixed.entries[7]);
	for(i=0; i<8; i++) {
		//gaps D:
		for(j=0; j<((inc)>>21); j+=) {
			epse_p[((base)>>21)+i*((inc)>>21)+j].caching_type=msr.mtrr_fixed.entries[i]; 
	
	if(def_type.mtrr.def_type.fe) {
		PARSE_FIXED_MTRR(IA32_MTRR_FIX64K_00000, fix64k_00000, 0, 0x10000);
		PARSE_FIXED_MTRR(IA32_MTRR_FIX16K_80000, fix16k_80000, 0x80000, 0x4000);
		PARSE_FIXED_MTRR(IA32_MTRR_FIX16K_A0000, fix16k_a0000, 0xa0000, 0x4000);
		PARSE_FIXED_MTRR(IA32_MTRR_FIX4K_C0000, fix4k_c0000, 0xc0000, 0x1000);
		PARSE_FIXED_MTRR(IA32_MTRR_FIX4K_C8000, fix4k_c8000, 0xc8000, 0x1000);
		PARSE_FIXED_MTRR(IA32_MTRR_FIX4K_D0000, fix4k_d0000, 0xd0000, 0x1000);
		PARSE_FIXED_MTRR(IA32_MTRR_FIX4K_D8000, fix4k_d8000, 0xd8000, 0x1000);
		PARSE_FIXED_MTRR(IA32_MTRR_FIX4K_E0000, fix4k_e0000, 0xe0000, 0x1000);
		PARSE_FIXED_MTRR(IA32_MTRR_FIX4K_E8000, fix4k_e8000, 0xe8000, 0x1000);
		PARSE_FIXED_MTRR(IA32_MTRR_FIX4K_F0000, fix4k_f0000, 0xf0000, 0x1000);
		PARSE_FIXED_MTRR(IA32_MTRR_FIX4K_F8000, fix4k_f8000, 0xf8000, 0x1000); }*/
		
	//not optimal but saves lines
	for(i=0; def_type.mtrr_def_type.e && i<vcnt; i++) {	//is this the right e?
		READ_MSR(msr, IA32_MTRR_PHYSBASE(i));
		//base=msr.mtrr_variable.addr<<12;
		base=msr.mtrr_variable.addr>>9;
		READ_MSR(msr, IA32_MTRR_PHYSMASK(i));
		if(!msr.mtrr_variable.v) { continue; }
		top=base;
		//top+=1ULL<<__builtin_ctzl(msr.mtrr_variable.addr<<12);
		top+=1ULL<<__builtin_ctzl(msr.mtrr_variable.addr>>9);
		//gprint("debug: 0x%lx", top<<21);
		gprint("variable mtrr %ld:\tbase: 0x%lx\tend: 0x%lx\ttype: 0x%02x",
		       i, base<<21, (top<<21)-1, msr.mtrr_variable.type);
		for(;base<top; base++) {
			epse_p[base].caching_type=msr.mtrr_variable.type; }}
	
	
	gprint("epses:\tpd: 0x%lx\tpdpt: 0x%lx\tpml4: 0x%lx",
	       ((epse_t *)(ept_data.pds.base))[0].val, ((epse_t *)(ept_data.pdpt))[0].val,
	       ((epse_t *)(ept_data.pml4))->val);
	
	ept_data.eptp=(eptp_t) {
		.accessed_dirty_control=1, .caching_type=PAT_WB, .page_walk_length=3,
		.pml4_addr=virt_to_phys((void *)ept_data.pml4)>>12 };
	gprint("eptp:\t0x%lx", ept_data.eptp.val);
	
	return 0; }

#endif
