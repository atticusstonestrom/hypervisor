#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/io.h>

#ifndef MEM_MANAGE
#define MEM_MANAGE

#include "utilities.h"

static int alloc_wb_page(char *name, unsigned long *vaddr, unsigned long *paddr) {
	msr_t msr;
	READ_MSR(msr, IA32_PAT);
	
	vtp_t vtp_s=(vtp_t){0};
	int ret=0;
	printk("[*]  allocating %s\n", name);
	*vaddr=get_zeroed_page(GFP_KERNEL);
	if(!(*vaddr)) {
		printk("[*]  no free page available\n");
		return -ENOMEM; }
	printk("[**] page:\t0x%lx\n", *vaddr);
	if( (ret=vtp(*vaddr, paddr, &vtp_s)) ) {
		printk("[*]  vtp failed\n");
		return ret; }
	if(vtp_s.pml5e_p) {
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
	printk("[*]  allocated successfully\n\n");
	
	printk("[*]  checking caching type\n");
	if(vtp_s.pte_p) {
		printk("[**] 4kb page\n");
		printk("[**] pat:\t%d\n", vtp_s.pte_p->pat_4kb);
		printk("[**] pcd:\t%d\n", vtp_s.pte_p->pcd);
		printk("[**] pwt:\t%d\n", vtp_s.pte_p->pwt);
		printk("[**] pat type:\t0x%02x\n",
		       msr.pat.entries[4*vtp_s.pte_p->pat_4kb+2*vtp_s.pte_p->pcd+vtp_s.pte_p->pwt]);
		if(vtp_s.pte_p->pcd || vtp_s.pte_p->pwt) {
			DISABLE_RW_PROTECTION;
			vtp_s.pte_p->pcd=0;
			vtp_s.pte_p->pwt=0;
			ENABLE_RW_PROTECTION;
			printk("[**] new pte:\t0x%lx\n", *(unsigned long *)vtp_s.pte_p);
			printk("[**] invalidating tlb\n");
			INVLPG(*vaddr); }}
	else if(vtp_s.pde_p) {
		printk("[**] 2mb page\n");
		printk("[**] pat: %d\n", vtp_s.pde_p->pat_2mb);
		printk("[**] pcd: %d\n", vtp_s.pde_p->pcd);
		printk("[**] pwt: %d\n", vtp_s.pde_p->pwt);
		printk("[**] current cache type: 0x%x\n",
		       msr.pat.entries[4*vtp_s.pde_p->pat_2mb+2*vtp_s.pde_p->pcd+vtp_s.pde_p->pwt]);
		if(vtp_s.pde_p->pcd || vtp_s.pde_p->pwt) {
			DISABLE_RW_PROTECTION;
			vtp_s.pde_p->pcd=0;
			vtp_s.pde_p->pwt=0;
			ENABLE_RW_PROTECTION;
			printk("[**] new pte:\t0x%lx\n", *(unsigned long *)vtp_s.pde_p);
			printk("[**] invalidating tlb\n");
			INVLPG(*vaddr); }}
	else if(vtp_s.pdpte_p) {
		printk("[**] 1gb page\n");
		printk("[**] pat: %d\n", vtp_s.pdpte_p->pat_1gb);
		printk("[**] pcd: %d\n", vtp_s.pdpte_p->pcd);
		printk("[**] pwt: %d\n", vtp_s.pdpte_p->pwt);
		printk("[**] current cache type: 0x%x\n",
		       msr.pat.entries[4*vtp_s.pdpte_p->pat_1gb+2*vtp_s.pdpte_p->pcd+vtp_s.pdpte_p->pwt]);
		if(vtp_s.pdpte_p->pcd || vtp_s.pdpte_p->pwt) {
			DISABLE_RW_PROTECTION;
			vtp_s.pdpte_p->pcd=0;
			vtp_s.pdpte_p->pwt=0;
			ENABLE_RW_PROTECTION;
			printk("[**] new pte:\t0x%lx\n", *(unsigned long *)vtp_s.pdpte_p);
			printk("[**] invalidating tlb\n");
			INVLPG(*vaddr); }}
	//else {	//vtp must have failed
	printk("[*]  caching type set to writeback\n\n");
	return ret; }

typedef struct {
	eptp_t eptp;
	unsigned long pml4;
	unsigned long pdpt;
	struct {
		unsigned long base;
		unsigned int order; }
		pds;
	struct {
		unsigned long base;
		unsigned int order; }
		pts;
	struct {
		unsigned long base;
		unsigned int order; }
		guest_memory;
} ept_data_t;

void free_ept(ept_data_t *ept) {
	if(ept->guest_memory.base) {
		free_pages(ept->guest_memory.base, ept->guest_memory.order); }
	if(ept->pts.base) {
		free_pages(ept->pts.base, ept->pts.order); }
	if(ept->pds.base) {
		free_pages(ept->pds.base, ept->pds.order); }
	if(ept->pdpt) {
		free_page(ept->pdpt); }
	if(ept->pml4) {
		free_page(ept->pml4); }
	ept->eptp.pml4_addr=0;
	return; }

//maybe do a struct like vtp?
//~1gb for each page directory
#define MAX_ORD_GUEST_PAGES 5
static int initialize_ept(ept_data_t *data, const int ord_guest_pages) {
	printk("[*]  initializing extended page tables\n");
	printk("[**] %d bytes of ram requested\n", (1<<ord_guest_pages)<<12);
	if(ord_guest_pages>MAX_ORD_GUEST_PAGES || ord_guest_pages<0) {
		printk("[*]  too much ram requested\n");
		return -EINVAL; }	//determine # of different structures based on this
	
	*data=(ept_data_t) {0};
	
	unsigned long guest_memory;
	epse_t *pml4, *pdpt, *pd, *pt;
	
	guest_memory=__get_free_pages(__GFP_ZERO, ord_guest_pages);
	data->guest_memory.base=guest_memory;
	data->guest_memory.order=ord_guest_pages;
	
	pml4=(void *)get_zeroed_page(GFP_KERNEL);
	data->pml4=(unsigned long)pml4;
	
	pdpt=(void *)get_zeroed_page(GFP_KERNEL);
	data->pdpt=(unsigned long)pdpt;
	
	pd=(void *)get_zeroed_page(GFP_KERNEL);
	data->pds.base=(unsigned long)pd;
	data->pds.order=0;
	
	pt=(void *)get_zeroed_page(GFP_KERNEL);
	data->pts.base=(unsigned long)pt;
	data->pts.order=0;
	
	if(!guest_memory || !pml4 || !pdpt || !pd || !pt) {
		printk("[*] no free pages available\n");
		free_ept(data);
		return -ENOMEM; }
	
	printk("[**] guest memory pool:\t0x%lx (%d pages)\n", guest_memory, 1<<ord_guest_pages);
	printk("[**] pml4:\t\t0x%px\n", pml4);
	printk("[**] pdpt:\t\t0x%px\n", pdpt);
	printk("[**] pd memory pool:\t0x%px (%d pages)\n", pd, 1<<0);
	printk("[**] pt memory pool:\t0x%px (%d pages)\n", pt, 1<<0);

	int i=0;
	for(i=0; i<(1<<ord_guest_pages); i++) {
		//={0}
		pt[i].accessed=0;
		pt[i].dirty=0;
		pt[i].caching_type=PAT_WB;
		pt[i].x=1;
		pt[i].ux=0;
		pt[i].ignore_pat=0;
		pt[i].addr=(virt_to_phys((void *)guest_memory)>>12)+i;
		pt[i].r=1;
		pt[i].suppress_ve=0;
		pt[i].w=1; }
	
	//={0}
	pd[0].accessed=0;
	pd[0].x=1;
	pd[0].ux=0;
	pd[0].addr=virt_to_phys(pt)>>12;
	pd[0].r=1;
	pd[0].w=1;

	//={0}
	pdpt[0].accessed=0;
	pdpt[0].x=1;
	pdpt[0].ux=0;
	pdpt[0].addr=virt_to_phys(pd)>>12;
	pdpt[0].r=1;
	pdpt[0].w=1;

	//={0}
	pml4[0].accessed=0;
	pml4[0].x=1;
	pml4[0].ux=0;
	pml4[0].addr=virt_to_phys(pd)>>12;
	pml4[0].r=1;
	pml4[0].w=1;
	
	data->eptp=(eptp_t) {0};
	data->eptp.accessed_dirty_control=1;
	data->eptp.caching_type=PAT_WB;
	data->eptp.page_walk_length=3;
	data->eptp.pml4_addr=virt_to_phys(pml4)>>12;
	
	printk("[*]  initialization complete\n");
	
	return 0; }

#endif
