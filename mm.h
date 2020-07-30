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

//maybe do a struct like vtp?
#define MAX_NUM_GUEST_PAGES 10
static int initialize_eptp_list(eptp_t *eptp_list, const int num_guest_pages) {
	if(num_guest_pages>MAX_NUM_GUEST_PAGES || num_guest_pages<=0) {
		return EINVAL; }	//determine # of different structures based on this
	eptp_list=(void *)get_zeroed_page(GFP_KERNEL);
	if(eptp_list==NULL) {
		return ENOMEM; }
	epse_t *ept_pml4, *ept_pdpt, *ept_pd, *ept_pt;
	ept_pml4=(void *)get_zeroed_page(GFP_KERNEL);
	if(ept_pml4==NULL) {
		free_page((unsigned long)eptp_list);
		return ENOMEM; }
	ept_pdpt=(void *)get_zeroed_page(GFP_KERNEL);
	if(ept_pdpt==NULL) {
		free_page((unsigned long)ept_pml4);
		free_page((unsigned long)eptp_list);
		return ENOMEM; }
	ept_pd=(void *)get_zeroed_page(GFP_KERNEL);
	if(ept_pd==NULL) {
		free_page((unsigned long)ept_pdpt);
		free_page((unsigned long)ept_pml4);
		free_page((unsigned long)eptp_list);
		return ENOMEM; }
	ept_pt=(void *)get_zeroed_page(GFP_KERNEL);
	if(ept_pt==NULL) {
		free_page((unsigned long)ept_pd);
		free_page((unsigned long)ept_pdpt);
		free_page((unsigned long)ept_pml4);
		free_page((unsigned long)eptp_list);
		return ENOMEM; }
	
	unsigned long guest_memory=__get_free_pages(__GFP_ZERO, num_guest_pages);
	if(!guest_memory) {
		free_page((unsigned long)ept_pt);
		free_page((unsigned long)ept_pd);
		free_page((unsigned long)ept_pdpt);
		free_page((unsigned long)ept_pml4);
		free_page((unsigned long)eptp_list);
		return ENOMEM; }
	int i=0;
	for(i=0; i<num_guest_pages; i++) {
		//={0}
		ept_pt[i].accessed=0;
		ept_pt[i].dirty=0;
		ept_pt[i].caching_type=PAT_WB;
		ept_pt[i].x=1;
		ept_pt[i].ux=0;
		ept_pt[i].ignore_pat=0;
		ept_pt[i].addr=virt_to_phys((void *)guest_memory)>>12;
		ept_pt[i].r=1;
		ept_pt[i].suppress_ve=0;
		ept_pt[i].w=1; }
	
	//={0}
	ept_pd[0].accessed=0;
	ept_pd[0].x=1;
	ept_pd[0].ux=0;
	ept_pd[0].addr=virt_to_phys(ept_pt)>>12;
	ept_pd[0].r=1;
	ept_pd[0].w=1;

	//={0}
	ept_pdpt[0].accessed=0;
	ept_pdpt[0].x=1;
	ept_pdpt[0].ux=0;
	ept_pdpt[0].addr=virt_to_phys(ept_pd)>>12;
	ept_pdpt[0].r=1;
	ept_pdpt[0].w=1;

	//={0}
	ept_pml4[0].accessed=0;
	ept_pml4[0].x=1;
	ept_pml4[0].ux=0;
	ept_pml4[0].addr=virt_to_phys(ept_pd)>>12;
	ept_pml4[0].r=1;
	ept_pml4[0].w=1;
	
	//={0}
	eptp_list[0].accessed_dirty_control=1;
	eptp_list[0].caching_type=PAT_WB;
	eptp_list[0].page_walk_length=3;
	eptp_list[0].pml4_addr=virt_to_phys(ept_pml4)>>12;
	
	return 0; }

#endif
