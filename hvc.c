//////////////////////////////////////////////////////
//                                                  //
//                                                  //
//                                                  //
//////////////////////////////////////////////////////



//////////////////////////////////////////////////////
//urgent todo:
//everything must run on one processor
//	https://stackoverflow.com/questions/36288877/isolate-kernel-module-to-a-specific-core-using-cpuset
//	how to ensure a kernel module only runs on one cpu
//	https://stackoverflow.com/questions/34633600/how-to-execute-a-piece-of-kernel-code-on-all-cpus
//	on_each_cpu
//mutex, as in the intro to char devices
//	http://derekmolloy.ie/writing-a-linux-kernel-module-part-2-a-character-device/
//init() should be open()
//save caching type
//////////////////////////////////////////////////////

#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include "utilities.h"

#define DEVICE_NAME "hvchar"
#define CLASS_NAME "hvc"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Atticus Stonestrom");
MODULE_DESCRIPTION("...");
MODULE_VERSION("0.01");

/////////////////////////////////////////
//character device variables
static int major_num;
static char message[256]={0};
static short size_of_message;
static int counter=0;
static struct class *hvc_class=NULL;
static struct device *hvc_device=NULL;

static int dev_open(struct inode *, struct file *);
static int dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);

static struct file_operations fops = {
	.open=dev_open,
	.read=dev_read,
	.write=dev_write,
	.release=dev_release };
/////////////////////////////////////////

/////////////////////////////////////////
//guest state variables
typedef struct {
	unsigned long vmxon_region;
	unsigned long vmxon_paddr;
	unsigned long vmcs_region;
	unsigned long vmcs_paddr;
} vmstate_t;
vmstate_t vmstate;
/////////////////////////////////////////

/////////////////////////////////////////
//host state variables
cr4_t initial_cr4;
/////////////////////////////////////////

int alloc_wb_page(char *name, unsigned long *vaddr, unsigned long *paddr) {
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

static int __init hvc_init(void) {
	//all of this should run only on a single processor
	
	cpuid_t cpuid;
	printk("[*]  verifying vt-x support\n");
	CPUID(cpuid.leaf_0, 0);
	printk("[**] vendor id: '%.12s'\n", cpuid.leaf_0.vendor_id);
	if(strncmp(cpuid.leaf_0.vendor_id, "GenuineIntel", 12)) {
		printk("[*] not intel, aborting\n");
		return -EOPNOTSUPP; }
	CPUID(cpuid, 1);
	printk("[**] cpuid.1:ecx.vmx[bit 5]: %d\n", cpuid.leaf_1.vmx);
	if(!(cpuid.leaf_1.vmx)) {
		printk("[*] vt-x not supported, aborting\n");
		return -EOPNOTSUPP; }
	printk("[*]  vt-x supported confirmed\n\n");
	
	cr4_t cr4;
	printk("[*]  setting cr4.vmxe[bit 13]\n");
	__asm__ __volatile__("mov %%cr4, %0":"=r"(cr4.val));
	printk("[**] cr4:\t0x%lx\n", cr4.val);
	initial_cr4.val=cr4.val;
	cr4.vmxe=1;
	__asm__ __volatile__("mov %0, %%cr4"::"r"(cr4.val));
	printk("[**] new cr4:\t0x%lx\n", cr4.val);
	printk("[*]  vmx enabled\n\n");
	
	msr_t msr;
	printk("[*]  parsing ia32_feature_control\n");
	READ_MSR(msr, IA32_FEATURE_CONTROL);
	printk("[**] current value:\t0x%lx\n", msr.val);
	if(msr.feature_control.lock) {
		printk("[**] vmx locked in bios\n");
		//should check if current processor state is smx
		if(!msr.feature_control.non_smx_vmxe) {
			printk("[*] non-smx vmx disabled\n");
			__asm__ __volatile__("mov %0, %%cr4"::"r"(initial_cr4.val));
			return -EOPNOTSUPP; }
		printk("[**] non-smx vmx enabled\n"); }
	else {
		printk("[**] enabling non-smx vmx\n");
		msr.feature_control.non_smx_vmxe=1;
		printk("[**] locking feature control\n");
		msr.feature_control.lock=1;
		printk("[**] writing value:\t0x%lx\n", msr.val);
		WRITE_MSR(msr, IA32_FEATURE_CONTROL); }
	printk("[*]  parse complete\n\n");
	
	printk("[*]  parsing page attribute table\n");
	READ_MSR(msr, IA32_PAT);
	printk("[**] pat entries: 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x\n",
	       msr.pat.entries[0], msr.pat.entries[1], msr.pat.entries[2], msr.pat.entries[3], 
	       msr.pat.entries[4], msr.pat.entries[5], msr.pat.entries[6], msr.pat.entries[7]);
	if(msr.pat.entries[0]!=PAT_WB && msr.pat.entries[4]!=PAT_WB) {
		printk("[*]  writeback caching not available\n");
		__asm__ __volatile__("mov %0, %%cr4"::"r"(initial_cr4.val));
		return -EOPNOTSUPP; }
	printk("[*]  writeback caching available\n\n");
	
	
	int ret=0;
	if(( ret=alloc_wb_page("vmxon region", &(vmstate.vmxon_region), &(vmstate.vmxon_paddr)) )) {
		__asm__ __volatile__("mov %0, %%cr4"::"r"(initial_cr4.val));
		return ret; }


	if(( ret=alloc_wb_page("vmcs region", &(vmstate.vmcs_region), &(vmstate.vmcs_paddr)) )) {
		__asm__ __volatile__("mov %0, %%cr4"::"r"(initial_cr4.val));
		free_page(vmstate.vmxon_region);
		return ret; }
	
	
	printk("[*]  executing vmxon\n");
	READ_MSR(msr, IA32_VMX_BASIC);
	printk("[**] revision identifier: 0x%x\n", msr.vmx_basic.revision_id);
	*(unsigned int *)(vmstate.vmxon_region)=msr.vmx_basic.revision_id;
	VMXON(vmstate.vmxon_region);
	rflags_t rflags;
	__asm__ __volatile__(
		"pushf;"
		"pop %0;"
		:"=r"(rflags.val)::"memory");
	printk("[**] rflags: 0x%lx\n", rflags.val);
	if(VMsucceed(rflags)) {
		printk("[**] vmxon succeeded\n"); }
	if(VMfailInvalid(rflags)) {
		printk("[**] vmxon failed with invalid vmcs\n"); }
	if(VMfailValid(rflags)) {
		printk("[**] vmxon failed with valid vmcs\n"); }
	__asm__ __volatile__("vmxoff");
	
	

	/*disable_rw_protection;
	invlpg, etc;	//or the one that comes before it in the manual

	//first 32 bits of VMCS to give processor type, msr*/
	
	
	//printk("[*] initializing the hvchar lkm\n");
	if( (major_num=register_chrdev(0, DEVICE_NAME, &fops))<0 ) {
		printk("[*] failed to register a major number\n");
		return major_num; }
	//printk("[*] registered correctly with major number %d\n", major_num);
	
	hvc_class=class_create(THIS_MODULE, CLASS_NAME);
	if(IS_ERR(hvc_class)) {
		unregister_chrdev(major_num, DEVICE_NAME);
		printk("[*] failed to register device class\n");
		return PTR_ERR(hvc_class); }
	//printk("[*] device class registered correctly\n");
	
	hvc_device=device_create(hvc_class, NULL, MKDEV(major_num, 0), NULL, DEVICE_NAME);
	if(IS_ERR(hvc_device)) {
		class_destroy(hvc_class);
		unregister_chrdev(major_num, DEVICE_NAME);
		printk("[*] failed to create the device\n");
		return PTR_ERR(hvc_device); }
	//printk("[*] device class created correctly\n");

	return 0; }

static void __exit hvc_exit(void) {
	cr4_t cr4;
	printk("[*]  restoring initial cr4\n");
	__asm__ __volatile__("mov %%cr4, %0":"=r"(cr4.val));
	printk("[**] cr4:\t0x%lx\n", cr4.val);
	cr4.val=initial_cr4.val;
	__asm__ __volatile__("mov %0, %%cr4"::"r"(cr4.val));
	printk("[**] new cr4:\t0x%lx\n", cr4.val);
	printk("[*]  restored\n\n");
	
	free_page(vmstate.vmxon_region);
	printk("[*]  freed vmxon_region: 0x%lx\n", vmstate.vmxon_region);
	free_page(vmstate.vmcs_region);
	printk("[*]  freed vmcs_region:  0x%lx\n", vmstate.vmcs_region);
	//free pages
	//restore caching type
	//invlpg
	
	device_destroy(hvc_class, MKDEV(major_num, 0));
	class_unregister(hvc_class);
	class_destroy(hvc_class);
	unregister_chrdev(major_num, DEVICE_NAME);
	printk("[*]  lkm unloaded\n"); }

static int dev_open(struct inode *inodep, struct file *filep) {
	printk("[*] device has been opened %d time(s)\n", ++counter);
	return 0; }

static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset) {
	int error=0;
	if(!(error=copy_to_user(buffer, message, size_of_message))) {
		printk("[*] sent %d characters to the user\n", size_of_message);
		return (size_of_message=0); }
	else {
		printk("[*] failed to send %d characters to the user\n", error);
		return -EFAULT; }}

static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset) {
	len=(len<sizeof(message)-20) ? \
		len:(sizeof(message)-21);
	sprintf(message, "%.*s (%zu letters)", (unsigned int)len, buffer, len);
	size_of_message=strlen(message);
	printk("[*] received %zu characters from the user", len);
	return len; }

static int dev_release(struct inode *inodep, struct file *filep) {
	printk("[*] device succesfully closed\n");
	return 0; }

module_init(hvc_init);
module_exit(hvc_exit);
