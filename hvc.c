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
//save/restore caching type
//check physical address width?
//# of cores (and corresponding # of vmcs regions) as argument to open
//////////////////////////////////////////////////////

#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include "utilities.h"
#include "mm.h"

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
	
	unsigned long eptp;
	unsigned long vmm_stack;
	
	unsigned long msr_bitmap;
	unsigned long msr_paddr;
} vmstate_t;
vmstate_t vmstate;
/////////////////////////////////////////

/////////////////////////////////////////
//host state variables
cr4_t initial_cr4;
/////////////////////////////////////////
	

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
	
	
	printk("[*]  entering vmx operation\n");
	READ_MSR(msr, IA32_VMX_BASIC);
	printk("[**] rev id:\t0x%x\n", msr.vmx_basic.revision_id);
	*(unsigned int *)(vmstate.vmxon_region)=msr.vmx_basic.revision_id;
	rflags_t rflags;
		//__asm__ __volatile__(
		//	"vmxon %1;"
		//	"jbe vmxon_fail;"
		//
		//"vmxon_success:;"
		//	"jmp vmxon_finish;"
		//"vmxon_fail:;"
		//	"jmp vmxon_finish;"
		//
		//"vmxon_finish:;"
		//	"pushf;"
		//	"popq %0;"
		//
		//	:"=r"(rflags.val)
		//	:"m"(vmstate.vmxon_paddr)
		//	:"memory");
	__asm__ __volatile__(		//define this as macro
		"vmxon %1;"
		"pushf;"
		"popq %0;"
		:"=r"(rflags.val)
		:"m"(vmstate.vmxon_paddr)
		:"memory");
	printk("[**] rflags:\t0x%lx\n", rflags.val);
	if(!VMsucceed(rflags)) {
		if(VMfailValid(rflags)) {
			//should get error field from current vmcs
			printk("[*]  vmxon failed with valid region\n"); }
		else if(VMfailInvalid(rflags)) {
			printk("[*]  vmxon failed with invalid region\n"); }
		__asm__ __volatile__("mov %0, %%cr4"::"r"(initial_cr4.val));
		free_page(vmstate.vmxon_region);
		free_page(vmstate.vmcs_region);
		return -EINVAL; }
	printk("[*]  vmx operation entered\n\n"); 
	

	printk("[*]  activating vmcs region\n");
	READ_MSR(msr, IA32_VMX_BASIC);
	printk("[**] rev id:\t0x%x\n", msr.vmx_basic.revision_id);
	*(unsigned int *)(vmstate.vmcs_region)=msr.vmx_basic.revision_id;
	printk("[**] clearing vmcs @ 0x%lx\n", vmstate.vmcs_paddr);
	__asm__ __volatile__(
		"vmclear %1;"
		"pushf;"
		"popq %0;"
		:"=r"(rflags.val)
		:"m"(vmstate.vmcs_paddr)
		:"memory");
	printk("[**] rflags:\t0x%lx\n", rflags.val);
	if(!VMsucceed(rflags)) {
		if(VMfailValid(rflags)) {
			//should get error field from current vmcs
			printk("[*]  vmclear failed with valid region\n"); }
		else if(VMfailInvalid(rflags)) {
			printk("[*]  vmclear failed with invalid region\n"); }
		__asm__ __volatile__("vmxoff");
		__asm__ __volatile__("mov %0, %%cr4"::"r"(initial_cr4.val));
		free_page(vmstate.vmxon_region);
		free_page(vmstate.vmcs_region);
		return -EINVAL; }
	printk("[**] vmclear successful\n"); 
	printk("[**] calling vmptrld\n");
	__asm__ __volatile__(
		"vmptrld %1;"
		"pushf;"
		"popq %0;"
		:"=r"(rflags.val)
		:"m"(vmstate.vmcs_paddr)
		:"memory");
	printk("[**] rflags:\t0x%lx\n", rflags.val);
	if(!VMsucceed(rflags)) {
		if(VMfailValid(rflags)) {
			//should get error field from current vmcs
			printk("[*]  vmptrld failed with valid region\n"); }
		else if(VMfailInvalid(rflags)) {
			printk("[*]  vmptrld failed with invalid region\n"); }
		__asm__ __volatile__("vmxoff");
		__asm__ __volatile__("mov %0, %%cr4"::"r"(initial_cr4.val));
		free_page(vmstate.vmxon_region);
		free_page(vmstate.vmcs_region);
		return -EINVAL; }
	printk("[*]  vmcs region activated\n\n"); 
	
	//__asm__ __volatile__("vmclear %0;"::"m"(vmstate.vmcs_paddr):"memory");
	
	
	

	eptp_t *eptp_list;
	if( (ret=initialize_eptp_list(eptp_list, MAX_NUM_GUEST_PAGES)) ) {
		__asm__ __volatile__("vmclear %0;"::"m"(vmstate.vmcs_paddr):"memory");
		__asm__ __volatile__("vmxoff");
		__asm__ __volatile__("mov %0, %%cr4"::"r"(initial_cr4.val));
		free_page(vmstate.vmxon_region);
		free_page(vmstate.vmcs_region);
		return ret; }
	//if(eptp_list==NULL) {
		
	
	
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
	printk("[*]  exiting vmx mode\n\n");
	__asm__ __volatile__("vmxoff");
	
	cr4_t cr4;
	printk("[*]  restoring initial cr4\n");
	__asm__ __volatile__("mov %%cr4, %0":"=r"(cr4.val));
	printk("[**] cr4:\t0x%lx\n", cr4.val);
	cr4.val=initial_cr4.val;
	__asm__ __volatile__("mov %0, %%cr4"::"r"(cr4.val));
	printk("[**] new cr4:\t0x%lx\n", cr4.val);
	printk("[*]  restored\n\n");
	
	printk("[*]  freeing vm regions\n");
	free_page(vmstate.vmxon_region);
	printk("[**] vmxon:\t0x%lx\n", vmstate.vmxon_region);
	free_page(vmstate.vmcs_region);
	printk("[**] vmcs:\t0x%lx\n", vmstate.vmcs_region);
	printk("[*]  all pages freed\n\n");
	
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
