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
//check physical address width?
//# of cores (and corresponding # of vmcs regions) as argument to open
//mutexes on all resources?
//all allocated pages should be writeback cacheable
//	save/restore caching type
//check error code in vmfailvalid
//	check which instruction can vmfailvalid
//////////////////////////////////////////////////////

#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include "x64-utilities.h"
#include "vtx-utilities.h"
#include "vmcs.h"
#include "mm.h"

static int param_cpu_id;
module_param(param_cpu_id, int, (S_IRUSR|S_IRGRP|S_IROTH));
MODULE_PARM_DESC(param_cpu_id, "cpu id that operations run on");

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
typedef struct {
	unsigned long vmxon_region;
	unsigned long vmxon_paddr;
	
	unsigned long vmcs_region;
	unsigned long vmcs_paddr;

	unsigned long msr_bitmap;
	unsigned long msr_paddr;
	
	ept_data_t ept_data;
	int active_flag;
} guest_state_t;
guest_state_t guest_state;
/////////////////////////////////////////
typedef struct {
	cr4_t old_cr4;
	int vmxon_flag;
#define VMM_STACK_ORDER 1
	unsigned long vmm_stack_base;
	int vmm_stack_order;
	unsigned long vmm_stack_top;
	//linked list of active guest_states?
} host_state_t;
host_state_t host_state;
/////////////////////////////////////////

void cleanup(guest_state_t *vm_state, host_state_t *vmm_state) {
	printk("–––––––––––––––––––––––––––––––––––––––––––––––––––––\n\n");
	
	lhf_t lhf;
	if(vm_state->active_flag && vm_state->vmcs_paddr) {
		printk("[*]  clearing vmcs\n");
		printk("[**] vmcs addr:\t0x%lx\n", vm_state->vmcs_paddr);
		VMCLEAR(vm_state->vmcs_paddr, lhf);
		printk("[**] lhf:\t0x%02x\n", lhf.val);
		if(!VMsucceed(lhf)) {
			if(VMfailValid(lhf)) {
				//should get error field from current vmcs
				printk("[*]  vmclear failed with valid region\n"); }
			else if(VMfailInvalid(lhf)) {
				printk("[*]  vmclear failed with invalid region\n"); }}
		else {
			vm_state->active_flag=0;
			printk("[*]  vmclear succeeded\n\n"); }}
		
	if(vmm_state->vmxon_flag) {
		printk("[*]  exiting vmx mode\n\n");
		VMXOFF;
		vmm_state->vmxon_flag=0; }
	
	cr4_t cr4;
	if(vmm_state->old_cr4.val) {
		printk("[*]  restoring initial cr4\n");
		__asm__ __volatile__("mov %%cr4, %0":"=r"(cr4.val));
		printk("[**] cr4:\t0x%lx\n", cr4.val);
		cr4.val=vmm_state->old_cr4.val;
		__asm__ __volatile__("mov %0, %%cr4"::"r"(cr4.val));
		printk("[**] new cr4:\t0x%lx\n", cr4.val);
		printk("[*]  restored\n\n");
		vmm_state->old_cr4.val=0; }
	
	printk("[*]  freeing pages\n");
	free_ept(&(vm_state->ept_data));
	if(vm_state->vmxon_region) {
		printk("[**] vmxon region:\t0x%lx\n", vm_state->vmxon_region); 
		free_page(vm_state->vmxon_region);
		vm_state->vmxon_region=0; }
	if(vm_state->vmcs_region) {
		printk("[**] vmcs region:\t0x%lx\n", vm_state->vmcs_region);
		free_page(vm_state->vmcs_region);
		vm_state->vmcs_region=0; }
	if(vmm_state->vmm_stack_base) {
		printk("[**] vmm stack:\t\t0x%lx (%d pages)\n",
		       vmm_state->vmm_stack_base, 1<<(vmm_state->vmm_stack_order));
		free_pages(vmm_state->vmm_stack_base, vmm_state->vmm_stack_order);
		vmm_state->vmm_stack_base=0; }
	if(vm_state->msr_bitmap) {
		printk("[**] msr bitmap:\t0x%lx\n", vm_state->msr_bitmap);
		free_page(vm_state->msr_bitmap);
		vm_state->msr_bitmap=0; }
	printk("[*]  all freed\n\n"); }


__attribute__((__used__))
static void hook(void) {
	/*lhf_t lhf;
	unsigned long exit_reason=0xdeadbeef, exit_qual=0xdeadbeef;
	VMREAD(exit_reason, EXIT_REASON, lhf);
	VMREAD(exit_qual, EXIT_QUALIFICATION, lhf);
	__asm__ __volatile__("vmxoff");
	guest_state.active_flag=0;
	host_state.vmxon_flag=0;
	printk("[*]  in the hook!\n");
	printk("[**] exited vmx operation\n");
	printk("[**] exit reason:\t0x%lx\n", exit_reason);
	printk("[**] exit qual:\t\t0x%lx\n", exit_qual);*/
	lhf_t lhf;
	unsigned long reason=0xdeadbeef;
	printk("[*]  in the hook!\n");
	VMREAD(reason, EXIT_REASON, lhf);
	printk("[**] exit reason:\t0x%lx\n", reason);
	VMREAD(reason, EXIT_QUALIFICATION, lhf);
	printk("[**] exit qual:\t\t0x%lx\n", reason);
	VMREAD(reason, EXIT_INSTRUCTION_LENGTH, lhf);
	printk("[**] instruction len:\t%ld\n", reason);
	if(!VMsucceed(lhf)) {
		if(VMfailValid(lhf)) {
			VMREAD(reason, VM_INSTRUCTION_ERROR, lhf);
			printk("[*]  vmread failed with error code %ld\n\n", reason); }
		else if(VMfailInvalid(lhf)) {
			printk("[*]  vmread failed with invalid region\n\n"); }}
	printk("[*]  leaving hook\n\n");
	return; }

unsigned long return_rsp;
unsigned long return_rbp;
__asm__(
	".text;"
	".global host_stub;"
"host_stub:;"
	PUSHA
	//"swapgs;"
	"call hook;"
	//"swapgs;"
	POPA
	"jmp return_from_init;");
extern void host_stub(void);

__asm__(
	".text;"
	".global guest_stub;"
"guest_stub:;"
//	"rdtsc;");
	"hlt;");
extern void guest_stub(void);

static void per_cpu_print(void *info) {
	cpuid_t cpuid;
	unsigned int ia32_tsc_aux;
	__asm__ __volatile__("rdtscp":"=c"(ia32_tsc_aux));
	CPUID(cpuid, 0x0b);
	printk("linux id: %d\t\tapic id: %d\t\ttsc_aux: %d\n", smp_processor_id(), cpuid.edx, ia32_tsc_aux); }

static int __init hvc_init(void) {
	on_each_cpu(per_cpu_print, NULL, 1);
	int cpu_id;
	if(param_cpu_id!=0) {
		printk("[*] unable to load module without cpu parameter 0\n");
		return -EINVAL; }
	cpu_id=get_cpu();
	printk("[*]  called on cpu: %d\n\n", cpu_id);
	//all of this should run only on a single processor
	
	guest_state=(guest_state_t) {0};
	host_state=(host_state_t) {0};
	
	cpuid_t cpuid;
	printk("[*]  verifying vt-x support\n");
	CPUID(cpuid.leaf_0, 0);
	printk("[**] vendor id: '%.12s'\n", cpuid.leaf_0.vendor_id);
	if(strncmp(cpuid.leaf_0.vendor_id, "GenuineIntel", 12)) {
		printk("[*]  not intel, aborting\n");
		return -EOPNOTSUPP; }
	CPUID(cpuid, 1);
	printk("[**] cpuid.1:ecx.vmx[bit 5]: %d\n", cpuid.leaf_1.vmx);
	if(!(cpuid.leaf_1.vmx)) {
		printk("[*] vt-x not supported, aborting\n");
		return -EOPNOTSUPP; }
	printk("[*]  vt-x support confirmed\n\n");
	
	cr4_t cr4;
	printk("[*]  setting cr4.vmxe[bit 13]\n");
	__asm__ __volatile__("mov %%cr4, %0":"=r"(cr4.val));
	printk("[**] cr4:\t0x%lx\n", cr4.val);
	host_state.old_cr4.val=cr4.val;
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
			cleanup(&guest_state, &host_state);
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
		printk("[*]  writeback caching not available\n\n");
		cleanup(&guest_state, &host_state);
		return -EOPNOTSUPP; }
	printk("[*]  writeback caching available\n\n");
	
	int ret=0;
	if(( ret=alloc_wb_page("vmxon region", &(guest_state.vmxon_region), &(guest_state.vmxon_paddr)) )) {
		cleanup(&guest_state, &host_state);
		return ret; }

	if(( ret=alloc_wb_page("vmcs region", &(guest_state.vmcs_region), &(guest_state.vmcs_paddr)) )) {
		cleanup(&guest_state, &host_state);
		return ret; }
	
	if(( ret=initialize_ept(&guest_state.ept_data, MAX_ORD_GUEST_PAGES) )) {
		cleanup(&guest_state, &host_state);
		return ret; }
	
	printk("[*]  allocating vmm stack\n");
	host_state.vmm_stack_order=VMM_STACK_ORDER;
	if( !(host_state.vmm_stack_base=__get_free_pages(__GFP_ZERO, host_state.vmm_stack_order)) ) {
		printk("[*]  no free page available\n");
		return -ENOMEM; }
	printk("[**] stack base:\t0x%lx (%d pages)\n", host_state.vmm_stack_base, 1<<(host_state.vmm_stack_order));
	host_state.vmm_stack_top=host_state.vmm_stack_base+((1<<12)<<(host_state.vmm_stack_order));
	printk("[**] stack top:\t\t0x%lx\n", host_state.vmm_stack_top);
	printk("[*]  allocated successfully\n\n");
	
	
	printk("[*]  entering vmx operation\n");
	READ_MSR(msr, IA32_VMX_BASIC);
	printk("[**] rev id:\t0x%x\n", msr.vmx_basic.revision_id);
	*(unsigned int *)(guest_state.vmxon_region)=msr.vmx_basic.revision_id;
	lhf_t lhf;
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
		//	:"m"(guest_state.vmxon_paddr)
		//	:"memory");
	VMXON(guest_state.vmxon_paddr, lhf);
	printk("[**] lhf:\t0x%02x\n", lhf.val);
	if(!VMsucceed(lhf)) {
		if(VMfailValid(lhf)) {
			//should get error field from current vmcs
			printk("[*]  vmxon failed with valid region\n"); }
		else if(VMfailInvalid(lhf)) {
			printk("[*]  vmxon failed with invalid region\n"); }
		cleanup(&guest_state, &host_state);
		return -EINVAL; }
	host_state.vmxon_flag=1;
	printk("[*]  vmx operation entered\n\n"); 
	

	printk("[*]  activating vmcs region\n");
	READ_MSR(msr, IA32_VMX_BASIC);
	printk("[**] rev id:\t0x%x\n", msr.vmx_basic.revision_id);
	*(unsigned int *)(guest_state.vmcs_region)=msr.vmx_basic.revision_id;
	*(unsigned int *)(guest_state.vmcs_region)&=0x7fffffff;	//not a shadow vmcs
	printk("[**] clearing vmcs @ 0x%lx\n", guest_state.vmcs_paddr);
	VMCLEAR(guest_state.vmcs_paddr, lhf);
	printk("[**] lhf:\t0x%02x\n", lhf.val);
	if(!VMsucceed(lhf)) {
		if(VMfailValid(lhf)) {
			//should get error field from current vmcs
			printk("[*]  vmclear failed with valid region\n"); }
		else if(VMfailInvalid(lhf)) {
			printk("[*]  vmclear failed with invalid region\n"); }
		cleanup(&guest_state, &host_state);
		return -EINVAL; }
	printk("[**] vmclear successful\n"); 
	printk("[**] calling vmptrld\n");
	VMPTRLD(guest_state.vmcs_paddr, lhf);
	printk("[**] lhf:\t0x%02x\n", lhf.val);
	if(!VMsucceed(lhf)) {
		if(VMfailValid(lhf)) {
			//should get error field from current vmcs
			printk("[*]  vmptrld failed with valid region\n"); }
		else if(VMfailInvalid(lhf)) {
			printk("[*]  vmptrld failed with invalid region\n"); }
		cleanup(&guest_state, &host_state);
		return -EINVAL; }
	guest_state.active_flag=1;
	printk("[*]  vmcs region activated\n\n"); 
	
	if( (ret=initialize_vmcs(\
	         &guest_state.ept_data.eptp, (unsigned long)&guest_stub, (unsigned long)&host_stub, host_state.vmm_stack_top, host_state.vmm_stack_top)) ) {
		cleanup(&guest_state, &host_state);
		return ret; }
	//error check vmxon

	__asm__ __volatile__(
		"mov %%rsp, %0;"
		"mov %%rbp, %1;"
		:"=r"(return_rsp), "=r"(return_rbp)
		::"memory");

	VMLAUNCH(lhf);
	unsigned long error_code;
	if(!VMsucceed(lhf)) {
		if(VMfailValid(lhf)) {
			//VMREAD(error_code, VM_INSTRUCTION_ERROR, lhf);
			printk("[*]  vmlaunch failed with error code %ld\n\n", error_code); }
		else if(VMfailInvalid(lhf)) {
			printk("[*]  vmlaunch failed with invalid region\n\n"); }
		cleanup(&guest_state, &host_state);
		return -EINVAL; }
	__asm__ __volatile__(
	"return_from_init:"
		"movq (return_rsp), %rsp;"
		"movq (return_rbp), %rbp;");
	cleanup(&guest_state, &host_state);
		
	
	
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

	put_cpu();
	return 0; }

static void __exit hvc_exit(void) {
	/*lhf_t lhf;
	unsigned long reason=0xdeadbeef;
	VMREAD(reason, EXIT_REASON, lhf);
	printk("[*]  exit reason:\t0x%lx\n", reason);
	VMREAD(reason, EXIT_QUALIFICATION, lhf);
	printk("[*]  exit qual:\t\t0x%lx\n\n", reason);*/
	
	cleanup(&guest_state, &host_state);
	
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
