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
//is there a way to force a vm exit from inside non-root operation?
//////////////////////////////////////////////////////

#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/slab.h>
#include "x64-utilities.h"
#include "vtx-utilities.h"
#include "vmcs.h"
#include "mm.h"
#include "hvc.h"

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
int ncores;

unsigned long *ret_rsp;
unsigned long *ret_rbp;

int *errors=NULL;	//every entry should be non-positive
#define parse_errors(i) ({ for(i=0;i<ncores;i++) { if(errors[i]) break; } (i==ncores) ? 0:errors[i]; })

state_t *state=NULL;
/////////////////////////////////////////

void cleanup_core(void *info) {
	int core=smp_processor_id();
	errors[core]=0;
	
	int success_flag;
	
	lhf_t lhf;
	if(state[core].active_flag && state[core].vmcs_paddr) {
		VMCLEAR(state[core].vmcs_paddr, lhf);
		success_flag=VMsucceed(lhf) ? 1:0;
		state[core].active_flag=1-success_flag;
		cprint("cleared vmcs:\t\t0x%lx\t%s", state[core].vmcs_paddr, success_flag ? "[done]":"[failed]"); }
		
	if(state[core].vmxon_flag) {
		VMXOFF;
		cprint("exited vmx mode");
		state[core].vmxon_flag=0; }
	
	cr4_t cr4;
	if(state[core].old_cr4.val) {
		__asm__ __volatile__("mov %%cr4, %0":"=r"(cr4.val));
		__asm__ __volatile__("mov %0, %%cr4"::"r"(state[core].old_cr4.val));
		cprint("restored cr4:\t\t0x%lx => 0x%lx", cr4.val, state[core].old_cr4.val);
		state[core].old_cr4.val=0; }
	

	free_ept(&(state[core].ept_data));	//printk??
	if(state[core].vmxon_region) {
		free_page(state[core].vmxon_region);
		cprint("freed vmxon region:\t0x%lx", state[core].vmxon_region);
		state[core].vmxon_region=0; }
	if(state[core].vmcs_region) {
		free_page(state[core].vmcs_region);
		cprint("freed vmcs region:\t\t0x%lx", state[core].vmcs_region);
		state[core].vmcs_region=0; }
	if(state[core].vmm_stack_base) {
		free_pages(state[core].vmm_stack_base, state[core].vmm_stack_order);
		cprint("freed vmm stack:\t\t0x%lx (%d pages)",
		       state[core].vmm_stack_base, 1<<state[core].vmm_stack_order);
		state[core].vmm_stack_base=0; }
	if(state[core].msr_bitmap) {
		free_page(state[core].msr_bitmap);
		cprint("freed msr bitmap:\t\t0x%lx", state[core].msr_bitmap);
		state[core].msr_bitmap=0; }
	
	return; }

void cleanup(void) {
	if(state==NULL) {
		printk("\n");
		return; }
	
	printk("–––––––––––––––––––––––––––––––––––––––––––––––––––––\n\n");
	gprint("cleaning up cores");
	on_each_cpu(cleanup_core, NULL, 1);
	gprint("all clean\n");
	
	if(ret_rbp!=NULL) {
		kfree(ret_rbp);
		gprint("freed 'ret_rbp':\t\t0x%px", ret_rbp);
		ret_rbp=NULL; }
	
	if(ret_rsp!=NULL) {
		kfree(ret_rsp);
		gprint("freed 'ret_rbp':\t\t0x%px", ret_rsp);
		ret_rsp=NULL; }
	
	if(errors!=NULL) {
		kfree(errors);
		gprint("freed 'errors':\t\t0x%px", errors);
		errors=NULL; }
	
	if(state!=NULL) {
		kfree(state);
		gprint("freed 'state':\t\t0x%px", state);
		state=NULL; }
	
	printk("\n–––––––––––––––––––––––––––––––––––––––––––––––––––––\n\n");
	return; }


//static void hook(struct guest_regs *regs_p);
//push regs, mov %rsp, first arg (rax?)
//specify calling convention? gcc
__attribute__((__used__))
static void hook(regs_t *regs_p) {
	int core=smp_processor_id();
	
	lhf_t lhf;
	
	unsigned long reason=0xdeadbeef, qual=0xfeed;
	
	VMREAD(reason, EXIT_REASON, lhf);
	VMREAD(qual, EXIT_QUALIFICATION, lhf);
	
	cprint("rax: 0x%lx\t\tr8: 0x%lx", regs_p->rax, regs_p->r8);
	cprint("exit reason: 0x%lx\t\texit qual: 0x%lx", reason, qual);
	/*VMREAD(reason, EXIT_INSTRUCTION_LENGTH, lhf);
	printk("[**] instruction len:\t%ld\n", reason);
	if(!VMsucceed(lhf)) {
		if(VMfailValid(lhf)) {
			VMREAD(reason, VM_INSTRUCTION_ERROR, lhf);
			printk("[*]  vmread failed with error code %ld\n\n", reason); }
		else if(VMfailInvalid(lhf)) {
			printk("[*]  vmread failed with invalid region\n\n"); }}
	printk("[*]  leaving hook\n\n");*/
	return; }

__asm__(
	".text;"
	".global host_stub;"
"host_stub:;"
	PUSHA
	//"swapgs;"
	"mov %rsp, %rdi;"
	"call hook;"
	//"swapgs;"
	POPA
	"jmp return_from_exit;");
extern void host_stub(void);

__asm__(
	".text;"
	".global guest_stub;"
"guest_stub:;"
	"rdtsc;"
	"mov $0xdeadbeef, %eax;"
	"mov $0xfeeddeaf, %r8;"
	"push %rax;"
	"hlt;");
extern void guest_stub(void);


static void initialize_core(void *info) {
	int core=smp_processor_id();
	state[core]=(state_t) {0};
	errors[core]=0;
	
	cr4_t cr4;
	__asm__ __volatile__("mov %%cr4, %0":"=r"(cr4.val));
	state[core].old_cr4.val=cr4.val;
	cr4.vmxe=1;
	__asm__ __volatile__("mov %0, %%cr4"::"r"(cr4.val));
	cprint("set cr4.vmxe[bit 13]:\t0x%lx => 0x%lx", state[core].old_cr4.val, cr4.val);

	int ret=0;

	if(( ret=alloc_wb_page(&(state[core].vmxon_region), &(state[core].vmxon_paddr)) )) {
		cprint("failed to allocate wb-cacheable vmxon region");
		errors[core]=ret;
		return; }
	cprint("vmxon region:\t\t0x%lx", state[core].vmxon_region);

	if(( ret=alloc_wb_page(&(state[core].vmcs_region), &(state[core].vmcs_paddr)) )) {
		cprint("failed to allocate wb-cacheable vmcs region");
		errors[core]=ret;
		return; }
	cprint("vmcs region:\t\t0x%lx", state[core].vmcs_region);
	
	if(( ret=initialize_ept(&state[core].ept_data, MAX_ORD_GUEST_PAGES) )) {
		cprint("failed to initialize ept");
		errors[core]=ret;
		return; }
	
	state[core].vmm_stack_order=VMM_STACK_ORDER;
	if( !(state[core].vmm_stack_base=__get_free_pages(__GFP_ZERO, state[core].vmm_stack_order)) ) {
		cprint("failed to allocate vmm stack");
		errors[core]=-ENOMEM;
		return; }
	cprint("vmm stack:\t\t\t0x%lx (%d pages)", state[core].vmm_stack_base, 1<<(state[core].vmm_stack_order));
	state[core].vmm_stack_top=state[core].vmm_stack_base+((1<<12)<<(state[core].vmm_stack_order));
	
	msr_t msr;
	READ_MSR(msr, IA32_VMX_BASIC);
	cprint("revision id:\t\t0x%x", msr.vmx_basic.revision_id);
	*(unsigned int *)(state[core].vmxon_region)=msr.vmx_basic.revision_id;
	lhf_t lhf;
	VMXON(state[core].vmxon_paddr, lhf);
	if(!VMsucceed(lhf)) {
		cprint("vmxon failed");
		errors[core]=-EINVAL;
		return; }
	cprint("vmxon succeeded");
	state[core].vmxon_flag=1;
	

	READ_MSR(msr, IA32_VMX_BASIC);
	*(unsigned int *)(state[core].vmcs_region)=msr.vmx_basic.revision_id;
	*(unsigned int *)(state[core].vmcs_region)&=0x7fffffff;	//not a shadow vmcs
	VMCLEAR(state[core].vmcs_paddr, lhf);
	if(!VMsucceed(lhf)) {
		cprint("vmclear failed");
		errors[core]=-EINVAL;
		return; }
	cprint("cleared vmcs:\t\t0x%lx", state[core].vmcs_paddr);
	VMPTRLD(state[core].vmcs_paddr, lhf);
	if(!VMsucceed(lhf)) {
		cprint("vmptrld failed");
		errors[core]=-EINVAL;
		return; }
	state[core].active_flag=1;
	cprint("vmcs region activated:\t0x%lx", state[core].vmcs_paddr);
	
	return; }


static void __init check_vmx_support(void *info) {
	int core=smp_processor_id();
	errors[core]=0;
	
	cpuid_t cpuid;
	CPUID(cpuid.leaf_0, 0);
	if(strncmp(cpuid.leaf_0.vendor_id, "GenuineIntel", 12)) {
		cprint("vendor id: '%.12s'\t\t[not intel]", cpuid.leaf_0.vendor_id);
		errors[core]=-EOPNOTSUPP;
		return; }
	cprint("vendor id: '%.12s'\t\t[okay]", cpuid.leaf_0.vendor_id);
	
	CPUID(cpuid, 1);
	if(!(cpuid.leaf_1.vmx)) {
		cprint("cpuid.1:ecx.vmx[bit 5]: %d\t\t[not supported]", cpuid.leaf_1.vmx);
		errors[core]=-EOPNOTSUPP;
		return; }
	cprint("cpuid.1:ecx.vmx[bit 5]: %d\t\t[okay]", cpuid.leaf_1.vmx);
	
	msr_t new_msr, msr;
	READ_MSR(msr, IA32_FEATURE_CONTROL);
	if(msr.feature_control.lock) {
		//should check if current processor state is smx
		if(!msr.feature_control.non_smx_vmxe) {
			cprint("ia32_feature_control: 0x%lx\t\t[non-smx vt-x disabled]", msr.val);
			errors[core]=-EOPNOTSUPP;
			return; }
		cprint("ia32_feature_control: 0x%lx\t\t[okay]", msr.val); }
	else {
		new_msr.val=msr.val;
		new_msr.feature_control.non_smx_vmxe=1;
		new_msr.feature_control.lock=1;
		WRITE_MSR(new_msr, IA32_FEATURE_CONTROL);
		cprint("ia32_feature_control: 0x%lx => 0x%lx\t\t[locked]", msr.val, new_msr.val); }
	
	READ_MSR(msr, IA32_PAT);
	if(msr.pat.entries[0]!=PAT_WB && msr.pat.entries[4]!=PAT_WB) {
		cprint("pat entries: 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x [wb caching unavailable]",
		       msr.pat.entries[0], msr.pat.entries[1], msr.pat.entries[2], msr.pat.entries[3], 
		       msr.pat.entries[4], msr.pat.entries[5], msr.pat.entries[6], msr.pat.entries[7]);
		errors[core]=-EOPNOTSUPP;
		return; }
	cprint("pat entries: 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x [wb caching available]",
	       msr.pat.entries[0], msr.pat.entries[1], msr.pat.entries[2], msr.pat.entries[3], 
	       msr.pat.entries[4], msr.pat.entries[5], msr.pat.entries[6], msr.pat.entries[7]);
	
	return; }

void launch(void *info) {
	int core=smp_processor_id();
	errors[core]=0;
	
	/*__asm__ __volatile__(
		"mov %%rsp, %0;"
		"mov %%rbp, %1;"
		:"=r"(state[core].return_rsp), "=r"(state[core].return_rbp)
		::"memory");*/
	__asm__ __volatile__(
		"mov $0x0b, %%eax;"
		"cpuid;"
		"movq (ret_rsp), %%rax;"
		"mov %%rsp, (%%rax, %%rdx, 8);"
		"movq (ret_rbp), %%rax;"
		"mov %%rbp, (%%rax, %%rdx, 8);"
		:::"eax", "ebx", "ecx", "edx", "memory");

	lhf_t lhf;
	unsigned long error_code;
	VMLAUNCH(lhf);
	if(!VMsucceed(lhf)) {
		if(VMfailValid(lhf)) {
			VMREAD(error_code, VM_INSTRUCTION_ERROR, lhf);
			cprint("vmlaunch failed with error code %ld", error_code); }
		else if(VMfailInvalid(lhf)) {
			cprint("vmlaunch failed with invalid region"); }
		errors[core]=-EINVAL;
		return; }
	
	__asm__ __volatile__(
	"return_from_exit:;"
		"mov $0x0b, %%eax;"
		"cpuid;"
		"movq (ret_rsp), %%rax;"
		"movq (%%rax, %%rdx, 8), %%rsp;"
		"movq (ret_rbp), %%rax;"
		"movq (%%rax, %%rdx, 8), %%rbp;"
		:::"eax", "ebx", "ecx", "edx", "memory");
	
	/*__asm__ __volatile__(
	"return_from_exit:"
		"movq %0, %%rsp;"
		"movq (%%rsp), %%rsp;"
		"movq %1, %%rbp;"
		"movq (%%rbp), %%rbp;"
		::"m"(state[core].return_rsp), "m"(state[core].return_rbp));*/
	
	return; }

static int __init hvc_init(void) {
	printk("–––––––––––––––––––––––––––––––––––––––––––––––––––––\n\n");
	int i, ret=0;

	ncores=num_online_cpus();
	gprint("number of online cores: %d", ncores);
	
	state=NULL;
	state=kmalloc(ncores*sizeof(state_t), __GFP_ZERO);
	if(state==NULL) {
		gprint("failed to allocate 'state' memory");
		cleanup();
		return -ENOMEM; }
	gprint("got %ld bytes for 'state':\t0x%px", ncores*sizeof(state_t), state);

	errors=NULL;
	errors=kmalloc(ncores*sizeof(int), __GFP_ZERO);
	if(errors==NULL) {
		gprint("failed to allocate 'errors' memory");
		cleanup();
		return -ENOMEM; }
	gprint("got %ld bytes for 'errors':\t0x%px", ncores*sizeof(int), errors);
	
	ret_rsp=NULL;
	ret_rsp=kmalloc(ncores*sizeof(long), __GFP_ZERO);
	if(ret_rsp==NULL) {
		gprint("failed to allocate 'ret_rsp' memory");
		cleanup();
		return -ENOMEM; }
	gprint("got %ld bytes for 'ret_rsp':\t0x%px", ncores*sizeof(long), ret_rsp);

	ret_rbp=NULL;
	ret_rbp=kmalloc(ncores*sizeof(long), __GFP_ZERO);
	if(ret_rbp==NULL) {
		gprint("failed to allocate 'ret_rbp' memory");
		cleanup();
		return -ENOMEM; }
	gprint("got %ld bytes for 'ret_rbp':\t0x%px\n", ncores*sizeof(long), ret_rbp);

	gprint("confirming vmx support");
	on_each_cpu(check_vmx_support, NULL, 1);
	if( (ret=parse_errors(i)) ) {
		gprint("vmx unsupported, aborting");
		cleanup();
		return ret; }
	gprint("vmx support confirmed\n");
	
	
	gprint("entering vmx operation");
	on_each_cpu(initialize_core, NULL, 1);
	if( (ret=parse_errors(i)) ) {
		gprint("failed to enter, aborting");
		cleanup();
		return ret; }
	gprint("vmx operation entered\n");
	
	gprint("initializing vmcss");
	on_each_cpu(fill_core_vmcs, NULL, 1);
	if( (ret=parse_errors(i)) ) {
		gprint("failed to initialize vmcs, aborting");
		cleanup();
		return ret; }
	gprint("initialized\n");
	

	//////////////////////////////////////////////////

	gprint("entering guest state");
	on_each_cpu(launch, NULL, 1);
	if( (ret=parse_errors(i)) ) {
		gprint("vm entry failed, aborting");
		cleanup();
		return ret; }
	gprint("vm entry succeeded\n");
	
	cleanup();
	
	
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
	/*lhf_t lhf;
	unsigned long reason=0xdeadbeef;
	VMREAD(reason, EXIT_REASON, lhf);
	printk("[*]  exit reason:\t0x%lx\n", reason);
	VMREAD(reason, EXIT_QUALIFICATION, lhf);
	printk("[*]  exit qual:\t\t0x%lx\n\n", reason);*/
	
	cleanup();
	
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
