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
static struct class *hvc_class=NULL;
static struct device *hvc_device=NULL;

static int global_open(struct inode *, struct file *);
static int global_close(struct inode *, struct file *);
//static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
//static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);

static struct file_operations fops = {
	.open=global_open,
//	.read=dev_read,
//	.write=dev_write,
	.release=global_close };
/////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////////
int ncores;

unsigned long *ret_rsp;
unsigned long *ret_rbp;

typedef struct __attribute__((packed)) {
	unsigned char read_low[1024];	//0x00000000 to 0x00001fff
	unsigned char read_high[1024];	//0xc0000000 to 0xc0001fff
	unsigned char write_low[1024];	//0x00000000 to 0x00001fff
	unsigned char write_high[1024]; //0xc0000000 to 0xc0001fff
} msr_bitmap_t;
unsigned long msr_bitmap;
#define set_rdmsr_bmp(val) \
if(val<=0x1fff) { \
	((msr_bitmap_t *)msr_bitmap)->read_low[(val)>>3]|=1<<((val)&0x07); } \
else if(val>=0xc0000000 && val<=0xc0001fff) { \
	((msr_bitmap_t *)msr_bitmap)->read_high[(val)>>3]|=1<<((val)&0x07); }
#define set_wrmsr_bmp(val) \
if(val<=0x1fff) { \
	((msr_bitmap_t *)msr_bitmap)->write_low[(val)>>3]|=1<<((val)&0x07); } \
else if(val>=0xc0000000 && val<=0xc0001fff) { \
	((msr_bitmap_t *)msr_bitmap)->write_high[(val)>>3]|=1<<((val)&0x07); }
//((msr_bitmap_t *)msr_bitmap)->read_low[0x277>>3]|=1<<(0x277&0x07);

int *errors=NULL;	//every entry should be non-positive
#define parse_errors(i) ({ for(i=0;i<ncores;i++) { if(errors[i]) break; } (i==ncores) ? 0:errors[i]; })

state_t *state=NULL;
//////////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////////
//static void hook(struct guest_regs *regs_p);
//push regs, mov %rsp, first arg (rax?)
//specify calling convention? gcc
__attribute__((__used__))
static void hook(regs_t *regs_p) {
	int core=smp_processor_id();
	
	lhf_t lhf;
	
	unsigned long reason=0xdeadbeef, qual=0xfeed;
	unsigned long cpl;
	
	VMREAD(cpl, GUEST_CS_SELECTOR, lhf);
	cpl &= 0x03;
	
	VMREAD(reason, EXIT_REASON, lhf);
	VMREAD(qual, EXIT_QUALIFICATION, lhf);
	cprint("exit reason: 0x%lx\t\texit qual: 0x%lx", reason, qual);
	cprint("cpl: %ld", cpl);
	
	cprint("rax: 0x%lx\t\tr8: 0x%lx", regs_p->rax, regs_p->r8);
	
	/*switch (reason) {
	case ER_CPUID:
		if(regs->rax==EXIT_ROOT_RAX && regs->rcx==EXIT_ROOT_RCX) {
			cprint("vmx exit requested"); }
		if(cpl>0) {
			cprint("cpl non-zero"); }
		cprint("exit from cpuid");
		break;
	case ER_RDMSR:
	default:
		cprint("cannot handle");
		break; };
	
	unsigned long rip, length;
	VMREAD(rip, GUEST_RIP, lhf);
	VMREAD(length, EXIT_INSTRUCTION_LENGTH, lhf);
	rip+=length;
	VMWRITE(rip, GUEST_RIP, lhf);*/
	
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
	"mov $0x277, %rcx;"
	"rdmsr;"
	"rdtsc;"
	"mov $0xdeadbeef, %eax;"
	"mov $0xfeeddeaf, %r8;"
	"push %rax;"
	"hlt;");
extern void guest_stub(void);
//////////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////////
static void core_exit(void *info) {
	int core=smp_processor_id();
	errors[core]=0;
	
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

static void global_exit(void) {
	if(state==NULL) {
		return; }
	
	printk("–––––––––––––––––––––––––––––––––––––––––––––––––––––\n\n");
	gprint("cleaning up cores");
	on_each_cpu(core_exit, NULL, 1);
	gprint("all clean\n");
	
	if(msr_bitmap) {
		free_page(msr_bitmap);
		gprint("freed 'msr_bitmap':\t0x%lx", msr_bitmap);
		msr_bitmap=0; }
	
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
	
	device_destroy(hvc_class, MKDEV(major_num, 0));
	class_unregister(hvc_class);
	class_destroy(hvc_class);
	unregister_chrdev(major_num, DEVICE_NAME);
	
	return; }
//////////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////////
static void core_close(void *info) {
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
	
	return; }

static int global_close(struct inode *inodep, struct file *filep) {
	printk("–––––––––––––––––––––––––––––––––––––––––––––––––––––\n\n");
	gprint("exiting vmx operation");
	on_each_cpu(core_close, NULL, 1);
	gprint("exited\n");
	printk("–––––––––––––––––––––––––––––––––––––––––––––––––––––\n\n");
	return 0; }
//////////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////////
void core_launch(void *info) {
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

static void core_open(void *info) {
	int core=smp_processor_id();
	errors[core]=0;
	
	(void)memset((void *)state[core].vmxon_region, 0, 4096);
	(void)memset((void *)state[core].vmcs_region, 0, 4096);
	cprint("zeroed:\tvmxon region: 0x%lx\t\tvmcs region: 0x%lx",
	       state[core].vmxon_region, state[core].vmcs_region);
	
	cr4_t cr4;
	__asm__ __volatile__("mov %%cr4, %0":"=r"(cr4.val));
	state[core].old_cr4.val=cr4.val;
	cr4.vmxe=1;
	__asm__ __volatile__("mov %0, %%cr4"::"r"(cr4.val));
	cprint("set cr4.vmxe[bit 13]:\t0x%lx => 0x%lx", state[core].old_cr4.val, cr4.val);
	
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

static int global_open(struct inode *inodep, struct file *filep) {
	printk("–––––––––––––––––––––––––––––––––––––––––––––––––––––\n\n");
	int ret=0, i=0;
	
	(void)memset((void *)msr_bitmap, 0, 4096);
	gprint("zeroed msr bitmap:\t0x%lx\n", msr_bitmap);
	//set_rdmsr_bmp(0x277);
	//((msr_bitmap_t *)msr_bitmap)->read_low[0x277>>3]|=1<<(0x277&0x07);
	//TODO must handle appropriately here
	
	gprint("entering vmx operation");
	on_each_cpu(core_open, NULL, 1);
	if( (ret=parse_errors(i)) ) {
		gprint("failed to enter, aborting\n");
		printk("–––––––––––––––––––––––––––––––––––––––––––––––––––––\n\n");
		global_close(inodep, filep);
		return ret; }
	gprint("vmx operation entered\n");
	
	gprint("initializing vmcss");
	on_each_cpu(core_fill_vmcs, NULL, 1);
	if( (ret=parse_errors(i)) ) {
		gprint("failed to initialize vmcs, aborting\n");
		printk("–––––––––––––––––––––––––––––––––––––––––––––––––––––\n\n");
		global_close(inodep, filep);
		return ret; }
	gprint("initialized\n");

	gprint("entering guest state");
	on_each_cpu(core_launch, NULL, 1);
	if( (ret=parse_errors(i)) ) {
		gprint("vm entry failed, aborting\n");
		printk("–––––––––––––––––––––––––––––––––––––––––––––––––––––\n\n");
		global_close(inodep, filep);
		return ret; }
	gprint("vm entry succeeded\n");
	
	printk("–––––––––––––––––––––––––––––––––––––––––––––––––––––\n\n");

	return 0; }
//////////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////////
static void __init core_check_vmx_support(void *info) {
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

static void __init core_init(void *info) {
	int core=smp_processor_id();
	state[core]=(state_t) {0};
	errors[core]=0;
	
	int ret=0;
	
	state[core].msr_bitmap=msr_bitmap;
	state[core].msr_paddr=virt_to_phys((void *)msr_bitmap);

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

	return; }

static int __init global_init(void) {
	printk("–––––––––––––––––––––––––––––––––––––––––––––––––––––\n\n");
	int i, ret=0;

	ncores=num_online_cpus();
	gprint("number of online cores: %d", ncores);
	
	state=NULL;
	state=kmalloc(ncores*sizeof(state_t), __GFP_ZERO);
	if(state==NULL) {
		gprint("failed to allocate 'state' memory\n");
		printk("–––––––––––––––––––––––––––––––––––––––––––––––––––––\n\n");
		global_exit();
		return -ENOMEM; }
	gprint("got %ld bytes for 'state':\t0x%px", ncores*sizeof(state_t), state);

	errors=NULL;
	errors=kmalloc(ncores*sizeof(int), __GFP_ZERO);
	if(errors==NULL) {
		gprint("failed to allocate 'errors' memory\n");
		printk("–––––––––––––––––––––––––––––––––––––––––––––––––––––\n\n");
		global_exit();
		return -ENOMEM; }
	gprint("got %ld bytes for 'errors':\t0x%px", ncores*sizeof(int), errors);
	
	ret_rsp=NULL;
	ret_rsp=kmalloc(ncores*sizeof(long), __GFP_ZERO);
	if(ret_rsp==NULL) {
		gprint("failed to allocate 'ret_rsp' memory\n");
		printk("–––––––––––––––––––––––––––––––––––––––––––––––––––––\n\n");
		global_exit();
		return -ENOMEM; }
	gprint("got %ld bytes for 'ret_rsp':\t0x%px", ncores*sizeof(long), ret_rsp);

	ret_rbp=NULL;
	ret_rbp=kmalloc(ncores*sizeof(long), __GFP_ZERO);
	if(ret_rbp==NULL) {
		gprint("failed to allocate 'ret_rbp' memory\n");
		printk("–––––––––––––––––––––––––––––––––––––––––––––––––––––\n\n");
		global_exit();
		return -ENOMEM; }
	gprint("got %ld bytes for 'ret_rbp':\t0x%px", ncores*sizeof(long), ret_rbp);
	
	msr_bitmap=0;
	msr_bitmap=get_zeroed_page(GFP_KERNEL);
	if(!msr_bitmap) {
		gprint("failed to allocate 'msr_bitmap' page\n");
		printk("–––––––––––––––––––––––––––––––––––––––––––––––––––––\n\n");
		global_exit();
		return -ENOMEM; }
	gprint("got page for msr bitmap:\t\t0x%lx\n", msr_bitmap);

	gprint("confirming vmx support");
	on_each_cpu(core_check_vmx_support, NULL, 1);
	if( (ret=parse_errors(i)) ) {
		gprint("vmx unsupported, aborting\n");
		printk("–––––––––––––––––––––––––––––––––––––––––––––––––––––\n\n");
		global_exit();
		return ret; }
	gprint("vmx support confirmed\n");
	
	
	gprint("allocating vmm memory");
	on_each_cpu(core_init, NULL, 1);
	if( (ret=parse_errors(i)) ) {
		gprint("failed to enter, aborting\n");
		printk("–––––––––––––––––––––––––––––––––––––––––––––––––––––\n\n");
		global_exit();
		return ret; }
	gprint("all allocated\n");
	
	printk("–––––––––––––––––––––––––––––––––––––––––––––––––––––\n\n");
	
	
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
//////////////////////////////////////////////////////////////////////////////////


module_init(global_init);
module_exit(global_exit);
