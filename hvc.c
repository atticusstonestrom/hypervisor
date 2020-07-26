//////////////////////////////////////////////////////
//                                                  //
//                                                  //
//                                                  //
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
	void *vmxon_region;
	void *vmcs_region;
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
	if(msr.ia32_feature_control.lock) {
		printk("[**] vmx locked in bios\n");
		//should check if current processor state is smx
		if(!msr.ia32_feature_control.non_smx_vmxe) {
			printk("[*] non-smx vmx disabled\n");
			__asm__ __volatile__("mov %0, %%cr4"::"r"(initial_cr4.val));
			return -EOPNOTSUPP; }
		printk("[**] non-smx vmx enabled\n"); }
	else {
		printk("[**] enabling non-smx vmx\n");
		msr.ia32_feature_control.non_smx_vmxe=1;
		printk("[**] locking feature control\n");
		msr.ia32_feature_control.lock=1;
		printk("[**] writing value:\t0x%lx\n", msr.val);
		WRITE_MSR(msr, IA32_FEATURE_CONTROL); }
	printk("[*]  parse complete\n\n");
	
	READ_MSR(msr, IA32_PAT);
	int i=0;
	for(i=0; i<8; i++) {
		printk("[*] pat %d: 0x%02x\n", i, msr.ia32_pat.entries[i]); }
	printk("[*] ia32_pat:\t0x%lx\n", msr.val);
	
	unsigned long my_page;
	my_page=get_zeroed_page(GFP_KERNEL);
	printk("[*] mypage:\t0x%lx\n", my_page);
	if(!my_page) {
		return -ENOMEM; }
	vtp_t vtp_s=(vtp_t){0};
	unsigned long paddr;
	if(vtp(my_page, &paddr, &vtp_s)) {
		return 1; }
	if(vtp_s.pml5e_p) {
		printk("[debug]: &pml5e:\t0x%px\n", vtp_s.pml5e_p);
		printk("[debug]: pml5e:\t0x%lx\n", *(unsigned long *)(vtp_s.pml5e_p)); }
	if(vtp_s.pml4e_p) {
		printk("[debug]: &pml4e:\t0x%px\n", vtp_s.pml4e_p);
		printk("[debug]: pml4e:\t0x%lx\n", *(unsigned long *)(vtp_s.pml4e_p)); }
	if(vtp_s.pdpte_p) {
		printk("[debug]: &pdpte:\t0x%px\n", vtp_s.pdpte_p);
		printk("[debug]: pdpte:\t0x%lx\n", *(unsigned long *)(vtp_s.pdpte_p)); }
	if(vtp_s.pde_p) {
		printk("[debug]: &pde:\t0x%px\n", vtp_s.pde_p);
		printk("[debug]: pde:\t0x%lx\n", *(unsigned long *)(vtp_s.pde_p)); }
	if(vtp_s.pte_p) {
		printk("[debug]: &pte:\t0x%px\n", vtp_s.pte_p);
		printk("[debug]: pte:\t0x%lx\n", *(unsigned long *)(vtp_s.pte_p)); }
	printk("[*] paddr:\t0x%lx\n", paddr);
	printk("[*] vtp:\t0x%lx\n", (unsigned long)virt_to_phys((void *)my_page));
	printk("[*] some long:\t0x%lx\n", *(unsigned long *)(my_page+80));
	free_page(my_page);
	
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
	
	device_destroy(hvc_class, MKDEV(major_num, 0));
	class_unregister(hvc_class);
	class_destroy(hvc_class);
	unregister_chrdev(major_num, DEVICE_NAME);
	printk("[*] lkm unloaded\n"); }

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
