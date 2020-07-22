//////////////////////////////////////////////////////
//                                                  //
//                                                  //
//                                                  //
//////////////////////////////////////////////////////

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <asm/io.h>
#include "utilities.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Atticus Stonestrom");
MODULE_DESCRIPTION("Hooks the zero divisor IDT entry");
MODULE_VERSION("0.01");


#define ZD_INT 0x00
#define BP_INT 0x03
struct idte_t *idte;			//points to the start of the IDT
unsigned long zd_handler;		//contains absolute address of division error IRQ handler
unsigned long bp_handler;		//contains absolute address of soft breakpoint IRQ handler
//#define STUB_SIZE 0x2b			//includes extra 8 bytes for the old value of cr3
#define STUB_SIZE 0x2b
unsigned char orig_bytes[STUB_SIZE];	//contains the original bytes of the division error IRQ handler
struct idtr_t idtr;			//holds base address and limit value of the IDT

int counter=0;
__attribute__((__used__))
static void hook(void) {
	printk("[*] in the hook! counter %d\n", ++counter);
	return; }

__asm__(
	".text;"
	".global asm_hook;"
"asm_hook:;"
	
	
	"push %rax;"		//struct tss_t *tss
	"push %rbx;"		//struct tssd_t *tssd
	"push %rdx;"		//placeholder
	"sub $12, %rsp;"
	"sgdt (%rsp);"
	"str 10(%rsp);"
	"movzwl 10(%rsp), %ebx;"
	"addq 2(%rsp), %rbx;"
	"movzwl 2(%rbx), %eax;"
	"movzbl 4(%rbx), %edx;"
	"shl $16, %rdx;"
	"or %rdx, %rax;"
	"movzbl 7(%rbx), %edx;"
	"shl $24, %rdx;"
	"or %rdx, %rax;"
	"mov 8(%rbx), %edx;"
	"shl $32, %rdx;"
	"or %rdx, %rax;"
	
	"add $12, %rsp;"
	"pop %rdx;"
	"lea 16(%rsp), %rbx;"	//original rsp
	
	"mov 12(%rax), %rsp;"	//lock sub 12, (%rax)?
	/*"push 32(%rbx);"	//ss
	"push 24(%rbx);"	//rsp
	"push 16(%rbx);"	//rflags
	"push 8(%rbx);"		//cs
	"push (%rbx);"		//rip*/
	"push %rbx;"		//old rsp
	"mov -8(%rbx), %rax;"
	"mov -16(%rbx), %rbx;"
	
	PUSHA
	"swapgs;"
	"call hook;"
	"swapgs;"
	POPA
	
	"mov (%rsp), %rsp;"
	"movq (bp_handler), %rax;"
	"ret;");
extern void asm_hook(void);

/*__asm__(
	".text;"
	".global stub;"
"stub:;"
	"push %rax;"	//bp_handler	
	"push %rbx;"	//new cr3, &asm_hook
	"push %rdx;"	//old cr3
	"mov %cr3, %rdx;"
	"mov .CR3(%rip), %rbx;"
	"mov %rbx, %cr3;"
	"mov $asm_hook, %rbx;"
	"call *%rbx;"
	"mov %rdx, %cr3;"
	"pop %rdx;"
	"pop %rbx;"
	"xchg %rax, (%rsp);"
	"ret;"
".CR3:;"
	//will be filled with a valid value of cr3 during module initialization
	".quad 0xdeadbeefdeadbeef;");*/
__asm__(
	".text;"
	".global stub;"
"stub:;"
	"push %rax;"	//bp_handler	
	"push %rbx;"	//new cr3, &asm_hook
	"push %rdx;"	//old cr3
	"mov %cr3, %rdx;"
	"mov %rdx, %rbx;"
	"bts $0x3f, %rbx;"
	"and $0xffffffffffffe7ff, %rbx;"
	"mov %rbx, %cr3;"
	"mov $asm_hook, %rbx;"
	"call *%rbx;"
	"mov %rdx, %cr3;"
	"pop %rdx;"
	"pop %rbx;"
	"xchg %rax, (%rsp);"
	"ret;");
extern void stub(void);

static int __init
idt_init(void) {
	READ_IDT(idtr)
	printk("[*]  idtr dump\n"
	       "[**] address:\t0x%px\n"
	       "[**] lim val:\t0x%x\n"
	       "[*]  end dump\n\n",
	       idtr.addr, idtr.lim_val);
	idte=(idtr.addr);

	zd_handler=0
		| ((long)((idte+ZD_INT)->offset_0_15))
		| ((long)((idte+ZD_INT)->offset_16_31)<<16)
		| ((long)((idte+ZD_INT)->offset_32_63)<<32);
	printk("[*]  idt entry %d:\n"
	       "[**] addr:\t0x%px\n"
	       "[**] segment:\t0x%x\n"
	       "[**] ist:\t%d\n"
	       "[**] type:\t%d\n"
	       "[**] dpl:\t%d\n"
	       "[**] p:\t\t%d\n"
	       "[*]  end dump\n\n",
	       ZD_INT, (void *)zd_handler, (idte+ZD_INT)->segment_selector, (idte+ZD_INT)->ist,
	       (idte+ZD_INT)->type, (idte+ZD_INT)->dpl, (idte+ZD_INT)->p);
	if(!(idte+ZD_INT)->p) {
		printk("[*] fatal: handler segment not present\n");
		return ENOSYS; }
		
	bp_handler=0
		| ((long)((idte+BP_INT)->offset_0_15))
		| ((long)((idte+BP_INT)->offset_16_31)<<16)
		| ((long)((idte+BP_INT)->offset_32_63)<<32);
	printk("[*] bp handler:\t0x%lx\n\n", bp_handler);


	/*unsigned long cr3;
	__asm__ __volatile__("mov %%cr3, %0":"=r"(cr3)::"memory");
	printk("[*] cr3:\t0x%lx\n\n", cr3);*/

	memcpy(orig_bytes, (void *)zd_handler, STUB_SIZE);
	DISABLE_RW_PROTECTION
	__asm__ __volatile__("cli":::"memory");
	memcpy((void *)zd_handler, &stub, STUB_SIZE);
	//*(unsigned long *)(zd_handler+STUB_SIZE-8)=cr3;
	__asm__ __volatile__("sti":::"memory");
	ENABLE_RW_PROTECTION

	return 0; }

static void __exit
idt_fini(void) {
	printk("[*] counter: %d\n\n", counter);

	DISABLE_RW_PROTECTION
	__asm__ __volatile__("cli":::"memory");
	memcpy((void *)zd_handler, orig_bytes, STUB_SIZE);
	__asm__ __volatile__("sti":::"memory");
	ENABLE_RW_PROTECTION }

module_init(idt_init);
module_exit(idt_fini);
