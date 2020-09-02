#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>

#define VMCALL_VMXOFF 0
#define VMCALL_SET_EPT_HOOK 1

unsigned long vmcall(unsigned long func, ...) {
	va_list ap;
	va_start (ap, func);
	unsigned long args[3];
	for(int i=0; i<3; i++) { args[i]=va_arg (ap, long); }
	va_end (ap);
	unsigned long ret;
	__asm__ __volatile__("vmcall":"=a"(ret):"a"(func), "b"(args[0]), "c"(args[1]), "d"(args[2]));
	return ret; }

int main() {
	int fd; 
	if( (fd=open("/dev/hvchar", O_RDWR))<0 ){
		perror("fatal in open");
		return errno; }
	printf("entered vmx guest mode!! press return to continue\n");
	printf("(hook set at %px)\n", &&hook);
	vmcall(VMCALL_SET_EPT_HOOK, (unsigned long)&&hook);
	getchar();
hook:
	if(close(fd)) {
		perror("fatal in close");
		return errno; }
	return 0; }
