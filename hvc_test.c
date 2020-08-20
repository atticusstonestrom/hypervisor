#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int main() {
	int fd; 
	if( (fd=open("/dev/hvchar", O_RDWR))<0 ){
		perror("fatal in open");
		return errno; }
	getchar();
	if(close(fd)) {
		perror("fatal in close");
		return errno; }
	return 0; }
