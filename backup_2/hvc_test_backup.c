#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static char rx_buffer[256];

int main() {
	int fd; 
	char tx_buffer[256];
	if( (fd=open("/dev/hvchar", O_RDWR))<0 ){
		perror("fatal in open");
		return errno; }
	printf("type in a short string to send to the kernel module:\n");
	scanf("%[^\n]%*c", tx_buffer);
	printf("writing message to the device [%s]\n", tx_buffer);
	if(write(fd, tx_buffer, strlen(tx_buffer))<0) {
		perror("fatal in write");
		return errno; }
	printf("press enter to read back from the device\n");
	getchar();
	if(read(fd, rx_buffer, sizeof(rx_buffer))<0) {
		perror("fatal in read");
		return errno; }
	printf("received: [%s]\n", rx_buffer);
	return 0; }
