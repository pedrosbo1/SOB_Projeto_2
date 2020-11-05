/**
 * 16507915 - Agostinho Sanches de Araujo
 * 16023905 - Evandro Douglas Capovilla Junior
 * 16105744 - Lucas Tenani Felix Martins
 * 16124679 - Pedro Andrade Caccavaro
 * 15248354 - Pedro Angelo Catalini
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

int main(){
	int fd;
	ssize_t ret;
	char file_content[200] = "", aux[200], target_file[100], secret_string[3200], final[200];
	
	// Get the name of the target file to encrypt and save the content
	printf("Enter the file name to encrypt: ");
	scanf("%[^\n]", target_file);	
	fd = open(target_file, O_RDONLY, 0666);
	while(read(fd, aux, sizeof(char))){
		strcat(file_content,aux);
	}
	close(fd);
	
	// create the secret file and use the sycall to store the cypher content
	fd = open("secret_file.txt", O_WRONLY|O_CREAT, 0666);
	ret = syscall(333, fd, file_content, strlen(file_content));
	if (ret < 0){
		printf("Operation Write Failed\n");
		return -1;
	}
	close(fd);
	
	// open this file and check the cipher content
	fd = open("secret_file.txt", O_RDONLY|O_CREAT, 0666);
	strcpy(aux,"");
	while(read(fd, aux, sizeof(char))){
		strcat(secret_string,aux);
	}
	printf("Secret file: %s", secret_string);
	close(fd);
	
	// use syscall to decypher the content and print
	fd = open("secret_file.txt", O_RDONLY|O_CREAT, 0666);
	ret = syscall(334, fd, final, strlen(file_content));
	if (ret < 0){
		printf("Operation Write Failed\n");
		return -1;
	}
	printf("Decrypted file: %s\n", final);
	return 0;
}
