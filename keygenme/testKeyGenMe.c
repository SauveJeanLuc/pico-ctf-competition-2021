#include <stdio.h>    
#include <openssl/md5.h>

int main(){    


int local_98 = 0x7b4654436f636970;
int sVar1 = strlen((char *)&local_98);
MD5((uchar *)&local_98,sVar1,local_b8);

printf("sVar1: %i", local_98);    
return 0;   
}  