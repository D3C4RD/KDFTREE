#include "kdf_tree.h"
#include "auth.h"
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include "cel.h"
int get_rand(uint8_t* IV,int n)
{
    int FD=open("/dev/urandom",O_RDONLY);
    if(FD<0)
    {
        printf("FILE /dev/urandom didnt open\n");
        return -1;
    }
    if(read(FD,IV,n)<0)
    {
        printf("Can't read file\n");
        close(FD);
        return -2;
    }
    close(FD);
    return 0;
}

int main()
{
    if(!auth())
    {
        return 0;
    }
    if(!testKdf_tree())
    {
        log("tests failed");
        log("session end\n");
        return;
    }
    log("test passed");
    uint8_t h[32];
    int exe=open("a.out",O_RDONLY);
    get_h(exe,h);
    close(exe);
    uint8_t h1[32];
    exe=open("integ",O_RDONLY);
    read(exe,h1,32);
    if(!cmp(h,h1,32))
    {
        log("exe file is wrong");
        log("session end\n");
        printf("exe file is wrong");
        return 0;
    }
    log("exe file is valid");
    printf("Enter number of keys:");
    unsigned int keys;
    scanf("%u",&keys);
    uint8_t res[keys*32];
    uint8_t key[64];
    get_rand(key,64);
    int L=keys*256;
    kdf_tree(res,key,64,4,L);
    get_rand(key,64);
    printf("Keys:\n\t");
    print_arr(res,keys*32);
    int fd=creat("keys",0666);
    write(fd,res,keys*32);
    close(fd);
    fd=open("keys",O_RDONLY);
    get_h(fd,h);
    close(fd);
    fd=creat("keys",0666);
    write(fd,h,32);
    write(fd,res,keys*32);
    get_rand(res,keys*32);
    log("key cleared");
    close(fd);
    log("session end\n");
    return 0;
}