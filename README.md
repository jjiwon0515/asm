# asm

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <seccomp.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <unistd.h>

#define LENGTH 128

void sandbox(){
        scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
        if (ctx == NULL) {
                printf("seccomp error\n");
                exit(0);
        }

        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

        if (seccomp_load(ctx) < 0){
                seccomp_release(ctx);
                printf("seccomp error\n");
                exit(0);
        }
        seccomp_release(ctx);
}

char stub[] = "\x48\x31\xc0\x48\x31\xdb\x48\x31\xc9\x48\x31\xd2\x48\x31\xf6\x48\x31\xff\x48\x31\xed\x4d\x31\xc0\x4d\x31\xc9\x4d\x31\xd2\x4d\x31\xdb\x4d\x31\xe4\x4d\x31\xed\x4d\x31\xf6\x4d\x31\xff";
unsigned char filter[256];
int main(int argc, char* argv[]){

        setvbuf(stdout, 0, _IONBF, 0);
        setvbuf(stdin, 0, _IOLBF, 0);

        printf("Welcome to shellcoding practice challenge.\n");
        printf("In this challenge, you can run your x64 shellcode under SECCOMP sandbox.\n");
        printf("Try to make shellcode that spits flag using open()/read()/write() systemcalls only.\n");
        printf("If this does not challenge you. you should play 'asg' challenge :)\n");

        char* sh = (char*)mmap(0x41414000, 0x1000, 7, MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE, 0, 0);
        memset(sh, 0x90, 0x1000);
        memcpy(sh, stub, strlen(stub));

        int offset = sizeof(stub);
        printf("give me your x64 shellcode: ");
        read(0, sh+offset, 1000);

        alarm(10);
        chroot("/home/asm_pwn");        // you are in chroot jail. so you can't use symlink in /tmp
        sandbox();
        ((void (*)(void))sh)();
        return 0;
}  


```asm
0x0000000000000d64 <+0>:     push   rbp
   0x0000000000000d65 <+1>:     mov    rbp,rsp
   0x0000000000000d68 <+4>:     sub    rsp,0x20
   0x0000000000000d6c <+8>:     mov    DWORD PTR [rbp-0x14],edi
   0x0000000000000d6f <+11>:    mov    QWORD PTR [rbp-0x20],rsi
   0x0000000000000d73 <+15>:    mov    rax,QWORD PTR [rip+0x201256]        # 0x201fd0
   0x0000000000000d7a <+22>:    mov    rax,QWORD PTR [rax]
   0x0000000000000d7d <+25>:    mov    ecx,0x0
   0x0000000000000d82 <+30>:    mov    edx,0x2
   0x0000000000000d87 <+35>:    mov    esi,0x0
   0x0000000000000d8c <+40>:    mov    rdi,rax
   0x0000000000000d8f <+43>:    call   0xaf0 <setvbuf@plt>
   0x0000000000000d94 <+48>:    mov    rax,QWORD PTR [rip+0x20123d]        # 0x201fd8
   0x0000000000000d9b <+55>:    mov    rax,QWORD PTR [rax]
   0x0000000000000d9e <+58>:    mov    ecx,0x0
   0x0000000000000da3 <+63>:    mov    edx,0x1
   0x0000000000000da8 <+68>:    mov    esi,0x0
   0x0000000000000dad <+73>:    mov    rdi,rax
   0x0000000000000db0 <+76>:    call   0xaf0 <setvbuf@plt>
   0x0000000000000db5 <+81>:    lea    rdi,[rip+0x18c]        # 0xf48
   0x0000000000000dbc <+88>:    call   0xa40 <puts@plt>
   0x0000000000000dc1 <+93>:    lea    rdi,[rip+0x1b0]        # 0xf78
   0x0000000000000dc8 <+100>:   call   0xa40 <puts@plt>
   0x0000000000000dcd <+105>:   lea    rdi,[rip+0x1f4]        # 0xfc8
   0x0000000000000dd4 <+112>:   call   0xa40 <puts@plt>
   0x0000000000000dd9 <+117>:   lea    rdi,[rip+0x240]        # 0x1020
   0x0000000000000de0 <+124>:   call   0xa40 <puts@plt>
   0x0000000000000de5 <+129>:   mov    r9d,0x0
   0x0000000000000deb <+135>:   mov    r8d,0x0
   0x0000000000000df1 <+141>:   mov    ecx,0x32
   0x0000000000000df6 <+146>:   mov    edx,0x7
   0x0000000000000dfb <+151>:   mov    esi,0x1000
   0x0000000000000e00 <+156>:   mov    edi,0x41414000
   0x0000000000000e05 <+161>:   call   0xa70 <mmap@plt>
   0x0000000000000e0a <+166>:   mov    QWORD PTR [rbp-0x8],rax
   0x0000000000000e0e <+170>:   mov    rax,QWORD PTR [rbp-0x8]
   0x0000000000000e12 <+174>:   mov    edx,0x1000
   0x0000000000000e17 <+179>:   mov    esi,0x90
   0x0000000000000e1c <+184>:   mov    rdi,rax
   0x0000000000000e1f <+187>:   call   0xaa0 <memset@plt>
   0x0000000000000e24 <+192>:   lea    rax,[rip+0x201295]        # 0x2020c0 <stub>
   0x0000000000000e2b <+199>:   mov    rdi,rax
   0x0000000000000e2e <+202>:   call   0xa60 <strlen@plt>
   0x0000000000000e33 <+207>:   mov    rdx,rax
   0x0000000000000e36 <+210>:   mov    rax,QWORD PTR [rbp-0x8]
   0x0000000000000e3a <+214>:   lea    rcx,[rip+0x20127f]        # 0x2020c0 <stub>
   0x0000000000000e41 <+221>:   mov    rsi,rcx
   0x0000000000000e44 <+224>:   mov    rdi,rax
   0x0000000000000e47 <+227>:   call   0xae0 <memcpy@plt>
   0x0000000000000e4c <+232>:   mov    DWORD PTR [rbp-0xc],0x2e
   0x0000000000000e53 <+239>:   lea    rdi,[rip+0x209]        # 0x1063
   0x0000000000000e5a <+246>:   mov    eax,0x0
---Type <return> to continue, or q <return> to quit---
   0x0000000000000e5f <+251>:   call   0xa80 <printf@plt>
   0x0000000000000e64 <+256>:   mov    eax,DWORD PTR [rbp-0xc]
   0x0000000000000e67 <+259>:   movsxd rdx,eax
   0x0000000000000e6a <+262>:   mov    rax,QWORD PTR [rbp-0x8]
   0x0000000000000e6e <+266>:   add    rax,rdx
   0x0000000000000e71 <+269>:   mov    edx,0x3e8
   0x0000000000000e76 <+274>:   mov    rsi,rax
   0x0000000000000e79 <+277>:   mov    edi,0x0
   0x0000000000000e7e <+282>:   call   0xac0 <read@plt>
   0x0000000000000e83 <+287>:   mov    edi,0xa
   0x0000000000000e88 <+292>:   call   0xab0 <alarm@plt>
   0x0000000000000e8d <+297>:   lea    rdi,[rip+0x1ec]        # 0x1080
   0x0000000000000e94 <+304>:   call   0xa20 <chroot@plt>
   0x0000000000000e99 <+309>:   mov    eax,0x0
   0x0000000000000e9e <+314>:   call   0xc50 <sandbox>
   0x0000000000000ea3 <+319>:   mov    rax,QWORD PTR [rbp-0x8]
   0x0000000000000ea7 <+323>:   call   rax
   0x0000000000000ea9 <+325>:   mov    eax,0x0
   0x0000000000000eae <+330>:   leave  
   0x0000000000000eaf <+331>:   ret 

