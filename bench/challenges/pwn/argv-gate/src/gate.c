#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "s3cr3t_pw") == 0) {
        char flag[] = {'f','l','a','g','{','p','w','n','_','a','r','g','v','_','g','a','t','e','}','\0'};
        puts(flag);
        return 0;
    }
    puts("access denied");
    return 1;
}
