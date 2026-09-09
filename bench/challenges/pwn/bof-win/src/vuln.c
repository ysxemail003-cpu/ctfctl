#include <stdio.h>
#include <unistd.h>
int main(void) {
    char buf[32];
    int win = 0;
    puts(">");
    fflush(stdout);
    read(0, buf, 200);
    if (win == 0x1337) {
        char f[] = {'f','l','a','g','{','p','w','n','_','b','o','f','_','w','i','n','}','\0'};
        puts(f);
        return 0;
    }
    puts("nope");
    return 1;
}
