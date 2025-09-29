#include <stdio.h>
#include <unistd.h>

void test_function() {
    printf("Test function called\n");
}

int main() {
    printf("Hello World\n");
    test_function();
    return 0;
}
