/*
 * examples/input/sample.c
 *
 * 占位示例输入。TODO: 替换为你自己的 C 源码。
 * 约定：污点分析严格限制在本文件内（不跨文件）。
 * 本示例仅用于让流程跑通，不保证包含真实漏洞，也不代表任何结论。
 */
#include <stdio.h>
#include <string.h>

static void copy_into(char *dst, const char *src, size_t n) {
    /* TODO: 示例函数占位。 */
    strncpy(dst, src, n);
}

int main(int argc, char **argv) {
    char buf[64];

    if (argc > 1) {
        copy_into(buf, argv[1], sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
    }

    printf("%s\n", buf);
    return 0;
}
