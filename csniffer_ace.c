/*
 *  $Id$
 *
 *  Building Open Source Network Security Tools
 *  csniffer_ace.c - builds an OUI header file for use with csniffer.c
 *                   Use the ASCII file downloaded from:
 *                   http://standards.ieee.org/regauth/oui
 *
 *  Copyright (c) 2002 Mike D. Schiffman <mike@infonexus.com>
 *  All rights reserved.
 */

#include <libnet.h>

#define OUI_PREAMBLE "
/*
 *  Organizationally Unique Identifier list.
 *  This list contains all of the MAC address prefix to organization
 *  identifier mappings.  This header file was auto-generated and should not
 *  be modified.
 *
 */

struct oui
{
    u_char prefix[3];       /* 24 bit global prefix */
    char *vendor;           /* vendor id string */
};

struct oui oui_table[] = {
"

int main(int argc, char **argv)
{
    int i, j, k;
    FILE *fp_in;
    FILE *fp_ou;
    char read_buf[BUFSIZ];
    char writ_buf[BUFSIZ];

    if (argc != 2)
    {
        fprintf(stderr, "用法: %s oui.txt\n", argv[0]);
        fprintf(stderr, "请确保 OUI 文件来源于: ");
        fprintf(stderr, "http://standards.ieee.org/regauth/oui\n");
        return (EXIT_FAILURE);
    }

    fp_in = fopen(argv[1], "r");
    if (fp_in == NULL)
    {
        fprintf(stderr, "无法打开 %s : %s\n", argv[1], strerror(errno));
        return (EXIT_FAILURE);
    }
    fp_ou = fopen("oui.h", "w");
    if (fp_ou == NULL)
    {
        fprintf(stderr, "无法打开 \"oui.h\" : %s\n", strerror(errno));
        return (EXIT_FAILURE);
    }

            
    if (write(fileno(fp_ou), OUI_PREAMBLE, strlen(OUI_PREAMBLE))
            != strlen(OUI_PREAMBLE))
    {
        fprintf(stderr, "写入失败: %s\n", strerror(errno));
        return (EXIT_FAILURE);
    }

    i = 0;
    while (fgets(read_buf, BUFSIZ - 1, fp_in))
    {
        if (isxdigit(read_buf[0]) && isxdigit(read_buf[1]) &&
                read_buf[2] == '-')
        {
            i++;
            fprintf(stderr, "正在处理条目: %d\r", i);
            memset(writ_buf, 0, BUFSIZ);

            memcpy(writ_buf, "    { { 0x", 10);
            memcpy(writ_buf + 10, &read_buf[0], 1);
            memcpy(writ_buf + 11, &read_buf[1], 1);
            memcpy(writ_buf + 12, ", 0x", 4);
            memcpy(writ_buf + 16, &read_buf[3], 1);
            memcpy(writ_buf + 17, &read_buf[4], 1);
            memcpy(writ_buf + 18, ", 0x", 4);
            memcpy(writ_buf + 22, &read_buf[6], 1);
            memcpy(writ_buf + 23, &read_buf[7], 1);
            memcpy(writ_buf + 24, " }, \"", 5);

            for (j = 18 + 14, k = 29; read_buf[j] != '\n'; j++, k++)
            {
                writ_buf[k] = read_buf[j];
            }
            memcpy(writ_buf + k, "\" },\n", 5);

            j = strlen(writ_buf);
            if (write(fileno(fp_ou), writ_buf, j) != j)
            {
                fprintf(stderr, "写入失败: %s\n", strerror(errno));
                return (EXIT_FAILURE);
            }
        }
    }

    memcpy(writ_buf, "\n};\n\n/* EOF */\n", 15);

    if (fseek(fp_ou, -2, SEEK_CUR) == -1)
    {
        fprintf(stderr, "fseek 失败: %s\n", strerror(errno));
        return (EXIT_FAILURE);
    }

    if (write(fileno(fp_ou), writ_buf, 15) != 15)
    {
        fprintf(stderr, "写入失败: %s\n", strerror(errno));
        return (EXIT_FAILURE);
    }

    fprintf(stderr, "\n完成，已生成 oui.h，共 %d 条记录\n", i);
    return (EXIT_SUCCESS);
}

/* EOF */
