/*
 * October 2014, Christian Hopps <chopps@gmail.com>
 *
 * Copyright (c) 2014 by Christian E. Hopps.
 * All rights reserved.
 *
 * REDISTRIBUTION IN ANY FORM PROHIBITED WITHOUT PRIOR WRITTEN
 * CONSENT OF THE AUTHOR.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <net/if.h>
#include <err.h>

int
main(int argc, char **argv)
{
    const char* interface = "vboxnet0";
    struct ifreq bound_if;
    char buf[ 11 ] = { 0 };
    int i, rv;
    int bpf = 0;
    int buf_len = 1;

    for (i = 0; i < 99; i++) {
        sprintf( buf, "/dev/bpf%i", i);
        if ((bpf = open( buf, O_RDWR)) != -1)
            break;
    }
    if (i == 99)
        err(-1, "open");

    strcpy(bound_if.ifr_name, interface);
    if ((rv = ioctl( bpf, BIOCSETIF, &bound_if)) != 0)
        err(-1, "BIOCSETIF");
    printf("BIOCSETIF rv: %d\n", rv);

    // activate immediate mode (therefore, buf_len is initially set to "1")
    if ((rv = ioctl( bpf, BIOCIMMEDIATE, &buf_len)) == -1)
        err(-1, "BIOCIMMEDIATE");
    printf("BIOCIMMEDIATE rv: %d buf_len %d\n", rv, buf_len);

    // request buffer length
    if ((rv = ioctl( bpf, BIOCGBLEN, &buf_len)) == -1)
        err(-1, "BIOCGBLEN");
    printf("BIOCGBLEN rv: %d buf_len %d\n", rv, buf_len);
}
