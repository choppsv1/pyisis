/*
 * Copyright (c) 2014 by Christian E. Hopps.
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
