/*
 * October 30 2014, Christian Hopps <chopps@gmail.com>
 *
 * Copyright (c) 2014 by Christian E. Hopps.
 * All rights reserved.
 */
#include <stdio.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <net/if.h>
#include <net/if_arp.h>

#define xstr(s) str(s)
#define str(s)  #s
#define PV(_x, _y)   printf("%s = 0x%x\n", _x, (u_int)_y)

int
main(int argc, char **argv)
{
    PV("BIOCGBLEN", BIOCGBLEN);
    PV("BIOCSBLEN", BIOCSBLEN);
    PV("BIOCSETF", BIOCSETF);
    PV("BIOCFLUSH", BIOCFLUSH);
    PV("BIOCPROMISC", BIOCPROMISC);
    PV("BIOCGDLT", BIOCGDLT);
    PV("BIOCGETIF", BIOCGETIF);
    PV("BIOCSETIF", BIOCSETIF);
    PV("BIOCSRTIMEOUT", BIOCSRTIMEOUT);
    PV("BIOCGRTIMEOUT", BIOCGRTIMEOUT);
    PV("BIOCGSTATS", BIOCGSTATS);
    PV("BIOCIMMEDIATE", BIOCIMMEDIATE);
    PV("BIOCVERSION", BIOCVERSION);
    PV("BIOCGRSIG", BIOCGRSIG);
    PV("BIOCSRSIG", BIOCSRSIG);
    PV("BIOCGHDRCMPLT", BIOCGHDRCMPLT);
    PV("BIOCSHDRCMPLT", BIOCSHDRCMPLT);
    PV("BIOCGSEESENT", BIOCGSEESENT);
    PV("BIOCSSEESENT", BIOCSSEESENT);
    PV("BIOCSDLT", BIOCSDLT);
    PV("BIOCGDLTLIST", BIOCGDLTLIST);
    PV("BIOCSETFNR", BIOCSETFNR);
    PV("SIOCGIFADDR", SIOCGIFADDR);
    PV("SIOCGIFHWADDR", SIOCGIFHWADDR);
}
