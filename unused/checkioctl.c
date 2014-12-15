/*
 * October 30 2014, Christian Hopps <chopps@gmail.com>
 *
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
