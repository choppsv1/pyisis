/*
 * From RFC 1008: 7.2.1
 */
#define MODX 4102

int
encodecc (unsigned char mess[], int len, int k)
{
    int ip,
        iq,
        ir,
        c0,
        c1;
    unsigned char *p,*p1,*p2,*p3 ;

    p = mess;
    p3 = mess + len;

    /* insert zeros for checksum octets */
    if ( k > 0) {
        mess[k-1] = 0x00;
        mess[k] = 0x00;
    }

    c0 = 0;
    c1 = 0;
    p1 = mess;
    /* outer sum accumulation loop */
    while (p1 < p3) {
        p2 = p1 + MODX;
        if (p2 > p3)
            p2 = p3;
        /*  inner sum accumulation loop */
        for (p = p1 ; p < p2 ; p++) {
            c0 = c0 + (*p);
            c1 = c1 + c0 ;
        }
        /* adjust accumulated sums to mod 255 */
        c0 = c0%255;
        c1 = c1%255;
        p1 = p2 ;
    }

    /* concatenate c1 and c0 */
    ip = (c1 << 8) + c0;

    /* compute and insert checksum octets */
    if (k > 0) {
        iq = ((len-k)*c0 - c1) % 255;
        if (iq <= 0)
            iq = iq + 255;
        mess[k-1] = iq;
        ir = (510 - c0 - iq);
        if (ir > 255)
            ir = ir - 255;
        mess[k] = ir;
    }

    return (ip);
}

