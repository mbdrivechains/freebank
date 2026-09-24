#ifndef BITCOIN_CHAINPARAMSSEEDS_H
#define BITCOIN_CHAINPARAMSSEEDS_H
/**
 * List of fixed seed nodes for the FreeBank network.
 * HAND-MAINTAINED (FreeBank): do NOT regenerate with contrib/seeds/generate-seeds.py.
 * contrib/seeds/nodes_main.txt is upstream Bitcoin data (:8333 nodes), and the script
 * would also emit pnSeed6_test and drop these comments.
 *
 * Each line contains a 16-byte IPv6 address and a port.
 * IPv4 as well as onion addresses are wrapped inside an IPv6 address accordingly.
 */
static SeedSpec6 pnSeed6_main[] = {
    // seed.ecxfreebank.com (163.47.9.132:8455) — the live FreeBank seed on eCash beta.
    // 163.47.9.132 is the seed droplet's DigitalOcean *reserved* IP: the address DNS
    // (seed / *.seed) resolves to and the seed advertises (-externalip), and it can be moved
    // to a replacement droplet. v0.2.12 shipped the droplet's primary IP (68.183.235.153),
    // which dies with the droplet. The DNS seed (chainparams.cpp) is the primary discovery
    // path; this is the hardcoded fallback.
    {{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xa3,0x2f,0x09,0x84}, 8455}
};

#endif // BITCOIN_CHAINPARAMSSEEDS_H
