/* Copyright © 2012 Brandon L Black <blblack@gmail.com> and Jay Reitz <jreitz@gmail.com>
 *
 * This file is part of gdnsd.
 *
 * gdnsd is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * gdnsd is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with gdnsd.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef GDNSD_LTREE_H
#define GDNSD_LTREE_H

/*

  ltree == "Label Tree", a representation of DNS data as a tree by domain
labels, e.g:
                        .
                       / \
                     com  net
                    /   \
                   /     \
               example   foo
                /   \
              www   ns1

  A whole ltree represents the whole of the DNS (for those zones defined in our
authoritative dataset, anyways) as a linked tree of per-label nodes starting at
the root.  During zone loading, detached per-zone trees are rooted at their
own zone root, and are later grafted onto the global ltree that starts at the
real root of the DNS.

  Each node in the ltree (ltree_node_t) contains a resizable hash table of
child nodes, as well as the data for its own local rrsets and a flags field for
identifying important properties like zone roots or delegation points.

  The zonefile parser (zscan.rl) constructs the label tree for a zone by making
ltree_add_rec_* calls into the ltree.c code.  After a zonefile has been parsed,
the ltree code does multiple phases of post-processing where it walks the
entire tree, doing many data validation checks and setting up inter-node
references for e.g. CNAMEs and NS->A glue.

  At runtime, the dnspacket.c code searches the ltree database directly via the
global root node, using its own local search function that understands the
ltree structure.

*/

#include "dnswire.h"

#include <gdnsd/compiler.h>
#include "plugins/plugapi.h"
#include <gdnsd/misc.h>

#include "ltarena.h"

#include <stddef.h>
#include <inttypes.h>
#include <stdbool.h>

// Maximum count of NS RRs in an NS rr-set.  Nobody should realistically ever
// hit this, but we needed some sane value here to size a stack-based array to
// hold glue offsets during dnspacket.c output generation.
#define MAX_NS_COUNT 64U

// Result type used by search functions in ltree.c and dnspacket.c
typedef enum {
    DNAME_NOAUTH = 0,
    DNAME_AUTH = 1,
    DNAME_DELEG = 2
} ltree_dname_status_t;

struct ltree_rdata_ns;
struct ltree_rdata_mx;
struct ltree_rdata_srv;
struct ltree_rdata_naptr;
struct ltree_rdata_rfc3597;

union  ltree_rrset;
struct ltree_rrset_a;
struct ltree_rrset_aaaa;
struct ltree_rrset_soa;
struct ltree_rrset_cname;
struct ltree_rrset_dync;
struct ltree_rrset_ns;
struct ltree_rrset_ptr;
struct ltree_rrset_mx;
struct ltree_rrset_srv;
struct ltree_rrset_naptr;
struct ltree_rrset_txt;
struct ltree_rrset_rfc3597;

typedef struct ltree_rdata_ns ltree_rdata_ns_t;
typedef uint8_t* ltree_rdata_ptr_t;
typedef struct ltree_rdata_mx ltree_rdata_mx_t;
typedef struct ltree_rdata_srv ltree_rdata_srv_t;
typedef struct ltree_rdata_naptr ltree_rdata_naptr_t;
typedef struct ltree_rdata_txt ltree_rdata_txt_t;
typedef struct ltree_rdata_rfc3597 ltree_rdata_rfc3597_t;

typedef union  ltree_rrset ltree_rrset_t;
typedef struct ltree_rrset_gen ltree_rrset_gen_t;
typedef struct ltree_rrset_a ltree_rrset_a_t;
typedef struct ltree_rrset_aaaa ltree_rrset_aaaa_t;
typedef struct ltree_rrset_soa ltree_rrset_soa_t;
typedef struct ltree_rrset_cname ltree_rrset_cname_t;
typedef struct ltree_rrset_dync ltree_rrset_dync_t;
typedef struct ltree_rrset_ns ltree_rrset_ns_t;
typedef struct ltree_rrset_ptr ltree_rrset_ptr_t;
typedef struct ltree_rrset_mx ltree_rrset_mx_t;
typedef struct ltree_rrset_srv ltree_rrset_srv_t;
typedef struct ltree_rrset_naptr ltree_rrset_naptr_t;
typedef struct ltree_rrset_txt ltree_rrset_txt_t;
typedef struct ltree_rrset_rfc3597 ltree_rrset_rfc3597_t;

struct ltree_rdata_ns {
    uint8_t* dname;
    ltree_rrset_a_t* glue_v4;
    ltree_rrset_aaaa_t* glue_v6;
};

struct ltree_rdata_mx {
    uint8_t* dname;
    uint16_t pref; // net-order
};

struct ltree_rdata_srv {
    uint8_t* dname;
    uint16_t priority; // net-order
    uint16_t weight; // net-order
    uint16_t port; // net-order
};

struct ltree_rdata_naptr {
    uint8_t* dname;
    uint8_t* text;
    uint16_t text_len;
    uint16_t order; // net-order
    uint16_t pref; // net-order
};

struct ltree_rdata_txt {
    uint8_t* text;
    unsigned text_len;
};

struct ltree_rdata_rfc3597 {
    uint8_t* rd;
    uint16_t rdlen;
};

// rrset structs

struct ltree_rrset_gen {
    ltree_rrset_t* next;
    uint16_t type; // host-order
    uint16_t count; // host-order
    uint32_t ttl; // net-order
};

// The rules for interpreting the _a_ structure:
//   if (!gen.count)
//       use .dyn, this is a DYNA
//   else if (gen.count <= LTREE_V4A_SIZE)
//       use v4a for direct IPv4 address data
//   else
//       else "addrs" for array of addresses

#if SIZEOF_UINTPTR_T == 8
#    define LTREE_V4A_SIZE 4
#else
#    define LTREE_V4A_SIZE 3
#endif

struct ltree_rrset_a {
    ltree_rrset_gen_t gen;
    union {
        uint32_t* addrs;
        uint32_t v4a[LTREE_V4A_SIZE];
        struct {
            gdnsd_resolve_cb_t func;
            unsigned resource;
            uint32_t ttl_min; // host-order!
        } dyn;
    };
};

// The rules for interpreting the _aaaa_ structure:
//   if (!gen.count)
//       use .dyn, this is a DYNA
//   else
//       else "addrs" for array of addresses

struct ltree_rrset_aaaa {
    ltree_rrset_gen_t gen;
    union {
        uint8_t* addrs;
        struct {
            gdnsd_resolve_cb_t func;
            unsigned resource;
            uint32_t ttl_min; // host-order!
        } dyn;
    };
};

struct ltree_rrset_soa {
    ltree_rrset_gen_t gen;
    uint8_t* email;
    uint8_t* master;
    uint32_t times[5];
};

struct ltree_rrset_cname {
    ltree_rrset_gen_t gen;
    uint8_t* dname;
};

struct ltree_rrset_dync {
    ltree_rrset_gen_t gen;
    gdnsd_resolve_cb_t func;
    unsigned resource;
    uint32_t ttl_min; // host-order!
};

struct ltree_rrset_ns {
    ltree_rrset_gen_t gen;
    ltree_rdata_ns_t* rdata;
};

struct ltree_rrset_ptr {
    ltree_rrset_gen_t gen;
    ltree_rdata_ptr_t* rdata;
};

struct ltree_rrset_mx {
    ltree_rrset_gen_t gen;
    ltree_rdata_mx_t* rdata;
};

struct ltree_rrset_srv {
    ltree_rrset_gen_t gen;
    ltree_rdata_srv_t* rdata;
};

struct ltree_rrset_naptr {
    ltree_rrset_gen_t gen;
    ltree_rdata_naptr_t* rdata;
};

struct ltree_rrset_txt {
    ltree_rrset_gen_t gen;
    ltree_rdata_txt_t* rdata;
};

struct ltree_rrset_rfc3597 {
    ltree_rrset_gen_t gen;
    ltree_rdata_rfc3597_t* rdata;
};

// This is never allocated, it's just used
//  for pointer types to cast between generic
//  rrset_t and the specific rrset_t's
union ltree_rrset {
    ltree_rrset_gen_t gen;
    ltree_rrset_a_t a;
    ltree_rrset_aaaa_t aaaa;
    ltree_rrset_soa_t soa;
    ltree_rrset_cname_t cname;
    ltree_rrset_dync_t dync;
    ltree_rrset_ns_t ns;
    ltree_rrset_ptr_t ptr;
    ltree_rrset_mx_t mx;
    ltree_rrset_srv_t srv;
    ltree_rrset_naptr_t naptr;
    ltree_rrset_txt_t txt;
    ltree_rrset_rfc3597_t rfc3597;
};

struct ltree_node;
typedef struct ltree_node ltree_node_t;

typedef struct ltree_hslot {
    uintptr_t hash;
    ltree_node_t* node;
} ltree_hslot;

struct ltree_node {
#if SIZEOF_UINTPTR_T == 8
#  define LTREE_NODE_MAX_SLOTS UINT32_MAX
    uint32_t ccount;
    struct {
        uint32_t zone_cut : 1;
    };
#else
#  define LTREE_NODE_MAX_SLOTS (UINT32_MAX >> 1U)
    struct {
        uint32_t ccount : 31;
        uint32_t zone_cut : 1;
    };
#endif
    uint8_t* label;
    ltree_hslot* child_table;
    ltree_rrset_t* rrsets;
};

// This is a temporary per-zone structure used during zone construction
typedef struct {
    ltree_node_t* root; // root of this zone
    uint8_t* dname; // name of this zone
    ltarena_t* arena; // storage for all node->label in "root" above
    unsigned serial; // serial copied from SOA for reporting successful loads
} zone_t;

F_NONNULL
zone_t* ltree_new_zone(const char* zname);
F_NONNULL
bool ltree_merge_zone(ltree_node_t* new_root_tree, ltarena_t* new_root_arena, zone_t* new_zone);

void* ltree_zones_reloader_thread(void* init_asvoid);
F_WUNUSED F_NONNULL
bool ltree_postproc_zone(zone_t* zone);
F_NONNULL
void ltree_destroy_zone(zone_t* zone);

// parameter structures for arguments to ltree_add_rec that otherwise
// have confusingly-long parameter lists
typedef struct lt_soa_args {
    const uint8_t* master;
    const uint8_t* email;
    unsigned ttl;
    const unsigned serial;
    const unsigned refresh;
    const unsigned retry;
    const unsigned expire;
    unsigned ncache;
} lt_soa_args;

typedef struct lt_srv_args {
    const uint8_t* rhs;
    const unsigned ttl;
    const unsigned priority;
    const unsigned weight;
    const unsigned port;
} lt_srv_args;

typedef struct lt_naptr_args {
    const uint8_t* rhs;
    const unsigned ttl;
    const unsigned order;
    const unsigned pref;
    const unsigned text_len;
    uint8_t* text;
} lt_naptr_args;

// Adding data to the ltree (called from parser)
F_WUNUSED F_NONNULL
bool ltree_add_rec_soa_args(const zone_t* zone, const uint8_t* dname, lt_soa_args args);
#define ltree_add_rec_soa(_z,_d,...) ltree_add_rec_soa_args(_z,_d,(lt_soa_args){__VA_ARGS__})
F_WUNUSED F_NONNULL
bool ltree_add_rec_a(const zone_t* zone, const uint8_t* dname, uint32_t addr, unsigned ttl);
F_WUNUSED F_NONNULL
bool ltree_add_rec_aaaa(const zone_t* zone, const uint8_t* dname, const uint8_t* addr, unsigned ttl);
F_WUNUSED F_NONNULL
bool ltree_add_rec_dynaddr(const zone_t* zone, const uint8_t* dname, const char* rhs, unsigned ttl, unsigned ttl_min);
F_WUNUSED F_NONNULL
bool ltree_add_rec_cname(const zone_t* zone, const uint8_t* dname, const uint8_t* rhs, unsigned ttl);
F_WUNUSED F_NONNULL
bool ltree_add_rec_dync(const zone_t* zone, const uint8_t* dname, const char* rhs, unsigned ttl, unsigned ttl_min);
F_WUNUSED F_NONNULL
bool ltree_add_rec_ptr(const zone_t* zone, const uint8_t* dname, const uint8_t* rhs, unsigned ttl);
F_WUNUSED F_NONNULL
bool ltree_add_rec_ns(const zone_t* zone, const uint8_t* dname, const uint8_t* rhs, unsigned ttl);
F_WUNUSED F_NONNULL
bool ltree_add_rec_mx(const zone_t* zone, const uint8_t* dname, const uint8_t* rhs, unsigned ttl, const unsigned pref);
F_WUNUSED F_NONNULL
bool ltree_add_rec_srv_args(const zone_t* zone, const uint8_t* dname, lt_srv_args args);
#define ltree_add_rec_srv(_z,_d,...) ltree_add_rec_srv_args(_z,_d,(lt_srv_args){__VA_ARGS__})
F_WUNUSED F_NONNULL
bool ltree_add_rec_naptr_args(const zone_t* zone, const uint8_t* dname, lt_naptr_args args);
#define ltree_add_rec_naptr(_z,_d,...) ltree_add_rec_naptr_args(_z,_d,(lt_naptr_args){__VA_ARGS__})
F_WUNUSED F_NONNULL
bool ltree_add_rec_txt(const zone_t* zone, const uint8_t* dname, const unsigned text_len, uint8_t* text, unsigned ttl);
F_WUNUSED F_NONNULLX(1, 2)
bool ltree_add_rec_rfc3597(const zone_t* zone, const uint8_t* dname, const unsigned rrtype, unsigned ttl, const unsigned rdlen, uint8_t* rd);

// Load zonefiles (called from main, invokes parser)
void ltree_load_zones(void);

// One-shot init at startup, after config load
void ltree_init(void);

// this hash wrapper is for labels encoded as one length-byte followed
//  by N characters.  Thus the label "www" is "\003www" (4 bytes)
F_UNUSED F_PURE F_WUNUSED F_NONNULL F_HOT
static uintptr_t ltree_hash(const uint8_t* input)
{
    const unsigned len = *input++;
    return gdnsd_shorthash_up(input, len);
}

// count2mask for a load factor of ~80%, by adding a rounded-down 25% (easy
// 2-bit shift) to the current count before converting it to the next
// power-of-two mask
F_CONST F_UNUSED
static uint32_t count2mask_lf80(const uint32_t x)
{
    return count2mask(x + (x >> 2U));
}

// "lstack" must be allocated to 127 pointers
// "dname" must be valid
// retval is label count (not including zero-width root label)
F_UNUSED F_WUNUSED F_NONNULL F_HOT
static unsigned dname_to_lstack(const uint8_t* dname, const uint8_t** lstack)
{
    gdnsd_assert(dname_status(dname) == DNAME_VALID);

    dname++; // skip overall len byte
    unsigned lcount = 0;
    unsigned llen; // current label len
    while ((llen = *dname)) {
        gdnsd_assert(lcount < 127);
        lstack[lcount++] = dname++;
        dname += llen;
    }

    return lcount;
}

// Used within ltree.c in many places, and also from dnspacket while traversing
// the tree for runtime lookups
F_NONNULL F_PURE F_UNUSED F_HOT
static ltree_node_t* ltree_node_find_child(const ltree_node_t* node, const uint8_t* child_label)
{
    if (node->child_table) {
        const uint32_t mask = count2mask_lf80(node->ccount);
        const uintptr_t kh = ltree_hash(child_label);
        uint32_t probe_dist = 0;
        do {
            const uint32_t slot = ((uint32_t)kh + probe_dist) & mask;
            const ltree_hslot* s = &node->child_table[slot];
            if (!s->node || ((slot - s->hash) & mask) < probe_dist)
                break;
            if (s->hash == kh && likely(!label_cmp(s->node->label, child_label)))
                return s->node;
            probe_dist++;
        } while (1);
    }
    return NULL;
}

// ltree_root is RCU-managed and accessed by reader threads, defined in ltree.c
extern ltree_node_t* root_tree;

#endif // GDNSD_LTREE_H
