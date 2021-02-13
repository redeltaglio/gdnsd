/* Copyright © 2021 Brandon L Black <blblack@gmail.com>
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

#include <config.h>
#include "dnssec_nxdc.h"

#include "dnssec.h"

#include <gdnsd/alloc.h>
#include <gdnsd/rand.h>
#include <gdnsd/misc.h>

#include <sodium.h>

/****************************************************************************
 * NXDC - The NXDOMAIN Synthesis Ratelimiting Cache
 *   The overall structure here is that we're caching synthesized responses in
 * an open-address hash table with robinhood-style probing, which is given a
 * fixed size at startup and does not grow once the cache is at capacity, at a
 * load factor of ~66%.  We store a hitcounter with each cache slot as well,
 * but we don't maintain any other LRU/LFU/CLOCK-ish additional metadata.  The
 * hash function is crypto_shorthash from libsodium, which is SipHash, and we
 * give every thread a unique secret random hash key just for this NXDC's use,
 * so that collisions can't be predicted by attackers.
 *   When new insertions need to happen and we're at capacity and must evict,
 * we use a 2-Random(-ish) Pseudo-LFU, which picks two random slots from the
 * hashtable and evicts the least-hit of the pair to make room for the new
 * entry.  2-Random strategies tend to work almost as well as traditional ones
 * that involve a lot more bookkeeping, and are far simpler.  For our case it's
 * also nice that they tend to be more attack resistant than some non-random
 * strategies, as this is a public cache whose efficiency will undoubtedly be
 * put under some intentional strains!
 *   The data storage for the responses themselves is a large linear chunk of
 * memory, and the hash slots hold pointers into it.  During initial fill the
 * new insertions grab space from the storage linearly until it's all used up.
 * Once everything's full and we're doing evictions, we reclaim the chunk of
 * the evicted victim to use as storage for the new entry.
 *   A not-very-bursty token bucket limiter is also in place, and is checked
 * right after we notice a hash miss, and can result in no-response.  The
 * overall logical flow of the main call into this code from dnspacket is
 * essentially:
 * 1. Check for cache hit (if so, return it)
 * 2. Check miss ratelimiter (if exceeded, return no data and drop response)
 * 3. Synthesize response (CPU cost of signing incurred here)
 * 4. If table full, evict some other entry and steal its bulk storage too
 * 5. Insert a new entry for the new response
 ****************************************************************************/

// Half of each hashtable slot in the raw array is the data pointer, and the
// other half is a pointer width worth of metadata where we store the "full"
// hash (in this case, not really full, but more bits than what we mask off for
// the table access itself, which saves a lot of failed memcmps that need
// memory outside of the table!) as well as the slot's hitcount for LFU-ish
// purposes. We only code for common 32- and 64- bit platforms.

typedef struct {
    struct {
#if SIZEOF_UINTPTR_T == 8
        uintptr_t hash : 48;
        uintptr_t hits : 16;
#elif SIZEOF_UNITPTR_T == 4
        uintptr_t hash : 20; // has to be at least the max configurable scale
        uintptr_t hits : 12;
#endif
    };
    uint8_t* data;
} nxdc_slot_t;

// KH_MASK - masks a uintptr_t hash result down to the size of "hash" above.
// HITS_MAX/HITS_RECYCLE - when the "hits" counter of a slot reaches max value
// and we hit it again, we flip over to this value before incrementing, which
// is essentially the same as wiping the top half of the bits of "hits".  As
// compared to just leaving them stuck at the ceiling, this gives a chance for
// very popular entries to more-quickly lose LFU to new real contenders as real
// organic patterns shift over time.   The other option is just letting them
// roll over to zero once in a while, but then that makes them prone to
// occasionally very silly shootdowns by fresh one-hit-wonder cases.

#if SIZEOF_UINTPTR_T == 8
#  define KH_MASK ((1LLU << 48) - 1LLU)
#  define HITS_MAX 65535U
#  define HITS_RECYCLE 255U
#elif SIZEOF_UINTPTR_T == 4
#  define KH_MASK ((1U << 20) - 1U)
#  define HITS_MAX 4095U
#  define HITS_RECYCLE 63U
#endif

struct nxdc {
    uint32_t mask;      // 2^scale - 1
    uint32_t max_count; // 2^(scale+1)/3, ~66% load factor
    uint32_t item_size; // size reserved per item in "items"
    uint32_t count;     // eventually stabilizes @ max_count
    uint64_t gen;       // compares with ltree root generation
    gdnsd_rstate32_t rstate; // RNG for cache eviction strategy
    // per-thread secret key so hash collisions aren't predictable by
    // nxdomain-attackers trying to slow us down even more:
    uint8_t hkey[crypto_shorthash_KEYBYTES];
    gdnsd_tbf_t* tbf;   // ratelimiter for misses causing synth->insert
    nxdc_slot_t* table; // 2^scale slots
    uint8_t* items;     // #max_count of len item_size
};

// Note: we are pessimistic about the zone data having huge owner names and
// huge possible nxdomain names, when allocating our storage space in "items",
// so that all possible cases are covered even when new zones are added at
// runtime.  For more-typical data, this results in ~60% of the cache's storage
// space being wasted (and it's wasted in an interleaved fashion, so it's not
// like we just have untouched pages at the end).  This is less-than-ideal, but
// it's not the end of the world, I guess.
// The smartest reasonable way I've thought of to reduce the memory waste is to
// have the ltree (re-)load process track the maximum zone name and domainname
// lengths of the total dataset, and size against that information at startup,
// and dynamically adjust max_count downwards on reloads if the new max is
// larger than our startup conditions (and suggest a replace if the data has
// changed dramatically).
// This seems like a lot of implementation complexity for the typical memory
// savings though, and adds to the existing difficulties of even documenting
// and explaining the cache's sizing to users as well, so I haven't pursued it
// at this time.

#define RRS_OFFSET 258U
static unsigned get_item_size(const unsigned max_zsks)
{
    gdnsd_assert(max_zsks);
    return 2U // length of the NSEC+RRSIG data
           + 256U // max-len dname for nxd_name
           + 275U // NSEC with "RRSIG NSEC" mask + 255B next-name
           + (349U * max_zsks); // RRSIG w/ 255B signer + 64B sig
}

nxdc_t* nxdc_new(const unsigned scale, const unsigned rate, const unsigned max_zsks)
{
    gdnsd_assert(scale >= 8U);
    gdnsd_assert(scale <= 20U);
    nxdc_t* n = xcalloc(sizeof(*n));
    const unsigned alloc = 1U << scale;
    n->mask = alloc - 1U;
    n->max_count = (1U << (scale + 1U)) / 3U;
    n->item_size = get_item_size(max_zsks);
    n->table = xcalloc_n(alloc, sizeof(*n->table));
    n->items = xmalloc_n(n->max_count, n->item_size);
    gdnsd_rand32_init(&n->rstate);
    crypto_shorthash_keygen(n->hkey);
    n->tbf = gdnsd_tbf_new(rate);
    return n;
}

void nxdc_destroy(nxdc_t* n)
{
    free(n->tbf);
    free(n->items);
    free(n->table);
    free(n);
}

// This is a standard linear robinhood insert
static void nxdc_insert(nxdc_t* n, uint8_t* new_data, const uintptr_t kh)
{
    nxdc_slot_t ins = { .hits = 0, .hash = kh, .data = new_data };
    const uint32_t mask = n->mask;
    nxdc_slot_t* tbl = n->table;
    uint32_t probe_dist = 0;
    do {
        const uint32_t slot = (ins.hash + probe_dist) & mask;
        nxdc_slot_t* s = &tbl[slot];
        if (!s->data) {
            memcpy(s, &ins, sizeof(*s));
            break;
        }
        const uint32_t s_pdist = (slot - s->hash) & mask;
        if (s_pdist < probe_dist) {
            probe_dist = s_pdist;
            nxdc_slot_t tmp = *s;
            *s = ins;
            ins = tmp;
        }
        probe_dist++;
    } while (1);
}

static bool dname_eq_name(const uint8_t* dname, const uint8_t* name, const unsigned name_len)
{
    return (dname[0] == name_len && !memcmp(&dname[1], name, name_len));
}

// This is a standard linear robinhood lookup, except that it also maintains
// the per-slot hitcounter for pseudo-LFU before returning a successful lookup
// for a hit.
static unsigned nxdc_lookup(nxdc_t* n, const uint8_t* nxd_name, uint8_t* buf,
                            const uintptr_t kh, const unsigned nxd_name_len)
{
    const uint32_t mask = n->mask;
    nxdc_slot_t* tbl = n->table;
    uint32_t probe_dist = 0;
    do {
        const uint32_t slot = (kh + probe_dist) & mask;
        nxdc_slot_t* s = &tbl[slot];
        if (!s->data || ((slot - s->hash) & mask) < probe_dist)
            break;
        if (s->hash == kh && likely(dname_eq_name(&s->data[2], nxd_name, nxd_name_len))) {
            if (unlikely(s->hits == HITS_MAX))
                s->hits = HITS_RECYCLE;
            s->hits++;
            const unsigned len = gdnsd_get_una16(s->data);
            memcpy(buf, &s->data[RRS_OFFSET], len);
            return len;
        }
        probe_dist++;
    } while (1);
    return 0;
}

// 2-Random(-ish) Pseudo-LFU to evict an existing object from the hash table,
// returning a pointer to its data item storage for re-use by the new entry
F_NONNULL
static uint8_t* nxdc_evict(nxdc_t* n)
{
    gdnsd_assert(n->count == n->max_count);
    nxdc_slot_t* tbl = n->table;

    // Pick two random hash table slots:
    uint32_t rslot1 = gdnsd_rand32_get(&n->rstate) & n->mask;
    uint32_t rslot2 = gdnsd_rand32_get(&n->rstate) & n->mask;

    // Our two random choices could be identical, and/or could also land in
    // empty slots.  At our ~66% load factor, each random choice has a ~1/3
    // chance of being empty.  We fix this by walking backwards from each
    // random choice in the table until those conditions are no longer true.
    // This is not as ideally-random as just re-making random choices until we
    // get two different non-empties, but using the backwalk strategy here has
    // some subtle advantages over both re-randoming and forward walks:
    // 1) Helps reduce max probe distance by pulling from the end of existing
    //    runs rather than the beginning, when possible
    // 2) Because probe distance ties are "won" by existing slots during
    //    insertion (the inserter goes after any extant equal probe counts in a
    //    chain), pulling from the end of a set biases us towards evicting the
    //    most-recently-inserted (least likely to be useful by LRU-like
    //    measures) of a colliding set, when such sets are in play.
    // 3) Walking backwards from an empty slot gaurantees no backshift fixups
    //    will be necessary at the bottom of this function, which saves time vs
    //    the likely set of backshifts if we had scanned forward to the start
    //    of a run of filled slots.

    // Backwalk 1 until not-empty, then backwalk 2 until not-empty and != 1
    while (!tbl[rslot1].data)
        rslot1 = (rslot1 - 1U) & n->mask;
    while (rslot2 == rslot1 || !tbl[rslot2].data)
        rslot2 = (rslot2 - 1U) & n->mask;

    // The comparison here also biases the equal-hits case towards rslot1,
    // because if rslot2's search hit rslot1 it would backwalk past rslot1,
    // making rslot1 the more likely of the two to be at the end of a run,
    // helping in all the same ways as above.
    uint32_t rslot = (tbl[rslot2].hits < tbl[rslot1].hits)
                     ? rslot2 : rslot1;

    // Steal the victim's pointer to data storage for re-use in the upcoming
    // insertion that triggered the eviction
    uint8_t* new_data = tbl[rslot].data;

    // Wipe the target slot and iteratively backshift the following ones until
    // we reach an empty or a zero probe distance.  If we didn't do this we'd
    // break runs that lookups were relying on, borking everything.  The other
    // "obvious" strategy is tombstones, but those turn out to make the table
    // performance horrible once you inevitably fill all empty space with them.
    do {
        memset(&tbl[rslot], 0, sizeof(tbl[rslot]));
        const uint32_t next_slot = (rslot + 1U) & n->mask;
        if (!tbl[next_slot].data) // empty, no breakage if we stop here
            break;
        const uint32_t next_pdist = (next_slot - tbl[next_slot].hash) & n->mask;
        if (!next_pdist) // zero-distance, no breakage if we stop here
            break;
        // backshift the next slot up one, reducing its probe distance, and
        // loop up to wipe the spot we pulled it from and go again
        tbl[rslot] = tbl[next_slot];
        rslot = next_slot;
    } while (1);

    return new_data;
}

static uintptr_t hash_nxd_name(const uint8_t* nxd_name, const size_t nxd_name_len, const uint8_t* hkey)
{
    static_assert(sizeof(uintptr_t) <= crypto_shorthash_BYTES,
                  "shorthash writes at least uintptr_t bytes");
    union {
        uint8_t u8[crypto_shorthash_BYTES];
        uintptr_t up;
    } output;
    crypto_shorthash(output.u8, nxd_name, nxd_name_len, hkey);
    return output.up;
}

unsigned nxdc_synth(nxdc_t* n, const dnssec_t* sec, const uint8_t* nxd_name, uint8_t* buf, bool* hit_p, uint64_t gen, const unsigned nxd_name_len)
{
    const uintptr_t kh = hash_nxd_name(nxd_name, nxd_name_len, n->hkey) & KH_MASK;
    unsigned len = 0;
    if (likely(gen == n->gen)) {
        len = nxdc_lookup(n, nxd_name, buf, kh, nxd_name_len);
        if (len) {
            *hit_p = true;
            return len;
        }
    } else {
        // Zones reloaded: wipe cache and miss
        n->gen = gen;
        n->count = 0;
        memset(n->table, 0, sizeof(*n->table) * (n->mask + 1U));
        // we're about to burst misses, and it's not the traffic's fault, so:
        gdnsd_tbf_reset(n->tbf);
    }

    // tbf counts one token per ZSK.  It'd be nice if there were a simple and
    // semi-accurate way to weight by-algorithm...
    if (gdnsd_tbf_limit_exceeded(n->tbf, dnssec_num_zsks(sec)))
        return 0;

    len = dnssec_synth_nxd(sec, nxd_name, buf, nxd_name_len);
    gdnsd_assert(len);
    uint8_t* new_data = NULL;
    if (n->count == n->max_count)
        new_data = nxdc_evict(n);
    else
        new_data = &n->items[n->item_size * n->count++];

    gdnsd_put_una16(len, new_data);
    new_data[2] = nxd_name_len;
    memcpy(&new_data[3], nxd_name, nxd_name_len);
    memcpy(&new_data[RRS_OFFSET], buf, len);
    nxdc_insert(n, new_data, kh);
    return len;
}
