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

#include <config.h>
#include "dnspacket.h"

#include "conf.h"
#include "socks.h"
#include "dnswire.h"
#include "ltree.h"
#include "chal.h"
#include "cookie.h"

#include "plugins/plugapi.h"
#include <gdnsd/alloc.h>
#include <gdnsd/log.h>
#include <gdnsd/misc.h>
#include <gdnsd/rand.h>

#include <string.h>
#include <stddef.h>
#include <pthread.h>
#include <time.h>

#include <urcu-qsbr.h>

// The fixed offset of qname compression target
#define QNAME_COMP sizeof(wire_dns_header_t)

// Fixed HINFO record with TTL=3600 for RFC 8482
static const char hinfo_for_any[] = "\300\14\0\15\0\1\0\0\16\20\0\11\7RFC8482";
#define hinfo_for_any_len sizeof(hinfo_for_any)

// EDNS Cookie-related states:
typedef struct {
    // Client sent COOKIE option, perhaps a malformed one
    bool recvd;

    // Client sent well-formed COOKIE option, and we will respond with one
    bool respond;

    // Client sent a full client+server cookie value that we recognize as one we issued
    bool valid;

    // Output cookie option data, if edns.cookie.respond
    uint8_t output[16U];
} cookie_t;

// Sub-struct of txn_t below for EDNS-related state at the per-transaction level
typedef struct {
    // dns source IP + optional EDNS client subnet info for plugins
    client_info_t client_info;

    // EDNS Client Subnet response mask.
    // Not valid/useful in DNS responses unless edns.respond_client_subnet is true
    // below, *and* the source mask was non-zero.
    // For static responses, this is set to zero by dnspacket.c
    // For dynamic responses, this is set from .ans_dyn{a,cname}.edns_client_mask,
    //   which is in turn defaulted to zero.
    unsigned client_scope_mask;

    // How many bytes the OPTRR will consume at the end of the packet
    unsigned out_bytes;

    // Whether this request had a valid EDNS optrr
    bool req_edns;

    // DO bit in edns, if edns used at all
    bool do_bit;

    // Client sent EDNS Client Subnet option, and we must respond with one
    bool respond_client_subnet;

    // If above is true, this records the original family value verbatim
    unsigned client_family;

    // Whether the query requested NSID *and* we have it configured
    bool respond_nsid;

    // Cookie-related states
    cookie_t cookie;
} edns_t;

// txn_t tracks various per-transaction state (the scope of a single
// process_dns_query execution from a dnsio caller), and is explicitly memset
// back to zero at the start of processing a fresh txn
typedef struct {
    // this is the packet buffer from the io code, this value is passed in and
    // set here at the start of every request
    pkt_t* pkt;

    // RFC 8490 DSO state tracking, NULL in UDP case.  Like "pkt" this is
    // passed in as a pointer on each request, overwriting this every time.
    dso_state_t* dso;

    // Max response size for this individual request, as determined
    //  by protocol type, expected edns output bytes at the end, and in the
    //  case of UDP, the EDNS max response size (if any).
    unsigned this_max_response;

    // The queried type.  Note that this gets switched internally to CNAME in
    // the case of queries which land on a CNAME RR.
    unsigned qtype;

    // The queried class.
    unsigned qclass;

    // This is used to fixup compression offsets when the query name has
    // unknown stuff to the left of whatever we're matching.  These cases are
    // split because we can have a NODATA negative SOA response against a
    // wildcard node, in which case a unified "comp_fixup" would carry the
    // wrong value for the SOA.
    unsigned comp_fixup_auth; // For delegations and SOA-negatives
    unsigned comp_fixup_wild; // For RHS compression in wildcard MX, CNAME, PTR

    unsigned qdcount;
    unsigned ancount;
    unsigned nscount;
    unsigned arcount;

    // The original query name input from the question is stored here,
    // normalized to lowercase, and in our "dname" format, which means
    // prefixing the wire version with an overall length byte.
    uint8_t lqname[256];

    // synthetic rrsets for DYN[AC]
    ltree_rrset_raw_t dynac_synth_rrset;

    // EDNS-related states
    edns_t edns;
} txn_t;

// per-thread persistent context
struct dnsp_ctx {
    // stats reference for this thread, permanent from startup
    dnspacket_stats_t* stats;

    // used to pseudo-randomly rotate some RRsets (A, AAAA, and NS)
    gdnsd_rstate32_t rand_state;

    // allocated at startup, memset to zero before each callback
    dyn_result_t* dyn;

    // whether the thread using this context is a udp or tcp thread,
    // set permanently at startup
    bool is_udp;

    // Whether to use EDNS and DSO Padding in TCP responses (encrypted transport)
    bool tcp_pad;

    // For UDP, the configured maximum response size, set permanently at
    // startup based on the UDP address family and the max_response options.
    unsigned udp_edns_max;

    // TCP Keepalive / TCP DSO Inactivity: these are the same value in
    // different units (100ms units for the EDNS version, and 1ms units for the
    // DSO version).  Set at thread start, reset to zero if dnsp_ctx_grace() is
    // called on this structure, to adverise zeros to clients and ask them to
    // disconnect gracefully as we're shutting down.
    unsigned edns_tcp_keepalive;
    unsigned dso_inactivity;

    // The current transaction state
    txn_t txn;
};

static pthread_mutex_t stats_init_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t stats_init_cond = PTHREAD_COND_INITIALIZER;
static unsigned stats_initialized = 0;

dnspacket_stats_t** dnspacket_stats;

// Allocates the array of pointers to stats structures, one per I/O thread
// Called from main thread before I/O threads are spawned.
void dnspacket_global_setup(const socks_cfg_t* socks_cfg)
{
    dnspacket_stats = xcalloc_n(socks_cfg->num_dns_threads, sizeof(*dnspacket_stats));
}

// Called from main thread after starting all of the I/O threads,
//  ensures they all finish allocating their stats and storing the pointers
//  into dnspacket_stats before allowing the main thread to continue.
void dnspacket_wait_stats(const socks_cfg_t* socks_cfg)
{
    const unsigned waitfor = socks_cfg->num_dns_threads;
    pthread_mutex_lock(&stats_init_mutex);
    while (stats_initialized < waitfor)
        pthread_cond_wait(&stats_init_cond, &stats_init_mutex);
    pthread_mutex_unlock(&stats_init_mutex);
}

static dnsp_ctx_t* dnspacket_ctx_init(dnspacket_stats_t** stats_out, const bool is_udp, const bool udp_is_ipv6, const bool tcp_pad, const unsigned tcp_timeout_secs)
{
    dnsp_ctx_t* ctx = xcalloc(sizeof(*ctx));
    if (udp_is_ipv6)
        gdnsd_assert(is_udp);
    if (tcp_pad)
        gdnsd_assert(!is_udp);
    if (tcp_timeout_secs)
        gdnsd_assert(!is_udp);

    gdnsd_rand32_init(&ctx->rand_state);
    ctx->is_udp = is_udp;
    ctx->udp_edns_max = udp_is_ipv6 ? gcfg->max_edns_response_v6 : gcfg->max_edns_response;
    ctx->tcp_pad = tcp_pad;
    ctx->edns_tcp_keepalive = tcp_timeout_secs * 10;
    ctx->dso_inactivity = tcp_timeout_secs * 1000;
    ctx->dyn = xmalloc(gdnsd_result_get_alloc());

    gdnsd_plugins_action_iothread_init();

    pthread_mutex_lock(&stats_init_mutex);
    ctx->stats = dnspacket_stats[stats_initialized++] = xcalloc(sizeof(*ctx->stats));
    ctx->stats->is_udp = is_udp;
    pthread_cond_signal(&stats_init_cond);
    pthread_mutex_unlock(&stats_init_mutex);

    *stats_out = ctx->stats;
    return ctx;
}

dnsp_ctx_t* dnspacket_ctx_init_udp(dnspacket_stats_t** stats_out, const bool is_ipv6)
{
    return dnspacket_ctx_init(stats_out, true, is_ipv6, false, 0);
}

dnsp_ctx_t* dnspacket_ctx_init_tcp(dnspacket_stats_t** stats_out, const bool pad, const unsigned timeout_secs)
{
    return dnspacket_ctx_init(stats_out, false, false, pad, timeout_secs);
}

void dnspacket_ctx_set_grace(dnsp_ctx_t* ctx)
{
    ctx->edns_tcp_keepalive = 0;
    ctx->dso_inactivity = 0;
}

void dnspacket_ctx_cleanup(dnsp_ctx_t* ctx)
{
    gdnsd_plugins_action_iothread_cleanup();

    free(ctx->dyn);
    free(ctx);
}

typedef enum {
    DECODE_IGNORE  = -4, // totally invalid packet (len < header len or QR-bit set in query) - NO RESPONSE PACKET
    // (^ also used for immediate connection abort in case of DSO session + edns keepalive)
    DECODE_FORMERR = -3, // slightly better but still invalid input, we return FORMERR
    DECODE_BADVERS = -2, // EDNS version higher than ours (0)
    DECODE_NOTIMP  = -1, // unsupported opcode or QUERY meta-type, we return NOTIMP
    DECODE_OK      =  0, // normal and valid, QUERY opcode
    DECODE_DSO     =  1, // DSO opcode, kicks out to special handling
} rcode_rv_t;

F_NONNULL
static rcode_rv_t handle_edns_client_subnet(edns_t* edns, unsigned opt_len, const uint8_t* opt_data)
{
    if (opt_len < 4) {
        log_devdebug("edns_client_subnet data too short (%u bytes)", opt_len);
        return DECODE_FORMERR;
    }

    const unsigned family = ntohs(gdnsd_get_una16(opt_data));
    opt_data += 2;
    const unsigned src_mask = *opt_data++;
    const unsigned scope_mask = *opt_data++;
    if (scope_mask) {
        log_devdebug("edns_client_subnet: non-zero scope mask in request: %u", scope_mask);
        return DECODE_FORMERR;
    }

    // Validate family and validate non-zero src_mask as appropriate
    if (family == 1U) { // IPv4
        if (src_mask > 32U) {
            log_devdebug("edns_client_subnet: invalid src_mask of %u for IPv4", src_mask);
            return DECODE_FORMERR;
        }
    } else if (family == 2U) { // IPv6
        if (src_mask > 128U) {
            log_devdebug("edns_client_subnet: invalid src_mask of %u for IPv6", src_mask);
            return DECODE_FORMERR;
        }
    } else {
        log_devdebug("edns_client_subnet has unknown family %u", family);
        return DECODE_FORMERR;
    }

    // There should be exactly enough address bytes to cover the provided source mask (possibly 0)
    const unsigned whole_bytes = src_mask >> 3;
    const unsigned trailing_bits = src_mask & 7;
    const unsigned addr_bytes = whole_bytes + (trailing_bits ? 1 : 0);
    if (opt_len != 4 + addr_bytes) {
        log_devdebug("edns_client_subnet: option length %u mismatches src_mask of %u", opt_len, src_mask);
        return DECODE_FORMERR;
    }

    // Also, we need to check that any unmasked trailing bits in the final
    // byte are explicitly set to zero
    if (trailing_bits) {
        const unsigned final_byte = opt_data[src_mask >> 3];
        const unsigned final_mask = ~(0xFFU << (8U - trailing_bits)) & 0xFFU;
        if (final_byte & final_mask) {
            log_devdebug("edns_client_subnet: non-zero bits beyond src_mask");
            return DECODE_FORMERR;
        }
    }

    // If we made it this far, the input data is completely-valid, and
    // should be used if the source mask is non-zero:
    if (src_mask) {
        if (family == 1U) { // IPv4
            edns->client_info.edns_client.sa.sa_family = AF_INET;
            memcpy(&edns->client_info.edns_client.sin4.sin_addr.s_addr, opt_data, addr_bytes);
        } else {
            gdnsd_assert(family == 2U); // IPv6
            edns->client_info.edns_client.sa.sa_family = AF_INET6;
            memcpy(edns->client_info.edns_client.sin6.sin6_addr.s6_addr, opt_data, addr_bytes);
        }
    }

    edns->out_bytes += (8 + addr_bytes); // leave room for response option
    edns->respond_client_subnet = true;
    edns->client_info.edns_client_mask = src_mask;
    edns->client_family = family; // copy family for output
    return DECODE_OK;
}

F_NONNULL
static rcode_rv_t handle_edns_cookie(dnsp_ctx_t* ctx, unsigned opt_len, const uint8_t* opt_data)
{
    ctx->txn.edns.cookie.recvd = true;
    // FORMERR if illegal data len, only legal lens are 8, or 16-40
    if (opt_len != 8U && (opt_len < 16U || opt_len > 40U)) {
        stats_own_inc(&ctx->stats->edns_cookie_formerr);
        return DECODE_FORMERR;
    }
    ctx->txn.edns.cookie.respond = true;
    ctx->txn.edns.out_bytes += 20U;
    ctx->txn.edns.cookie.valid = cookie_process(ctx->txn.edns.cookie.output, opt_data, &ctx->txn.edns.client_info.dns_source, opt_len);
    if (ctx->txn.edns.cookie.valid)
        stats_own_inc(&ctx->stats->edns_cookie_ok);
    else if (opt_len == 8U)
        stats_own_inc(&ctx->stats->edns_cookie_init);
    else
        stats_own_inc(&ctx->stats->edns_cookie_bad);
    return DECODE_OK;
}

F_NONNULL
static rcode_rv_t handle_edns_option(dnsp_ctx_t* ctx, unsigned opt_code, unsigned opt_len, const uint8_t* opt_data)
{
    gdnsd_assert(ctx->stats);

    rcode_rv_t rv = DECODE_OK;
    if (opt_code == EDNS_CLIENTSUB_OPTCODE) {
        if (gcfg->edns_client_subnet) {
            stats_own_inc(&ctx->stats->edns_clientsub);
            rv = handle_edns_client_subnet(&ctx->txn.edns, opt_len, opt_data);
        }
    } else if (opt_code == EDNS_NSID_OPTCODE) {
        if (!opt_len) {
            if (gcfg->nsid.len) {
                gdnsd_assert(gcfg->nsid.data);
                ctx->txn.edns.out_bytes += (4U + gcfg->nsid.len);
                ctx->txn.edns.respond_nsid = true;
            }
        } else {
            rv = DECODE_FORMERR; // nsid req MUST NOT have data
        }
    } else if (opt_code == EDNS_TCP_KEEPALIVE_OPTCODE) {
        // DSO Protoerr F: EDNS TCP Keepalive inside established DSO session
        if (!ctx->is_udp) {
            gdnsd_assert(ctx->txn.dso);
            if (ctx->txn.dso->estab) {
                log_devdebug("Got EDNS Keepalive during DSO session, Proto Err -> Conn Abort");
                stats_own_inc(&ctx->stats->tcp.dso_protoerr);
                rv = DECODE_IGNORE; // causes retval 0 to TCP, forcing conn abort
            }
        }
        // Otherwise we ignore the client values sent here since we always send
        // the response version of this when legal, with our own fixed values.
    } else if (opt_code == EDNS_PADDING) {
        // Ditto, we emit padding in response to any EDNS request over TCP when
        // tcp_pad is enabled, so we don't care what padding they did (or
        // didn't) send.
    } else if (opt_code == EDNS_COOKIE_OPTCODE) {
        // ignore any cookie after the first one, per RFC
        if (!gcfg->disable_cookies && !ctx->txn.edns.cookie.recvd)
            rv = handle_edns_cookie(ctx, opt_len, opt_data);
    } else {
        log_devdebug("Unknown EDNS option code: %x", opt_code);
    }

    return rv;
}

F_NONNULL
static rcode_rv_t handle_edns_options(dnsp_ctx_t* ctx, unsigned rdlen, const uint8_t* rdata)
{
    gdnsd_assert(rdlen);

    // minimum edns option length is 4 bytes (2 byte option code, 2 byte data len)
    do {
        if (rdlen < 4) {
            log_devdebug("EDNS option too short");
            return DECODE_FORMERR;
        }
        unsigned opt_code = ntohs(gdnsd_get_una16(rdata));
        rdata += 2;
        unsigned opt_dlen = ntohs(gdnsd_get_una16(rdata));
        rdata += 2;
        rdlen -= 4;
        if (opt_dlen > rdlen) {
            log_devdebug("EDNS option too long");
            return DECODE_FORMERR;
        }
        rcode_rv_t rv = handle_edns_option(ctx, opt_code, opt_dlen, rdata);
        if (rv != DECODE_OK)
            return rv;
        rdlen -= opt_dlen;
        rdata += opt_dlen;
    } while (rdlen);

    return DECODE_OK;
}

F_NONNULL
static rcode_rv_t parse_optrr(dnsp_ctx_t* ctx, unsigned* offset_ptr, const unsigned packet_len)
{
    gdnsd_assert(ctx->stats);

    const uint8_t* packet = ctx->txn.pkt->raw;

    unsigned offset = *offset_ptr;
    // assumptions caller has checked for us:
    gdnsd_assert(offset + 11 <= packet_len); // enough bytes for minimal OPT RR
    gdnsd_assert(packet[offset] == '\0'); // root name
    gdnsd_assert(ntohs(gdnsd_get_una16(&packet[offset + 1])) == DNS_TYPE_OPT);

    // skip past the above and grab the other fields we need
    offset += 3;
    unsigned edns_maxsize = ntohs(gdnsd_get_una16(&packet[offset]));
    offset += 2;
    unsigned edns_extflags = ntohl(gdnsd_get_una32(&packet[offset]));
    offset += 4;
    unsigned edns_rdlen = ntohs(gdnsd_get_una16(&packet[offset]));
    offset += 2;

    rcode_rv_t rcode = DECODE_OK;
    ctx->txn.edns.req_edns = true;            // send OPT RR with response
    ctx->txn.edns.out_bytes = 11;

    stats_own_inc(&ctx->stats->edns);

    // DO-bit from extflags
    if (edns_extflags & 0x8000) {
        ctx->txn.edns.do_bit = true;
        stats_own_inc(&ctx->stats->edns_do);
    }

    // derive version from extflags
    const unsigned edns_version = (edns_extflags & 0xFF0000) >> 16;
    if (likely(edns_version == 0)) {
        if (likely(ctx->is_udp)) {
            if (edns_maxsize < 512U)
                edns_maxsize = 512U;
            ctx->txn.this_max_response = edns_maxsize < ctx->udp_edns_max
                                         ? edns_maxsize
                                         : ctx->udp_edns_max;
        } else if (!ctx->txn.dso->estab) {
            ctx->txn.edns.out_bytes += 6U; // tcp keepalive option space
        }

        if (edns_rdlen) {
            if (packet_len < offset + edns_rdlen) {
                log_devdebug("Received EDNS OPT RR with options data longer than packet length");
                rcode = DECODE_FORMERR;
            } else {
                rcode = handle_edns_options(ctx, edns_rdlen, &packet[offset]);
            }
            offset += edns_rdlen;
        }
    } else {
        log_devdebug("Received EDNS OPT RR with VERSION > 0 (BADVERSION)");
        rcode = DECODE_BADVERS;
    }

    if (rcode == DECODE_OK)
        *offset_ptr = offset;
    return rcode;
}

F_NONNULL
static bool parse_first_question(txn_t* txn, unsigned* offset_ptr, const unsigned packet_len)
{
    const unsigned len = packet_len - *offset_ptr;
    if (unlikely(!len))
        return true;

    const uint8_t* buf = &txn->pkt->raw[*offset_ptr];
    uint8_t* lqname_ptr = &txn->lqname[1];
    unsigned pos = 0;
    unsigned llen;
    while ((llen = *lqname_ptr++ = buf[pos++])) {
        if (unlikely(llen & 0xC0)) {
            log_devdebug("Label compression detected in question, failing.");
            return true;
        }

        if (unlikely(pos + llen >= len)) {
            log_devdebug("Query name truncated (runs off end of packet)");
            return true;
        }

        if (unlikely(pos + llen > 254)) {
            log_devdebug("Query domain name too long");
            return true;
        }

        while (llen--) {
            if (unlikely((buf[pos] < 0x5B) && (buf[pos] > 0x40)))
                *lqname_ptr++ = buf[pos++] | 0x20;
            else
                *lqname_ptr++ = buf[pos++];
        }
    }

    // Store the overall length of the lowercased name
    txn->lqname[0] = pos;

    if (likely(pos + 4 <= len)) {
        txn->qtype = ntohs(gdnsd_get_una16(&buf[pos]));
        pos += 2;
        txn->qclass = ntohs(gdnsd_get_una16(&buf[pos]));
        pos += 2;
    } else {
        log_devdebug("Packet length exhausted before parsing question type/class!");
        return true;
    }

    *offset_ptr += pos;
    gdnsd_assert(*offset_ptr <= packet_len);
    return false;
}

F_NONNULL
static unsigned parse_rr_name_minimal(const uint8_t* buf, unsigned len)
{
    gdnsd_assert(len);
    // input len is whole remaining buffer, so cap it to legal name length so
    // we can check both limits together.
    if (len > 255)
        len = 255;
    unsigned pos = 0;
    unsigned llen;
    while ((llen = buf[pos++])) {
        if (unlikely(llen & 0xC0)) {
            pos++;
            if (unlikely(pos >= len))
                return 0;
            return pos;
        }
        pos += llen;
        if (unlikely(pos >= len))
            return 0;
    }

    return pos;
}

F_NONNULL
static bool parse_rr_minimal(const txn_t* txn, unsigned* offset_ptr, const unsigned packet_len, const bool has_data)
{
    const unsigned len = packet_len - *offset_ptr;
    if (unlikely(!len))
        return true;

    const uint8_t* buf = &txn->pkt->raw[*offset_ptr];
    unsigned pos = parse_rr_name_minimal(buf, len);
    if (unlikely(!pos))
        return true;

    if (has_data) {
        if (unlikely(pos + 10 > len)) // type/class/ttl/rdlen
            return true;
        pos += 8; // type/class/ttl
        const unsigned rdlen = ntohs(gdnsd_get_una16(&buf[pos]));
        pos += 2;
        pos += rdlen;
        if (unlikely(pos > len))
            return true;
    } else {
        if (unlikely(pos + 4 > len)) // type/class
            return true;
        pos += 4;
    }

    *offset_ptr += pos;
    gdnsd_assert(*offset_ptr <= packet_len);
    return false;
}

F_NONNULL
static rcode_rv_t parse_query_rrs(dnsp_ctx_t* ctx, unsigned* output_offset_ptr, const unsigned packet_len)
{
    gdnsd_assert(*output_offset_ptr == sizeof(wire_dns_header_t));
    gdnsd_assert(packet_len >= sizeof(wire_dns_header_t));

    const wire_dns_header_t* hdr = &ctx->txn.pkt->hdr;
    const uint8_t* packet = ctx->txn.pkt->raw;
    unsigned offset = sizeof(wire_dns_header_t);

    gdnsd_assert(!ctx->txn.qdcount);

    const unsigned qdcount = DNSH_GET_QDCOUNT(hdr);
    const unsigned ancount = DNSH_GET_ANCOUNT(hdr);
    const unsigned nscount = DNSH_GET_NSCOUNT(hdr);
    const unsigned arcount = DNSH_GET_ARCOUNT(hdr);

    if (qdcount) {
        if (parse_first_question(&ctx->txn, &offset, packet_len))
            return DECODE_FORMERR;
        // If we can parse the first question, we'll include it in the
        // output, even if the rest below may result in some other error
        // response.  Note we don't currently reflect any additional questions
        // even if they parse correctly, because it's too burdensome on our
        // output sizing constraints.
        ctx->txn.qdcount = 1;
        *output_offset_ptr = offset;
    }

    for (unsigned i = 1; i < qdcount; i++)
        if (parse_rr_minimal(&ctx->txn, &offset, packet_len, false))
            return DECODE_FORMERR;

    for (unsigned i = 0; i < ancount; i++)
        if (parse_rr_minimal(&ctx->txn, &offset, packet_len, true))
            return DECODE_FORMERR;

    for (unsigned i = 0; i < nscount; i++)
        if (parse_rr_minimal(&ctx->txn, &offset, packet_len, true))
            return DECODE_FORMERR;

    bool seen_optrr = false;
    for (unsigned i = 0; i < arcount; i++) {
        if (likely(packet_len >= (offset + 11) && packet[offset] == '\0'
                   && ntohs(gdnsd_get_una16(&packet[offset + 1])) == DNS_TYPE_OPT)) {
            if (seen_optrr) // >1 OPT RRs
                return DECODE_FORMERR;
            seen_optrr = true;
            rcode_rv_t rc = parse_optrr(ctx, &offset, packet_len);
            if (rc != DECODE_OK)
                return rc;
            continue;
        }
        if (parse_rr_minimal(&ctx->txn, &offset, packet_len, true))
            return DECODE_FORMERR;
    }

    return DECODE_OK;
}

F_NONNULL
static rcode_rv_t decode_query(dnsp_ctx_t* ctx, unsigned* output_offset_ptr, const unsigned packet_len)
{
    gdnsd_assert(ctx->txn.pkt);
    gdnsd_assert(*output_offset_ptr == sizeof(wire_dns_header_t));

    if (unlikely(packet_len < (sizeof(wire_dns_header_t)))) {
        log_devdebug("Ignoring short request of length %u", packet_len);
        return DECODE_IGNORE;
    }

    const wire_dns_header_t* hdr = &ctx->txn.pkt->hdr;

    if (unlikely(DNSH_GET_QR(hdr))) {
        log_devdebug("QR bit set in query, ignoring");
        return DECODE_IGNORE;
    }

    // In all cases other than the 2 ignores above, we will do our best to
    // parse the query RRs, and always send some kind of response packet...
    rcode_rv_t rcode = parse_query_rrs(ctx, output_offset_ptr, packet_len);

    if (rcode != DECODE_OK)
        return rcode;

    const unsigned opcode = DNSH_GET_OPCODE(hdr);

    if (opcode == DNS_OPCODE_QUERY) {
        // We could FORMERR-reject QUERY operations here if they have trailing
        // junk beyond the parsed RRs, but we'll choose not to for now and just
        // ignore such data.  For other opcodes, whether any data after the
        // indicated RR counts is illegal or not depends on the opcode, so we'd
        // rather NOTIMP them.

        // Require exactly one question, except in the case that an EDNS cookie
        // was received, in which case that standard allows zero questions as a
        // cookie-refresh ping.
        const unsigned hdr_qdcount = DNSH_GET_QDCOUNT(hdr);
        if (unlikely(hdr_qdcount > 1U || (!hdr_qdcount && !ctx->txn.edns.cookie.recvd))) {
            log_devdebug("Received QUERY request with %hu questions, FORMERR", DNSH_GET_QDCOUNT(hdr));
            return DECODE_FORMERR;
        }

        if (unlikely(ctx->txn.qtype > 127 && ctx->txn.qtype < 255)) {
            // Range 128-255 is meta-query types, not data types.  We implement ANY
            // (255) in normal response process, but we do not implement any others
            // (e.g. IXFR, AXFR, MAILA, MAILB, TKEY, TSIG, etc).
            log_devdebug("Unsupported meta-query type %u (NOTIMP) attempted", ctx->txn.qtype);
            return DECODE_NOTIMP;
        }

        return DECODE_OK;
    }

    if (opcode == DNS_OPCODE_DSO && !gcfg->disable_tcp_dso)
        return DECODE_DSO;

    log_devdebug("NOTIMP: unsupported opcode %u", opcode);
    return DECODE_NOTIMP;
}

F_NONNULL
static void shuffle_addrs_rdata(gdnsd_rstate32_t* rs, uint8_t* rrset_rdata, const unsigned rr_count, unsigned rr_len)
{
    gdnsd_assert(rr_count); // non-zero rr_count is a given!

    // These are the lengths for A and AAAA, respectively, when the
    // left-hand-side is a fully-compressed name with a two byte pointer.
    gdnsd_assert(rr_len == 16U || rr_len == 28U);

    // The first byte of the first (and all other) RR's name is either the
    // first byte of a compression pointer, or it's the root of the DNS.  The
    // root case results in RRs which are one byte shorter than expected, so we
    // need to adjust rr_len
    gdnsd_assert(*rrset_rdata & 0xC0 || *rrset_rdata == 0x0);
    if (*rrset_rdata == 0x0)
        rr_len--;

    // Fisher/Yates(/Durstenfeld/Knuth) shuffle of the fixed-length RRs within
    // the rdata chunk:
    for (unsigned i = rr_count - 1U; i > 0; i--) {
        const unsigned j = gdnsd_rand32_bounded(rs, i + 1U);
        // Logically there's little reason for the extra branch here, but
        // memcpy is undefined when given the same pointer as src and dst in
        // the middle copy below, so we may as well take the branch cost.
        if (j != i) {
            uint8_t* i_ptr = &rrset_rdata[i * rr_len];
            uint8_t* j_ptr = &rrset_rdata[j * rr_len];
            uint8_t temp[28];
            memcpy(temp, i_ptr, rr_len);
            memcpy(i_ptr, j_ptr, rr_len);
            memcpy(j_ptr, temp, rr_len);
        }
    }
}

// Invoke dyna callback for DYN[AC], taking care of zeroing
//   out ctx->dyn and cleaning up the ttl + scope_mask issues,
//   returning the TTL to actually use, in network order.
F_NONNULLX(1, 2)
static unsigned do_dyn_callback(dnsp_ctx_t* ctx, gdnsd_resolve_cb_t func, const unsigned res, const unsigned ttl_max_net, const unsigned ttl_min)
{
    dyn_result_t* dr = ctx->dyn;
    memset(dr, 0, sizeof(*dr));
    const gdnsd_sttl_t sttl = func(res, ctx->txn.qtype, &ctx->txn.edns.client_info, dr);
    if (dr->edns_scope_mask > ctx->txn.edns.client_scope_mask)
        ctx->txn.edns.client_scope_mask = dr->edns_scope_mask;
    assert_valid_sttl(sttl);
    unsigned ttl = sttl & GDNSD_STTL_TTL_MASK;
    if (ttl > ttl_max_net)
        ttl = ttl_max_net;
    else if (ttl < ttl_min)
        ttl = ttl_min;
    return ttl;
}

F_NONNULL
static ltree_rrset_raw_t* synthesize_dynac(dnsp_ctx_t* ctx, const ltree_rrset_dynac_t* rd)
{
    const unsigned ttl = do_dyn_callback(ctx, rd->func, rd->resource, rd->ttl_max, rd->ttl_min);
    dyn_result_t* dr = ctx->dyn;
    ltree_rrset_raw_t* synth = &ctx->txn.dynac_synth_rrset;
    synth->gen.type = rd->gen.type;
    synth->gen.count = dr->count;
    synth->data = dr->storage;
    synth->data_len = dr->storage_len;

    // Inject final calculated TTLs into the wire copies of all RRs
    unsigned rrlen = 16U; // this is for A, and the value doesn't matter for CNAME (1 RR)
    if (rd->gen.type == DNS_TYPE_AAAA)
        rrlen = 28U;
    for (unsigned i = 0; i < dr->count; i++)
        gdnsd_put_una32(htonl(ttl), &dr->storage[(rrlen * i) + 6U]);

    return synth;
}

F_NONNULL
static unsigned encode_rrs_raw(dnsp_ctx_t* ctx, const unsigned offset, const ltree_rrset_raw_t* rrset)
{
    gdnsd_assert(offset);
    gdnsd_assert(rrset->gen.count);
    gdnsd_assert(rrset->data);
    gdnsd_assert(rrset->data_len);

    ctx->txn.ancount += rrset->gen.count;
    ctx->txn.arcount += rrset->num_addtl;
    uint8_t* packet = ctx->txn.pkt->raw;
    memcpy(&packet[offset], rrset->data, rrset->data_len);
    if (rrset->num_comp_offsets) { // only set for wild mx/cname/ptr, deleg NS, and SOA
        // Choosing which fixup to use: NS and SOA aren't allowed at wildcards, and
        // are used in delegation and negative responses and need the _auth
        // variant.  All other uses should be wildcards fixing up right-hand-side
        // compression.
        unsigned fixup_by;
        if (rrset->gen.type == DNS_TYPE_SOA || rrset->gen.type == DNS_TYPE_NS)
            fixup_by = ctx->txn.comp_fixup_auth;
        else
            fixup_by = ctx->txn.comp_fixup_wild;
        if (fixup_by) {
            for (unsigned i = 0; i < rrset->num_comp_offsets; i++) {
                uint8_t* pkt_ptr = &packet[rrset->comp_offsets[i] + fixup_by];
                unsigned comp_ptr = ntohs(gdnsd_get_una16(pkt_ptr));
                gdnsd_assert(comp_ptr & 0xC000u);
                comp_ptr += fixup_by;
                gdnsd_assert(comp_ptr & 0xC000u);
                gdnsd_put_una16(htons(comp_ptr), pkt_ptr);
            }
        }
    }

    if (rrset->gen.type == DNS_TYPE_A)
        shuffle_addrs_rdata(&ctx->rand_state, &packet[offset], rrset->gen.count, 16U);
    else if (rrset->gen.type == DNS_TYPE_AAAA)
        shuffle_addrs_rdata(&ctx->rand_state, &packet[offset], rrset->gen.count, 28U);

    return offset + rrset->data_len;
}

F_NONNULL
static unsigned encode_rrs_dynac(dnsp_ctx_t* ctx, const unsigned offset, const ltree_rrset_dynac_t* rrset)
{
    gdnsd_assert(offset);
    gdnsd_assert(!rrset->gen.count);
    ltree_rrset_raw_t* synth = synthesize_dynac(ctx, rrset);
    if (!synth->gen.count)
        return offset;
    return encode_rrs_raw(ctx, offset, synth);
}

typedef struct {
    const ltree_node_t* dom;
    const ltree_node_t* auth;
    unsigned comp_fixup_wild;
    unsigned comp_fixup_auth;
} search_result_t;

F_NONNULL
static ltree_dname_status_t search_ltree_for_name(const uint8_t* name, search_result_t* res)
{
    memset(res, 0, sizeof(*res));

    // Construct a treepath, which is a valid uncompressed domainname, but with
    // the label order reversed (still terminates in \0)
    uint8_t treepath[255];
    const unsigned name_len = treepath_len_from_name(treepath, name);
    gdnsd_assert(name_len); // legit names are always length 1+

    ltree_dname_status_t rval = DNAME_NOAUTH;
    ltree_node_t* cur_node = rcu_dereference(root_tree);
    const uint8_t* cur_label = treepath;
    unsigned cur_label_len = *cur_label;
    unsigned name_remaining_depth = name_len - 1U;
    while (cur_node) {
        if (cur_node->zone_cut) {
            if (res->auth) {
                gdnsd_assert(rval == DNAME_AUTH);
                gdnsd_assert(cur_label >= treepath);
                res->comp_fixup_auth = name_remaining_depth;
                res->dom = cur_node;
                return DNAME_DELEG;
            }
            gdnsd_assert(rval == DNAME_NOAUTH);
            gdnsd_assert(!res->auth);
            rval = DNAME_AUTH;
            res->comp_fixup_auth = name_remaining_depth;
            res->auth = cur_node;
        }

        if (!cur_label_len) {
            res->dom = cur_node;
            return rval; // could be DNAME_AUTH or DNAME_NOAUTH
        }

        ltree_node_t* next = NULL;

        static const uint8_t label_wild[2] =  { '\001', '*' };

        // Special case: skip the lookup here iff we're already in auth space
        // and this is the last label of the input, *and* the input label is an
        // explicit '*'.  This is because we need this to take the
        // wildcard-matching clause below, just as if it were a lookup on 'foo'
        // matching the '*', so that we get the same logic and comp_fixup_wild
        if (rval == DNAME_AUTH && !cur_label[cur_label_len + 1U] && !memcmp(cur_label, label_wild, 2U)) {
            // no-op, leave "next" as NULL to use the wildcard matching below
        } else {
            next = ltree_node_find_child(cur_node, cur_label);
        }

        // If no deeper match and we're in auth space, try wildcard
        if (!next && rval == DNAME_AUTH) {
            cur_node = ltree_node_find_child(cur_node, label_wild);
            if (cur_node) {
                res->comp_fixup_wild = name_remaining_depth;
                res->dom = cur_node;
                return DNAME_AUTH;
            }
        }

        // Advance the cur_ stuff and iterate
        const unsigned jump_by = cur_label_len + 1U;
        gdnsd_assert(name_remaining_depth >= jump_by);
        name_remaining_depth -= jump_by;
        cur_label += jump_by;
        cur_label_len = *cur_label;
        cur_node = next;
    }

    gdnsd_assert(!res->dom);
    return rval; // could be DNAME_AUTH or DNAME_NOAUTH
}

F_NONNULLX(1, 3)
static unsigned do_auth_response(dnsp_ctx_t* ctx, const ltree_node_t* dom, const ltree_node_t* auth, unsigned offset)
{
    uint8_t* packet = ctx->txn.pkt->raw;
    gdnsd_assert(packet);
    wire_dns_header_t* res_hdr = &ctx->txn.pkt->hdr;
    res_hdr->flags1 |= 4; // AA bit

    const ltree_rrset_t* rrsets = dom ? dom->rrsets : NULL;

    if (rrsets) {
        if (rrsets->gen.type == DNS_TYPE_CNAME) {
            gdnsd_assert(!rrsets->gen.next); // CNAME does not co-exist with other rrsets
            ctx->txn.qtype = DNS_TYPE_CNAME;
        }
        if (ctx->txn.qtype != DNS_TYPE_ANY) {
            const ltree_rrset_t* search_rrset = rrsets;
            do {
                if (search_rrset->gen.type == ctx->txn.qtype) {
                    if (search_rrset->gen.count)
                        offset = encode_rrs_raw(ctx, offset, &search_rrset->raw);
                    else
                        offset = encode_rrs_dynac(ctx, offset, &search_rrset->dynac);
                    break;
                }
                search_rrset = search_rrset->gen.next;
            } while (search_rrset);
        }
    }

    bool chal_matched = false;
    if (!ctx->txn.ancount)
        chal_matched = chal_respond(ctx->txn.qtype, ctx->txn.lqname, packet, &ctx->txn.ancount, &offset, ctx->txn.this_max_response);

    if (ctx->txn.qtype == DNS_TYPE_ANY) {
        // construct_normal_response is not called for ANY, and
        // chal_respond does not inject an RR for ANY, so there should
        // still be zero answers here:
        gdnsd_assert(!ctx->txn.ancount);
        // ANY->CNAME was already handled above construct_normal_response by changing ctx->txn.qtype
        gdnsd_assert(!rrsets || rrsets->gen.type != DNS_TYPE_CNAME);

        // The conditional here basically means "if this wouldn't be an NXDOMAIN below"
        if (dom || chal_matched) {
            ctx->txn.ancount = 1;
            memcpy(&packet[offset], hinfo_for_any, hinfo_for_any_len);
            offset += hinfo_for_any_len;
        }
    }

    if (!ctx->txn.ancount) {
        // ltree ensures SOA is the first rrset in the zone root node
        gdnsd_assert(auth->rrsets);
        gdnsd_assert(auth->rrsets->gen.type == DNS_TYPE_SOA);
        offset = encode_rrs_raw(ctx, offset, &auth->rrsets->raw);
        // Transfer the singleton SOA's count from answer to auth section.
        gdnsd_assert(ctx->txn.ancount == 1 && !ctx->txn.nscount);
        ctx->txn.nscount = 1;
        ctx->txn.ancount = 0;
        if (!dom && !chal_matched) {
            res_hdr->flags2 = DNS_RCODE_NXDOMAIN;
            stats_own_inc(&ctx->stats->nxdomain);
        }
    }

    return offset;
}

F_NONNULL
static unsigned db_lookup(dnsp_ctx_t* ctx, unsigned offset)
{
    ltree_dname_status_t status;
    search_result_t res;
    status = search_ltree_for_name(&ctx->txn.lqname[1], &res);
    if (status == DNAME_NOAUTH) {
        ctx->txn.pkt->hdr.flags2 = DNS_RCODE_REFUSED;
        stats_own_inc(&ctx->stats->refused);
        return offset;
    }

    gdnsd_assert(res.auth);
    ctx->txn.comp_fixup_auth = res.comp_fixup_auth;
    ctx->txn.comp_fixup_wild = res.comp_fixup_wild;

    if (status == DNAME_DELEG) {
        gdnsd_assert(res.dom);
        gdnsd_assert(res.dom->rrsets);
        gdnsd_assert(res.dom->rrsets->gen.type == DNS_TYPE_NS);
        const ltree_rrset_raw_t* ns = &res.dom->rrsets->raw;
        // DNAME_DELEG uses the same code we'd use for zroot qtype=NS, but we
        // have to transfer the count of NS RRs over to the auth section
        // afterwards as a hackaround.
        unsigned rv = encode_rrs_raw(ctx, offset, ns);
        ctx->txn.nscount = ctx->txn.ancount;
        ctx->txn.ancount = 0;
        return rv;
    }

    gdnsd_assert(status == DNAME_AUTH);

    return do_auth_response(ctx, res.dom, res.auth, offset);
}

F_NONNULL
static unsigned answer_from_db(dnsp_ctx_t* ctx, unsigned offset)
{
    gdnsd_assert(offset);
    gdnsd_assert(ctx->stats);

    const unsigned full_trunc_offset = offset;

    // Respond from the DB
    rcu_read_lock();
    offset = db_lookup(ctx, offset);
    rcu_read_unlock();

    // UDP truncation handling
    if (ctx->is_udp) {
        if (!ctx->txn.edns.cookie.valid && gcfg->max_nocookie_response && gcfg->max_nocookie_response < ctx->txn.this_max_response)
            ctx->txn.this_max_response = gcfg->max_nocookie_response;

        if ((offset + ctx->txn.edns.out_bytes) > ctx->txn.this_max_response) {
            offset = full_trunc_offset;
            ctx->txn.pkt->hdr.flags1 |= 0x2; // TC bit
            ctx->txn.ancount = 0;
            ctx->txn.nscount = 0;
            ctx->txn.arcount = 0;
            if (ctx->txn.edns.req_edns)
                stats_own_inc(&ctx->stats->udp.edns_tc);
            else
                stats_own_inc(&ctx->stats->udp.tc);
        }
    }

    return offset;
}

F_NONNULL
static unsigned do_edns_output(dnsp_ctx_t* ctx, uint8_t* packet, unsigned res_offset, const rcode_rv_t status)
{
    uint32_t extflags = (status == DECODE_BADVERS) ? 0x01000000 : 0;
    if (ctx->txn.edns.do_bit)
        extflags |= 0x8000;

    packet[res_offset++] = '\0'; // domainname part of OPT
    gdnsd_put_una16(htons(DNS_TYPE_OPT), &packet[res_offset]);
    res_offset += 2;
    gdnsd_put_una16(htons(DNS_EDNS_SIZE), &packet[res_offset]);
    res_offset += 2;
    gdnsd_put_una32(htonl(extflags), &packet[res_offset]);
    res_offset += 4;
    uint8_t* rdlen_ptr = &packet[res_offset]; // filled in at end, after we know
    res_offset += 2;

    // code below which tacks on options should increment this for the overall rdlen of the OPT RR
    unsigned rdlen = 0;

    if (ctx->txn.edns.respond_client_subnet) {
        const unsigned src_mask = ctx->txn.edns.client_info.edns_client_mask;
        const unsigned scope_mask = src_mask ? ctx->txn.edns.client_scope_mask : 0;
        const unsigned addr_bytes = (src_mask >> 3) + ((src_mask & 7) ? 1 : 0);
        rdlen += (8 + addr_bytes);
        gdnsd_put_una16(htons(EDNS_CLIENTSUB_OPTCODE), &packet[res_offset]);
        res_offset += 2;
        gdnsd_put_una16(htons(4 + addr_bytes), &packet[res_offset]);
        res_offset += 2;
        gdnsd_put_una16(htons(ctx->txn.edns.client_family), &packet[res_offset]);
        res_offset += 2;
        packet[res_offset++] = src_mask;
        packet[res_offset++] = scope_mask;
        if (src_mask) {
            gdnsd_assert(addr_bytes);
            if (ctx->txn.edns.client_family == 1U) { // IPv4
                memcpy(&packet[res_offset], &ctx->txn.edns.client_info.edns_client.sin4.sin_addr.s_addr, addr_bytes);
            } else {
                gdnsd_assert(ctx->txn.edns.client_family == 2U); // IPv6
                memcpy(&packet[res_offset], ctx->txn.edns.client_info.edns_client.sin6.sin6_addr.s6_addr, addr_bytes);
            }
            res_offset += addr_bytes;
        }
    }

    // EDNS Cookie output
    if (ctx->txn.edns.cookie.respond) {
        gdnsd_assert(ctx->txn.edns.cookie.recvd);
        rdlen += 20U;
        gdnsd_put_una16(htons(EDNS_COOKIE_OPTCODE), &packet[res_offset]);
        res_offset += 2;
        gdnsd_put_una16(htons(16), &packet[res_offset]);
        res_offset += 2;
        memcpy(&packet[res_offset], ctx->txn.edns.cookie.output, 16U);
        res_offset += 16U;
    }

    // TCP keepalive is emitted with every response to an EDNS query over
    // TCP if DSO isn't established, using either the fixed timeout set
    // from config at startup, or zero if we're in shutdown_grace mode and
    // trying to get clients to disconnect.
    if (!ctx->is_udp) {
        gdnsd_assert(ctx->txn.dso);
        if (!ctx->txn.dso->estab) {
            rdlen += 6U;
            gdnsd_put_una16(htons(EDNS_TCP_KEEPALIVE_OPTCODE), &packet[res_offset]);
            res_offset += 2;
            gdnsd_put_una16(htons(2), &packet[res_offset]);
            res_offset += 2;
            gdnsd_put_una16(htons(ctx->edns_tcp_keepalive), &packet[res_offset]);
            res_offset += 2;
        }
    }

    // NSID, if configured by user and requested by query
    if (ctx->txn.edns.respond_nsid) {
        gdnsd_assert(gcfg->nsid.data);
        gdnsd_assert(gcfg->nsid.len);
        rdlen += (4U + gcfg->nsid.len);
        gdnsd_put_una16(htons(EDNS_NSID_OPTCODE), &packet[res_offset]);
        res_offset += 2;
        gdnsd_put_una16(htons(gcfg->nsid.len), &packet[res_offset]);
        res_offset += 2;
        memcpy(&packet[res_offset], gcfg->nsid.data, gcfg->nsid.len);
        res_offset += gcfg->nsid.len;
    }

    // predicted edns.out_bytes correctly earlier for truncation.  note
    // this happens before padding below.
    gdnsd_assert(ctx->txn.edns.out_bytes == (11U + rdlen));

    // Padding, must be the last option, as it must make calculations based
    // on the total size of the packet including any updates to
    // "res_offset" from earlier options
    if (ctx->tcp_pad) {
        gdnsd_assert(!ctx->is_udp);
        // RFC 8467 recommends block padding to 468, which we'll stick with
        // here even though MTU-size concerns don't really matter as much
        // for now, as we only support the TCP case.  The minimum size
        // added to a packet by the Padding option itself is 4 bytes (for
        // option code and option len of zero), plus however many bytes of
        // actual padding length is tacked on).  Note MAX_RESPONSE_DATA
        // allows us to always add the option and always obtain perfect
        // padding within MAX_RESPONSE_BUF at a block size of 468 as
        // documented in dnswire.h.
        gdnsd_assert(res_offset <= MAX_RESPONSE_DATA);
        unsigned pad_dlen = (((res_offset + 4U + PAD_BLOCK_SIZE - 1U) / PAD_BLOCK_SIZE) * PAD_BLOCK_SIZE) - 4U - res_offset;
        gdnsd_assert(res_offset + 4U + pad_dlen <= MAX_RESPONSE_BUF);

        rdlen += (4U + pad_dlen);
        gdnsd_put_una16(htons(EDNS_PADDING), &packet[res_offset]);
        res_offset += 2;
        gdnsd_put_una16(htons(pad_dlen), &packet[res_offset]);
        res_offset += 2;
        memset(&packet[res_offset], 0, pad_dlen);
        res_offset += pad_dlen;

        gdnsd_assert(res_offset <= MAX_RESPONSE_BUF);
        gdnsd_assert((res_offset % PAD_BLOCK_SIZE) == 0);
    }

    // Update OPT RR's rdlen for any options emitted above, and bump arcount for it
    gdnsd_put_una16(htons(rdlen), rdlen_ptr);
    ctx->txn.arcount++;

    // We only do one kind of truncation: complete truncation.
    //  therefore if we're returning a >512 packet, it wasn't truncated
    if (ctx->is_udp && res_offset > 512U)
        stats_own_inc(&ctx->stats->udp.edns_big);

    return res_offset;
}

F_NONNULL
static unsigned handle_dso(const dnsp_ctx_t* ctx, const unsigned packet_len)
{
    uint8_t* packet = ctx->txn.pkt->raw;
    gdnsd_assert(packet);
    wire_dns_header_t* hdr = &ctx->txn.pkt->hdr;

    // Ensure all the Z-bits (flags) are clear in any DSO response:
    // The main process_dns_query code already clears TC and AA from flags1,
    // but leaves RD as-is and sets QR for us, and we assign our rcodes
    // unmasked to flags2, which clears the other 4 bits in them (RA, reserved,
    // AD, CD) implicitly.  So all we *should* have to do here on top of that
    // is ensure we don't reflect client's RD bit, but better safe than sorry
    // in case of code changes elsewhere, so clear all but QR+Opcode:
    hdr->flags1 &= 0xF8;
    hdr->flags2 = 0;

    // If we get a DSO opcode over UDP, send a FORMERR response with no data
    // Non-zero RR counts with DSO *MUST* generate a FORMERR by the standard
    if (ctx->is_udp || (hdr->qdcount | hdr->ancount | hdr->nscount | hdr->arcount)) {
        log_devdebug("Got DSO packet over UDP or with non-zero RR counts, FORMERR");
        hdr->qdcount = 0;
        hdr->ancount = 0;
        hdr->nscount = 0;
        hdr->arcount = 0;
        stats_own_inc(&ctx->stats->formerr);
        hdr->flags2 = DNS_RCODE_FORMERR;
        return sizeof(wire_dns_header_t);
    }

    gdnsd_assert(ctx->txn.dso); // TCP always has this pointer

    // All of these cases are protocol-fatal and the standard requires immediate connection abort:
    //    A. Any unidirectional of any TLV type (ID = 0)
    //    B. Lack of a primary TLV
    //    C. Any known non-Keepalive TLV (RetryDelay, Padding) as primary
    //    D. Any length errors in blindly parsing all TLVs (TLV runs off end of
    //       packet, junk data at end of packet, etc).
    //    E. A Keepalive TLV with a data length other than 8.
    //    F. If we see EDNS Keepalive in an established DSO session (elsewhere)

    if (!hdr->id || packet_len < sizeof(wire_dns_header_t) + 4U) { // Protoerr A||B
        log_devdebug("Got DSO packet with zero id (uni) or no room for primary TLV, Proto Err -> Conn Abort");
        stats_own_inc(&ctx->stats->tcp.dso_protoerr);
        return 0;
    }

    // Offset used to parse primary TLV
    unsigned offset = sizeof(wire_dns_header_t);

    // Grab type primary request TLV
    const unsigned dtype = ntohs(gdnsd_get_una16(&packet[offset]));
    offset += 2;

    if (dtype == DNS_DSO_RETRY_DELAY || dtype == DNS_DSO_PADDING) { // Protoerr C
        log_devdebug("Got DSO packet with primary TLV known and illegal (retry or padding), Proto Err -> Conn Abort");
        stats_own_inc(&ctx->stats->tcp.dso_protoerr);
        return 0;
    }

    // Grab data len of primary request TLV
    const unsigned dlen = ntohs(gdnsd_get_una16(&packet[offset]));
    offset += 2;

    // Consume and ignore primary TLV data bytes (dlen) and all additional TLVs
    // so long as there's still room in the packet for them
    unsigned atlv_offset = offset + dlen; // start of first atlv
    while (packet_len >= (atlv_offset + 4U)) { // while 1+ ATLVs present
        const unsigned adlen = ntohs(gdnsd_get_una16(&packet[atlv_offset + 2U]));
        atlv_offset += (4U + adlen);
    }

    if (atlv_offset != packet_len) { // Protoerr D
        log_devdebug("Got DSO packet with a length parsing error, Proto Err -> Conn Abort");
        stats_own_inc(&ctx->stats->tcp.dso_protoerr);
        return 0;
    }

    if (dtype == DNS_DSO_KEEPALIVE) {
        if (dlen != 8) { // Protoerr E
            log_devdebug("Got DSO KeepAlive Request with data len %u, should be 8, Proto Err -> Conn Abort", dlen);
            stats_own_inc(&ctx->stats->tcp.dso_protoerr);
            return 0;
        }

        // We have a legitimate well-formed client KeepAlive, establishing a
        // session and requiring a matching response from us.  last_was_ka
        // informs the TCP layer not to reset the inactivity timer.
        ctx->txn.dso->last_was_ka = true;
        if (!ctx->txn.dso->estab) {
            ctx->txn.dso->estab = true;
            stats_own_inc(&ctx->stats->tcp.dso_estab);
        }

        // offset is already sitting just past the keepalive type+len, just add our data:
        gdnsd_put_una32(0xFFFFFFFFU, &packet[offset]); // keepalive interval = infinite
        offset += 4U;
        gdnsd_put_una32(htonl(ctx->dso_inactivity), &packet[offset]); // inactivity interval
        offset += 4U;
        gdnsd_assert(offset == 24U); // 12 hdr + 12 KA primary tlv response
        return offset;
    }

    // A DSO request with an unknown primary TLV type causes a DSOTYPENI error
    // response and does not establish a DSO session, but keeps the connection.
    log_devdebug("Got DSO Request of unknown type %u, DSOTYPENI", dtype);
    stats_own_inc(&ctx->stats->tcp.dso_typeni);
    hdr->flags2 = DNS_RCODE_DSOTYPENI;
    return sizeof(wire_dns_header_t);
}

F_NONNULL
static unsigned handle_dso_with_padding(const dnsp_ctx_t* ctx, const unsigned packet_len)
{
    unsigned offset = handle_dso(ctx, packet_len);

    // assert that all our known responses from above are small enough to use
    // the simplest padding case (always fits in the first padding block with
    // room for the padding option itself with zero or more bytes of pad).
    gdnsd_assert(offset <= (PAD_BLOCK_SIZE - 4U));

    // Crypto padding Additional TLV if appropriate (note that it's ok to have
    // an Additional TLV in cases where no Primary is required/allowed, such as
    // DSOTYPENI and FORMERR responses):
    if (ctx->tcp_pad && offset) {
        gdnsd_assert(!ctx->is_udp);
        gdnsd_assert(offset >= sizeof(wire_dns_header_t)); // non-zero offsets are 12+
        uint8_t* packet = ctx->txn.pkt->raw;
        gdnsd_assert(packet);
        const unsigned pad_dlen = PAD_BLOCK_SIZE - offset - 4U;
        gdnsd_put_una16(htons(DNS_DSO_PADDING), &packet[offset]);
        offset += 2U;
        gdnsd_put_una16(htons(pad_dlen), &packet[offset]);
        offset += 2U;
        memset(&packet[offset], 0, pad_dlen);
        offset += pad_dlen;
        gdnsd_assert(offset == PAD_BLOCK_SIZE);
    }

    return offset;
}

unsigned process_dns_query(dnsp_ctx_t* ctx, const gdnsd_anysin_t* sa, pkt_t* pkt, dso_state_t* dso, const unsigned packet_len)
{
    // iothreads don't allow queries larger than this
    gdnsd_assert(packet_len <= DNS_RECV_SIZE);

    memset(&ctx->txn, 0, sizeof(ctx->txn));
    gdnsd_assert(ctx->stats);
    if (ctx->is_udp)
        gdnsd_assert(!dso);
    else
        gdnsd_assert(dso);
    ctx->txn.pkt = pkt;
    ctx->txn.dso = dso;
    memcpy(&ctx->txn.edns.client_info.dns_source, sa, sizeof(*sa));

    if (sa->sa.sa_family == AF_INET6)
        stats_own_inc(&ctx->stats->v6);

    // parse_optrr() will raise this value in the udp edns case as necc.
    ctx->txn.this_max_response = ctx->is_udp ? 512U : MAX_RESPONSE_DATA;

    unsigned res_offset = sizeof(wire_dns_header_t);
    const rcode_rv_t status = decode_query(ctx, &res_offset, packet_len);

    if (status == DECODE_IGNORE) {
        stats_own_inc(&ctx->stats->dropped);
        return 0;
    }

    wire_dns_header_t* hdr = &pkt->hdr;
    hdr->flags1 &= 0x79; // Clears QR, TC, AA bits, preserves RD and Opcode
    hdr->flags1 |= 0x80; // Sets QR

    if (status == DECODE_DSO)
        return handle_dso_with_padding(ctx, packet_len);

    if (likely(status == DECODE_OK)) {
        hdr->flags2 = DNS_RCODE_NOERROR;
        if (likely(DNSH_GET_QDCOUNT(hdr) == 1U)) {
            if (likely(ctx->txn.qclass == DNS_CLASS_IN) || ctx->txn.qclass == DNS_CLASS_ANY) {
                res_offset = answer_from_db(ctx, res_offset);
            } else if (ctx->txn.qclass == DNS_CLASS_CH) {
                ctx->txn.ancount = 1;
                memcpy(&pkt->raw[res_offset], gcfg->chaos.data, gcfg->chaos.len);
                res_offset += gcfg->chaos.len;
            } else {
                hdr->flags2 = DNS_RCODE_REFUSED;
                stats_own_inc(&ctx->stats->refused);
            }
        } else {
            gdnsd_assert(ctx->txn.edns.cookie.recvd);
        }
        if (hdr->flags2 == DNS_RCODE_NOERROR)
            stats_own_inc(&ctx->stats->noerror);
    } else {
        if (status == DECODE_FORMERR) {
            hdr->flags2 = DNS_RCODE_FORMERR;
            stats_own_inc(&ctx->stats->formerr);
        } else if (status == DECODE_NOTIMP) {
            hdr->flags2 = DNS_RCODE_NOTIMP;
            stats_own_inc(&ctx->stats->notimp);
        } else {
            gdnsd_assert(status == DECODE_BADVERS);
            hdr->flags2 = DNS_RCODE_NOERROR;
            stats_own_inc(&ctx->stats->badvers);
        }
    }

    if (ctx->txn.edns.req_edns)
        res_offset = do_edns_output(ctx, pkt->raw, res_offset, status);

    gdnsd_put_una16(htons(ctx->txn.qdcount), &hdr->qdcount);
    gdnsd_put_una16(htons(ctx->txn.ancount), &hdr->ancount);
    gdnsd_put_una16(htons(ctx->txn.nscount), &hdr->nscount);
    gdnsd_put_una16(htons(ctx->txn.arcount), &hdr->arcount);

    gdnsd_assert(res_offset <= MAX_RESPONSE_BUF);

    return res_offset;
}
