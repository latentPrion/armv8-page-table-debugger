/** @brief Given a payload, this function will determine how much of that
 * payload can be transmitted within a given MTU, taking into account the
 * IP header, and then it will return the number of bytes of payload which
 * were actually rendered into the destbuffer.
 *
 * Make sure that you set `mtu_sz` to the size of the L2 MTU *minus* the total
 * size of the L2 headers -- and not just the raw L2 MTU.
 *
 * ASSUMPTIONS:
 *
 * It is assumed that the memory at `dest` is capable of holding at least
 * `l2_mtu_minus_l2_hdr_sz` bytes.
 *
 * @return The number of bytes of L3 payload which were able to be packed into
 *         `dest` buf. I.e, *not* including the L3 IP header which was
 *         constructed by this function.
 *         Returns 0 on FAILURE.
 */
static size_t
exasock_pktdrill_ipfrag_construct(uint8_t *dest, const uint8_t *payload,
                                  const size_t remaining_payload_sz,
                                  const size_t payload_cursor,
                                  const size_t l2_mtu_minus_l2_hdr_sz,
                                  const struct ip *orig_hdr)
{
    size_t this_frag_payload_sz;
    struct ip *this_frag_hdr;
    uint16_t this_frag_csum, frag_fields;
    bool is_last_fragment;
    const size_t per_frag_l3_max_payload_sz = l2_mtu_minus_l2_hdr_sz
                                              - sizeof(struct ip);

    this_frag_hdr = (struct ip *)dest;

    is_last_fragment = !!(remaining_payload_sz <= per_frag_l3_max_payload_sz);
    this_frag_payload_sz = (is_last_fragment)
                           ? remaining_payload_sz
                           : per_frag_l3_max_payload_sz;

    if (!is_last_fragment && this_frag_payload_sz % 8) {
        /* The IP fragment offset field is in multiples of 8 bytes, so we must
         * send fragments whose sizes are multiples of 8, so that fragments
         * always begin at offsets aligned by 8.
         *
         * Cut off the trailing bytes and send them in the next fragment.
         */
        this_frag_payload_sz &= ~((size_t)8 - 1);
    }

fprintf(stderr, "ipfrag_construct: dest %p, payload %p, orig_hdr %p, this_f_hdr %p.\n"
        "\tWill be sending %zuB of payload this frag (last? %d)\n",
        dest, payload, orig_hdr, this_frag_hdr,
        this_frag_payload_sz, is_last_fragment);

    *this_frag_hdr = *orig_hdr;
    memcpy(&this_frag_hdr[1], payload, this_frag_payload_sz);

    /* Deal with frag flags. We don't set 'DF' (don't fragment), and the
     * reserved field must be 0.
     */
    frag_fields = payload_cursor / 8;
    if (frag_fields & ~(IP_OFFMASK)) {
        fprintf(stderr, "IP Fragmenter: frag offset field value %x exceeds "
                "length of field. Not transmitting.\n",
                frag_fields);

        return 0;
    }

    if (!is_last_fragment) {
        frag_fields |= IP_MF;
    }
    this_frag_hdr->ip_off = htons(frag_fields);

    // Checksum the IP header.
fprintf(stderr, "IP CKSUM: hdrlen: ntoh %d, nontoh %d * 4\n",
    ntohs(this_frag_hdr->ip_hl), this_frag_hdr->ip_hl);

    this_frag_hdr->ip_sum = 0;
    /* You need an IPv4 checksum calculator. */
    this_frag_csum = ipv4_checksum(this_frag_hdr, this_frag_hdr->ip_hl * 4);
    this_frag_hdr->ip_sum = htons(this_frag_csum);
    return this_frag_payload_sz;
}

/** @brief Does IP dgram fragmentation and sends out dgram fragments using
 * repeated incremental calls to a layer 2 NIC driver's TX api.
 *
 * ASSUMPTIONS:
 *
 * Assumes a that the only MTU it needs to care about is the underlying exanic
 * device's MTU and assumes that there are no protocols
 * (such as MPLS, ATM, etc) underlying the Eth frame.
 *
 * @return 0 on success, nonzero on error.
 */
static int
exasock_pktdrill_netdev_send(__attribute__((unused)) void *userdata,
                             const void *buf, size_t count)
{
    struct exasock_pktdrill_audit_dev *dev;
    size_t cursor, cur_frag_nbytes_sent;
    // uint8_t is preferable to char here.
    int ret, frag_retry_count;
    const struct ip *orig_hdr = (struct ip *)buf;
    const int frag_max_retry_attempts = 4;
    const uint8_t dst_mac[ETH_ALEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    const uint8_t src_mac[ETH_ALEN] = { 0, 0, 0, 0, 0, 0 };

    if (count > IP_MAXPACKET) {
        return -1;
    }

    dev = exasock_pktdrill_get_audit_dev(userdata);

fprintf(stderr, "Exasock: netdev_send(%zuB) called! Dev %p, tx_stage %p\n",
        count, dev, dev->eth_frame_staging_buf);

    frag_retry_count = 0;
    /* The actual layer 3 payload begins after the IP header, so pre-advance
     * the cursor past the IP header of packetdrill's datagram.
     */
    cursor = sizeof(struct ip);

    for (; cursor < count; cursor += cur_frag_nbytes_sent)
    {
        const size_t dgram_total_remaining = count - cursor;

        if (frag_retry_count >= frag_max_retry_attempts) {
            fprintf(stderr, "Exasock: pktdrill: netdev_send: Failed to send "
                    "IP fragment (offset %zu).\n"
                    "\tAborting the rest of current dgram.\n",
                    cursor);

            return -1;
        }

#ifdef EXASOCK_PKTDRILL_ENABLE_IP_FRAGMENTATION
        /* per frag L2 payload sz is L2 MTU minus (Eth hdr + Eth Footr). */
        const size_t per_frag_l2_payload_sz = dev->tx_mtu
                                              - sizeof(struct ethhdr) + 4;

        cur_frag_nbytes_sent = exasock_pktdrill_ipfrag_construct(
                                            dev->eth_frame_staging_buf + sizeof(struct ethhdr),
                                            &((uint8_t *)buf)[cursor],
                                            dgram_total_remaining,
                                            cursor - sizeof(struct ip),
                                            per_frag_l2_payload_sz,
                                            orig_hdr);
fprintf(stderr, "Frag off %zu: %zu bytes to be sent (L2 payload capacity %zu).\n",
        cursor, cur_frag_nbytes_sent, per_frag_l2_payload_sz);

        if (cur_frag_nbytes_sent < 1)
        {
            fprintf(stderr, "Exasock: pktdrill: fragment for offset %zu into "
                    "dgram failed fragmentation.\n",
                    cursor);

            cur_frag_nbytes_sent = 0;
            frag_retry_count++;
            continue;
        }
#else
        memcpy(dev->eth_frame_staging_buf + sizeof(struct ethhdr),
               orig_hdr, count);

        cur_frag_nbytes_sent = dgram_total_remaining;
#endif

        /* Now prepare the Eth encapsulation around the datagram. */
        exasock_pktdrill_eth_encap(dev->eth_frame_staging_buf,
                                   cur_frag_nbytes_sent + sizeof(struct ip),
                                   dst_mac, src_mac,
                                   ETH_P_IP);

        ret = exanic_transmit_frame(dev->tx,
                                    (const char *)dev->eth_frame_staging_buf,
                                    cur_frag_nbytes_sent + sizeof(struct ip)
                                    + sizeof(struct ethhdr));

        if (ret != 0) {
            /* Setting cur_frag_nbytes_sent to 0 will ensure that the cursor
             * isn't incremented, and so the loop will retry this frame
             * on the next iteration.
             *
             * We maintain a retry counter and if it is exceeded we give up on
             * transmitting this datagram.
             */
            cur_frag_nbytes_sent = 0;
            frag_retry_count++;
            continue;
        }
    }

    return 0;
}
