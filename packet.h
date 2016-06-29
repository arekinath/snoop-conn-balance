#if !defined(_PACKET_H)
#define _PACKET_H

void clean_dns(uint32_t time);
void got_tcp_conn(uint32_t src, uint32_t dst, uint16_t sport, uint16_t dport);
void print_summary(void);
void parse_dns(uint32_t src, uint32_t dst, uint16_t sport, uint16_t dport,
    const uint8_t *data, int len, uint32_t time);

#endif
