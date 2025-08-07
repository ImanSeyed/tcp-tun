### TCP Stack Implementation
A userspace TCP/IPv4 stack implementation using TUN interfaces for educational purposes.

### Features
#### Implemented
- [x] IPv4 header processing with checksum validation
- [x] TCP header parsing and generation
- [x] TCP 3-way handshake (SYN, SYN-ACK, ACK)
- [x] Connection establishment and termination
- [x] Dynamic connection hash table with `list_head` collision chains
- [x] Proper sequence number arithmetic with wrap-around support
- [x] TUN interface integration for packet I/O
- [x] Basic TCP state machine (LISTEN, SYN-RCVD, ESTABLISHED, FIN-WAIT-1, etc.)

#### Planned
- [ ] Retransmission and timeout handling
- [ ] TCP window management and flow control
- [ ] Out-of-order packet buffering
- [ ] Congestion control algorithms

### Architecture
```
 ┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
 │   Application   │<──>│   TCP Stack      │<──>│  TUN Interface  │
 │   (netcat, etc) │    │                  │    │                 │
 └─────────────────┘    └──────────────────┘    └─────────────────┘
                               │
                       ┌───────v───────┐
                       │ Connection    │
                       │ Hash Table    │
                       └───────────────┘
```
### Quick Start
```bash
# Build and run with proper network setup
 bash secure_run.sh
```
Currently the server IP address is hard-coded (`192.168.20.1`), but client range can be any IP in `192.168.20.2-254`.
```bash
# In another terminal, connect using netcat
nc 192.168.20.42 42
```

### Limitations
**WARNING**: This is an educational implementation. Do not use in production or as your primary network stack.

### Standards Compliance
Implementation follows these RFCs:
- [RFC 791](https://datatracker.ietf.org/doc/html/rfc791) Internet Protocol (IPv4)
- [RFC 793](https://datatracker.ietf.org/doc/html/rfc793) Transmission Control Protocol (TCP)
- [RFC 1071](https://www.rfc-editor.org/rfc/rfc1071) Computing the Internet Checksum
- [RFC 7414](https://datatracker.ietf.org/doc/html/rfc7414#section-2) A Roadmap for TCP Implementation
