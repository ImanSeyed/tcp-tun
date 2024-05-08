## Description

This repository is a learning experience in implementing TCP stack in userspace via a `tun` interface.

## How to Run it

 To build and execute the project, run `secure_run.sh` with bash:

```bash
$ bash secure_run.sh
```

To establish a connection, run `nc` as below:

```bash
$ nc 192.168.20.10 123
```

## Warning

Don't use this project as an inbound yet; otherwise, your Internet connection will get lost. This project is under development and it's not a complete TCP stack implementation, therefore just test it without changing your routing table.

## RFCs

- [RFC 791](https://datatracker.ietf.org/doc/html/rfc791) (IPv4)
- [RFC 793](https://datatracker.ietf.org/doc/html/rfc793) (TCP)
- [RFC 1071](https://www.rfc-editor.org/rfc/rfc1071) (Checksum calculation)
- [RFC 7414](https://datatracker.ietf.org/doc/html/rfc7414#section-2) (A roadmap for TCP implementation)
