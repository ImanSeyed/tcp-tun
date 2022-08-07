## Description

This repository is a learning experience in implementing TCP with C language. In order not to get bothered by the Linux kernel TCP implementation, it's over a `tun` interface.

## How To Run It

You just need to run `run.sh` with bash:

```bash
$ bash run.sh
```

Don't worry about `sudo` stuff. It's for setting some capabilities over `tcp-tun` file and assigning IP address for `tun` interface. Of course, you can just do the process manually. (Just read the `run.sh` script)

You can use `nc` to make a connection with the program.

```bash
$ nc 192.168.20.10 123
```

## Warning

Don't mess with routing stuff if you don't know what you're doing, otherwise your connection to the Internet can get lost. This program is under development and it's not a complete TCP implementation, therefor just test it on a `tun` device without changing your routing table.

## Standards

- [RFC 791](https://datatracker.ietf.org/doc/html/rfc791) (IPv4)
- [RFC 793](https://datatracker.ietf.org/doc/html/rfc793) (TCP)
- [RFC 7414](https://datatracker.ietf.org/doc/html/rfc7414#section-2) (A Roadmap for TCP Implementation)
