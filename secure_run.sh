#!/bin/bash

ROOTER=sudo

set -x
cmake -Bbuild/ && make -j$(nproc) -C build/ || exit 1
$ROOTER setcap cap_net_admin=eip build/tcp-tun || exit 1
build/tcp-tun &
pid=$!
trap "kill $pid" INT
wait $pid
