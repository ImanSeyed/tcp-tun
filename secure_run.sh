#!/bin/bash
ROOTER=doas
if ! command -v doas &> /dev/null; then
        ROOTER=sudo
fi

if [ ! -d build ]; then
        mkdir build
fi

cmake -Bbuild/ -S. && make -j$(nproc) -C build/ && cd build/ || exit 1
$ROOTER setcap cap_net_admin=eip ./tcp-tun || exit 1
./tcp-tun &
pid=$!
trap "kill $pid && cd .." INT
wait $pid
