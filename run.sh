make
doas setcap cap_net_admin=eip ./tcp-tun
./tcp-tun &
pid=$!
doas ip address add 192.168.1.1/24 dev tun0
doas ip link set up dev tun0
trap "kill $pid" INT
wait $pid
