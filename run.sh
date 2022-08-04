ROOTER=doas
if ! command -v doas &> /dev/null; then
	ROOTER=sudo
fi
make
$ROOTER setcap cap_net_admin=eip ./tcp-tun.out
./tcp-tun.out &
pid=$!
$ROOTER ip address add 192.168.1.1/24 dev tun0
$ROOTER ip link set up dev tun0
trap "kill $pid" INT
wait $pid
