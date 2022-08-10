ROOTER=doas
if ! command -v doas &> /dev/null; then
	ROOTER=sudo
fi

if [ ! -d build ]; then
	mkdir build
fi
cd build && cmake .. && make
$ROOTER setcap cap_net_admin=eip ./tcp-tun
./tcp-tun &
pid=$!
$ROOTER ip address add 192.168.20.1/24 dev tun0
$ROOTER ip link set up dev tun0
trap "kill $pid && cd .." INT
wait $pid
