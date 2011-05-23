#!/bin/bash

for i in {0..9}
do
	beforeRX=$(ifconfig eth0 | grep "RX packets" | awk '{print($2) }' | awk 'BEGIN{FS=":"}{$2=$2}1' |awk '{print($2)}')
	beforeTX=$(ifconfig eth0 | grep "TX packets" | awk '{print($2) }' | awk 'BEGIN{FS=":"}{$2=$2}1' |awk '{print($2)}')
	script -a times.$i.log -c "time ./manager -p -t -m -c config.cfg * 2> output.$i.log"
	#sleep 10
	afterRX=$(ifconfig eth0 | grep "RX packets" | awk '{print($2) }' | awk 'BEGIN{FS=":"}{$2=$2}1' |awk '{print($2)}')
	afterTX=$(ifconfig eth0 | grep "TX packets" | awk '{print($2) }' | awk 'BEGIN{FS=":"}{$2=$2}1' |awk '{print($2)}')
	echo "transferidos $((afterTX - beforeTX))"
	echo "recebidos $((afterRX - beforeRX))"
done
