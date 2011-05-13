#!/bin/bash

for i in {0..9}
do
	before=$(ifconfig eth0 | grep "RX packets" | awk '{print($2) }' | awk 'BEGIN{FS=":"}{$2=$2}1' |awk '{print($2)}')
	time ./manager -p -t -m -c config.cfg
	#sleep 10
	after=$(ifconfig eth0 | grep "RX packets" | awk '{print($2) }' | awk 'BEGIN{FS=":"}{$2=$2}1' |awk '{print($2)}')
	echo $((after - before))
done
