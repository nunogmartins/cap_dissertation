#!/bin/bash

mkdir $DIR_PATH

for i in {0..9}
do
	beforeRX=$(ifconfig eth0 | grep "RX packets" | awk '{print($2) }' | awk 'BEGIN{FS=":"}{$2=$2}1' |awk '{print($2)}')
	beforeTX=$(ifconfig eth0 | grep "TX packets" | awk '{print($2) }' | awk 'BEGIN{FS=":"}{$2=$2}1' |awk '{print($2)}')
	script -a $DIR_PATH/times.$i.log -c "time ./manager -p -t -m -c config.cfg * 2> $DIR_PATH/output.$i.log"
	afterRX=$(ifconfig eth0 | grep "RX packets" | awk '{print($2) }' | awk 'BEGIN{FS=":"}{$2=$2}1' |awk '{print($2)}')
	afterTX=$(ifconfig eth0 | grep "TX packets" | awk '{print($2) }' | awk 'BEGIN{FS=":"}{$2=$2}1' |awk '{print($2)}')
	echo "---------------------------------" >> $DIR_PATH/output.$i.log
	echo "transferidos $((afterTX - beforeTX))" >> $DIR_PATH/output.$i.log
	echo "recebidos $((afterRX - beforeRX))" >> $DIR_PATH/output.$i.log
done
