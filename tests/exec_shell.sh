#!/bin/bash

for i in {0..9}
do
	ifconfig eth0 | grep packets | awk '{print($2) }' | awk 'BEGIN{FS=":"}{$2=$2}1' |awk '{print($2)}'
	time ./manager -p -t -m -c config.cfg
	ifconfig eth0 | grep packets | awk '{print($2) }' | awk 'BEGIN{FS=":"}{$2=$2}1' |awk '{print($2)}'
done
