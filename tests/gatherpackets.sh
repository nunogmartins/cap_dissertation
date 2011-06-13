#!/bin/bash
for i in {0..9}
do

recv_packets=$(cat output.$i.log |grep recebidos |awk '{ print($2) }')
trans_packets=$(cat output.$i.log |grep transferidos |awk '{ print($2) }')

tcap_packets=$(cat output.$i.log |grep captured |awk '{ print($1) }')
trecv_packets=$(cat output.$i.log |grep received |awk '{ print($1) }')
tdrop_packets=$(cat output.$i.log |grep dropped |awk '{ print($1) }')

#echo "tcapturei $((tcap_packets)) pacotes"
#echo "trecebi $((trecv_packets)) pacotes"
#echo "tdrop $((tdrop_packets)) pacotes"
#echo "enviei $((trans_packets)) pacotes"
#echo "recebi $((recv_packets)) pacotes"

echo "$((tcap_packets));$((trecv_packets));$((tdrop_packets));$((trans_packets));$((recv_packets))"

        beforePRX=$(cat ifconfig.old.$i.log | grep "RX packets" | awk '{print($2) }' | awk 'BEGIN{FS=":"}{$2=$2}1' |awk '{print($2)}')
        beforePTX=$(cat ifconfig.old.$i.log | grep "TX packets" | awk '{print($2) }' | awk 'BEGIN{FS=":"}{$2=$2}1' |awk '{print($2)}')
        beforeBRX=$(cat ifconfig.old.$i.log | grep "RX bytes" | awk '{print($2) }' | awk 'BEGIN{FS=":"}{$2=$2}1' |awk '{print($2)}')
        beforeBTX=$(cat ifconfig.old.$i.log | grep "TX bytes" | awk '{print($6) }' | awk 'BEGIN{FS=":"}{$2=$2}1' |awk '{print($2)}')
         
	 afterPRX=$(cat ifconfig.new.$i.log | grep "RX packets" | awk '{print($2) }' | awk 'BEGIN{FS=":"}{$2=$2}1' |awk '{print($2)}')
         afterPTX=$(cat ifconfig.new.$i.log | grep "TX packets" | awk '{print($2) }' | awk 'BEGIN{FS=":"}{$2=$2}1' |awk '{print($2)}')
         afterBRX=$(cat ifconfig.new.$i.log | grep "RX bytes" | awk '{print($2) }' | awk 'BEGIN{FS=":"}{$2=$2}1' |awk '{print($2)}')
         afterBTX=$(cat ifconfig.new.$i.log | grep "TX bytes" | awk '{print($6) }' | awk 'BEGIN{FS=":"}{$2=$2}1' |awk '{print($2)}')
        echo "$((afterPTX - beforePTX));$((afterPRX - beforePRX));$((afterBTX - beforeBTX));$((afterBRX - beforeBRX))"
done

