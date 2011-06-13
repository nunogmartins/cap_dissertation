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

done
