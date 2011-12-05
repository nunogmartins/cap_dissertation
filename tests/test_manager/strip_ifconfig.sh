#!/bin/bash

read line;


packet=${line%:*}
RX=${line#*:}
echo $RX

read newline
TXpacket=${newline%:*}
TX=${newline#*:}
echo $TX
