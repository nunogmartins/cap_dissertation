#!/bin/bash
for i in {0..2}
do
	export DIR_PATH="data_"$i
	exec $1
done
