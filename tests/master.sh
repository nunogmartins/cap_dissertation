#!/bin/bash
#for i in {0..2}
#do
#	export DIR_PATH="data_"$i
#	./exec_shell.sh
#done


	export DIR_PATH="data_0"
	./exec_shell0.sh config0.cfg
	export DIR_PATH="data_1"
	./exec_shell1.sh config1.cfg
	export DIR_PATH="data_2"
	./exec_shell2.sh config2.cfg
