#!/bin/bash
for i in {0..9}
do
cat times.$i.log |grep real |awk '{ print($2) }' >> realfulltimes
done

#for i in {0..9}
#do
#cat times.$i.log |grep user |awk '{ print($2) }' >> userfulltimes
#done

#for i in {0..9}
#do
#cat times.$i.log |grep sys |awk '{ print($2) }' >> sysfulltimes
#done



#cat fulltimes | awk 'BEGIN{FS="m"}{$1=$1}1' | awk '{print($1)}' >> minutes_tmp_my_data.csv
#cat fulltimes | awk 'BEGIN{FS="."}{$2=$2}1' | awk '{print($1)}' >> seconds_tmp_my_data.csv
#cat fulltimes | awk 'BEGIN{FS=""}{$2=$2}1' | awk '{print($2)}' |sed 's/s//' >> miliseconds_tmp_my_data.csv

cat realfulltimes |sed 's/m/ / ' | sed 's/\./ /' | sed 's/s/ /' |awk '{print($1)}' >> minutes_tmp_data.csv
cat realfulltimes |sed 's/m/ / ' | sed 's/\./ /' | sed 's/s/ /' |awk '{print($2)}' >> seconds_tmp_data.csv
cat realfulltimes |sed 's/m/ / ' | sed 's/\./ /' | sed 's/s/ /' |awk '{print($3)}' >> miliseconds_tmp_data.csv

exec 3<"minutes_tmp_data.csv"
exec 4<"seconds_tmp_data.csv"
exec 5<"miliseconds_tmp_data.csv"

for i in {0..9}
do
read mline <&3
minutes=$((mline))
read sline <&4
seconds=$((sline))
read mmline <&5

miliseconds=$mmline
if [ $i -eq 9 ]
then
	echo -n "$((minutes*60+seconds))"".$miliseconds" >> my_data.csv
else
	echo -n "$((minutes*60+seconds))"".$miliseconds," >> my_data.csv
fi
done
