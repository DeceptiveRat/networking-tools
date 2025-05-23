#!/bin/bash 

startDirectory=`pwd`

cd ../include
find . -name "*.h" | while read -r header_file; do
	c_file="${header_file%.h}.c"
	if [[ -f "$c_file" ]]; then
		o_file="${c_file%.c}.o"
		gcc -c "$c_file" -o "$o_file" -Wall -g
		echo "compiled $c_file into $o_file"
	else
		echo "warning: No matching .c file for $header_file"
	fi
done
cd "$startDirectory"
gcc -I../include -c packetSniffer.c -o packetSniffer.o -Wall -g
gcc ../include/*.o packetSniffer.o -o packetSniffer -lpcap -lz -lm
exit
