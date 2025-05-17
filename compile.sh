#!/bin/bash 

COMPILEOPTION="-Wall -g"
LINKOPTION="-lm -lz"
LIBRARIESUSED=""
HEADERDIRECTORY="../include"
STARTDIR=`pwd`
while getopts "f:h:c:l:s" opt; do
    case $opt in 
        f) FILE="$OPTARG";;
        h) 
            HEADERDIRECTORY="$OPTARG"
            cd "$HEADERDIRECTORY"
            find . -name "*.h" | while read -r header_file; do
				header_file=${header_file#./}
                c_file="${header_file%.h}.c"
                if [[ -f "$c_file" ]]; then
                    o_file="${c_file%.c}.o"
					set -x
                    gcc -c "$c_file" -o "$o_file" $COMPILEOPTION
					set +x
                else
                    echo "warning: No matching .c file for $header_file"
                fi
            done
            cd "$STARTDIR" ;;
        c) COMPILEOPTION="$OPTARG" ;;
        l) LINKOPTION="$OPTARG" ;;
		s) LINKOPTION+=" -static" ;;
    esac    
done

if [[ -z "$FILE" ]]; then
    echo "Error: Please provide a source file with -f"
    exit 1
fi

if [[ -z "$LIBRARIESUSED" ]]; then
	for i in `grep '#include "' $FILE | awk '{
    match($0, /"[^"]+"/)
    full = substr($0, RSTART+1, RLENGTH-4)
    n = split(full, parts, "/")
    print parts[n]}' |
	tr '\n' ' ';`
	do
		LIBRARIESUSED+="$i.o "
	done
fi

echo "compiling using libraries: "
echo "$LIBRARIESUSED"

if [[ "$LINKOPTION" == *-static* ]]; then
	cd "$HEADERDIRECTORY"
	ar rcs lib"${FILE%.*}".a $LIBRARIESUSED
	cd "$STARTDIR"

	cp "$FILE" "$FILE".bkp
	set -x
	gcc -I "$HEADERDIRECTORY" -c "$FILE" -o "${FILE%.*}".o $COMPILEOPTION
	gcc "${FILE%.*}".o -o "${FILE%.*}" -L"$HEADERDIRECTORY" -l"${FILE%.*}" $LINKOPTION
	set +x
	mv "$FILE".bkp "$FILE"

	cd "$HEADERDIRECTORY"
	rm lib"${FILE%.*}".a
else
	cp "$FILE" "$FILE".bkp
	set -x
	gcc -I "$HEADERDIRECTORY" -c "$FILE" -o "${FILE%.*}".o $COMPILEOPTION
	cd "$HEADERDIRECTORY"
	gcc "$STARTDIR"/"${FILE%.*}".o -o "$STARTDIR"/"${FILE%.*}" $LIBRARIESUSED $LINKOPTION
	set +x
	cd "$STARTDIR"
	mv "$FILE".bkp "$FILE"
fi

exit
