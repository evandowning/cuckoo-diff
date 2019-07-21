#!/bin/bash

dumps='../intel_workshop_output'

# rbot.original
og_hash='b02bff99c66c3003f6acdfa206302f32987d6589c3b3d5d30f5d05ba7e1c850f'

# Get path of sysdump for original file
og_dump=`find ${dumps}/${og_hash} -type f | grep sysdump`

# Copy original file
cp $og_dump $og_hash

for fn in `find $dumps -type f | grep sysdump`;
do
    fn_hash="${fn: ${#dumps}+1 : 64}"
    echo "$fn_hash"

    # If this sample is the original, ignore it
    if [ "$fn_hash" == "$og_hash" ]; then
        continue
    fi

    # Diff these files
    cp $fn $fn_hash

    python diff.py "$og_hash" "$fn_hash" > "${fn_hash}.out" 2> "${fn_hash}.err"

    rm "$fn_hash"
done
