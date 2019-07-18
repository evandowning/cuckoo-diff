#!/bin/bash

dumps='../nvmtrace-dump'

og='rbot-original'

# Copy original file
cp "$dumps/$og" .

for fn in `find $dumps -type f`;
do
    name=`basename $fn`

    echo "$name"

    if [ "$name" == "$og" ]; then
        continue
    fi

    # Diff these files
    cp "$fn" .

    python diff.py "$og" "$name" > "${name}.out" 2> "${name}.err"

    rm "$name"
done
