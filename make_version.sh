#!/bin/bash

hash=`git rev-parse --short=8 HEAD`
str="#define COMMIT_HASH \"$hash\""

if [[ $(< commit_hash.h) != "#define COMMIT_HASH \"$hash\"" ]]; then
   echo "$str"
   echo "$str" > commit_hash.h    
fi
