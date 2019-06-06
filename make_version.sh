#!/bin/bash
hash=`git rev-parse --short=8 HEAD`
str="#define COMMIT_HASH \"$hash\""
echo "$str"
echo "$str" > commit_hash.h
