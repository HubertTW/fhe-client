#!/bin/bash

#array=("a aaaaaaaaaaaaaaaaaa" "a aaaaa aaaaaaaaaaaa" "a aaaa aaaa aaaaaaaa" "a aaa aaa aaa aaaaaa" "a aa aa aa aa aaaaaa" "a a a a a a aaaaaaaa" "a a a a a a a aaaaaa" "a a a a a a a a aaaa" "a a a a a a a a a aa")
#string_num=(2 3 4 5 6 7 8 9 10)

#array=("a" "aa" "aaa" "aaaa" "aaaab" "aaaabb" "aaaabbb" "aaaabbbb" "aaaabbbbb" "aaaabbbbbb")
#string_num=(1 1 1 1 1 1 1 1 1 1)
array=("aaaabbbb")
string_num=(1)

rm ~/fhe-proxy/eval.log
rm ~/fhe-client/eval.log

for idx in "${!array[@]}"; do
    cd ~/fhe-client
    sh reset.sh
    cargo run --release "${array[idx]}" >>eval.log
    sh copy.sh

    cd ~/fhe-proxy
    cargo run --release "${#array[idx]}" "${string_num[idx]}" >> eval.log
    sh reset.sh


done

echo "All tasks completed successfully!"
