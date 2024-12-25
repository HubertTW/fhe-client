#!/bin/bash

#array=("a aaaaaaaaaaaaaaaaaa" "a aaaaa aaaaaaaaaaaa" "a aaaa aaaa aaaaaaaa" "a aaa aaa aaa aaaaaa" "a aa aa aa aa aaaaaa" "a a a a a a aaaaaaaa" "a a a a a a a aaaaaa" "a a a a a a a a aaaa" "a a a a a a a a a aa")
#string_num=(2 3 4 5 6 7 8 9 10)

#array=("a" "aa" "aaa" "aaaa" "aaaab" "aaaabb" "aaaabbb" "aaaabbbb" "aaaabbbbb" "aaaabbbbbb")
#string_num=(1 1 1 1 1 1 1 1 1 1)
array=("please rm all bat file")
#string_num=(5)

rm ~/fhe-proxy/eval.log
rm ~/fhe-client/eval.log

for idx in "${!array[@]}"; do
    cd ~/fhe-client
    sh reset.sh
    cargo run --release "${array[idx]}" >>eval.log
    sh copy.sh

    cd ~/fhe-proxy
    rm slice*
    cargo run --release "${#array[idx]}"  >> eval.log
    sh reset.sh
    rm ~/fhe-worker/slice*
    cp slice* ~/fhe-san
    #cp slice* ~/fhe-worker


done

echo "All tasks completed successfully!"
