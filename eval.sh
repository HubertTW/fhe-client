#!/bin/bash

#array=("aa" "aaaa" "aaaaaa" "aaaaaaaa" "aaaaaaaaaa" "aaaaaaaaaabb" "aaaaaaaaaabbbb" "aaaaaaaaaabbbbbb" "aaaaaaaaaabbbbbbbb")
array=("aaaaaaaa" "aaaaaaaaaa")
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
    cp slice* ~/fhe-worker

    cd ~/fhe-worker/
    cargo run --release "${#array[idx]}" >> mtek_20240116.log
    rm slice* ~/fhe-worker

    #cp slice* ~/fhe-worker


done

echo "All tasks completed successfully!"
