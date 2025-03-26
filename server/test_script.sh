#!/usr/bin/env bash

args=$(python ./encode.py "$1")
enc_res=$(curl -s "http://localhost:8000/?args=${args}")
res=$(python ./decode.py "$enc_res")
echo $"$res"
