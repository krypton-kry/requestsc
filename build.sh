#!/bin/bash

pushd build
cc -g -I ../external/ -I ../external/BearSSL ../code/main.c -o main -lssl -lcrypto
popd