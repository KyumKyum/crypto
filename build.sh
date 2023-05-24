#! /bin/sh

gcc aes.c -lm -lssl -lcrypto -o aes
./aes