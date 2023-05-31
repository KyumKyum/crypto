#! /bin/sh

gcc cbc.c -lm -lssl -lcrypto -o cbc
./cbc