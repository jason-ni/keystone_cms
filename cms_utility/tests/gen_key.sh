#!/bin/bash

openssl genrsa -out cakey.pem 1024 -config openssl.conf
echo 'gen cakey ok.'

openssl req -new -x509 -extensions v3_ca -passin pass:None -key cakey.pem -out ca.pem -days 3650 -config openssl.conf -subj /C=US/ST=Unset/L=Unset/O=Unset/CN=www.example.com
echo 'gen req'

openssl genrsa -out signing_key.pem 1024 -config openssl.conf
echo 'gen signing key'

openssl req -key signing_key.pem -new -nodes -out req.pem -config openssl.conf -subj /C=US/ST=Unset/L=Unset/O=Unset/CN=www.example.com
echo 'gen req'

openssl ca -batch -out signing_cert.pem -config openssl.conf -days 3650 -cert cq.pem -keyfile cakey.pem -infiles req.pem
echo 'ca'

