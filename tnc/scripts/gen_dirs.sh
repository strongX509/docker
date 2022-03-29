#! /bin/sh

for dir in client server
do
  cd $dir
  mkdir -p bliss pkcs12 pkcs8 private pubkey rsa x509aa x509ac x509crl x509ocsp
  cd ..
done
