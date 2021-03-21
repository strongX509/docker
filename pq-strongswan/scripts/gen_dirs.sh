#! /bin/sh

for dir in moon carol
do
  cd $dir
  mkdir -p ecdsa pkcs12 pkcs8 private pubkey rsa x509 x509ca x509aa x509ac x509crl x509ocsp
  cd ..
done
