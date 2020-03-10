pki --gen --type ecdsa --size 384 --outform pem > caKey.pem

pki --self --type ecdsa --in caKey.pem --ca --lifetime 3652 \
    --dn "C=CH, O=Cyber, CN=Cyber Root CA"                  \
    --outform pem > caCert.pem

pki --gen --type ecdsa --size 384 --outform pem > serverKey.pem

pki --issue --cacert caCert.pem --cakey caKey.pem   \
    --type ecdsa --in serverKey.pem --lifetime 1461 \
    --dn "C=CH, O=Cyber, CN=server.strongswan.org"  \
    --san server.strongswan.org --flag serverAuth   \
    --outform pem > serverCert.pem

pki --gen --type ecdsa --size 384 --outform pem > clientKey.pem

pki --issue --cacert caCert.pem --cakey caKey.pem    \
     --type ecdsa --in clientKey.pem --lifetime 1461 \
     --dn "C=CH, O=Cyber, CN=client.strongswan.org"  \
     --san client.strongswan.org --flag clientAuth   \
     --outform pem > clientCert.pem
