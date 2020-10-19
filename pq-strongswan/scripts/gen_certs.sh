pki --gen --type ecdsa --size 384 --outform pem > caKey.pem

pki --self --type ecdsa --in caKey.pem --ca --lifetime 3652 \
    --dn "C=CH, O=Cyber, CN=Cyber Root CA"                  \
    --outform pem > caCert.pem

pki --gen --type ecdsa --size 384 --outform pem > moonKey.pem

pki --issue --cacert caCert.pem --cakey caKey.pem   \
    --type ecdsa --in moonKey.pem --lifetime 1461 \
    --dn "C=CH, O=Cyber, CN=moon.strongswan.org"    \
    --san moon.strongswan.org --outform pem > moonCert.pem

pki --gen --type ecdsa --size 384 --outform pem > carolKey.pem

pki --issue --cacert caCert.pem --cakey caKey.pem    \
     --type ecdsa --in carolKey.pem --lifetime 1461 \
     --dn "C=CH, O=Cyber, CN=carol@strongswan.org"  \
     --san carol@strongswan.org --outform pem > carolCert.pem
