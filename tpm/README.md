# tpm 

Build and run the [IBM TPM 2.0][IBM_TPM2] simulator as well as the [tpm2-tools][TPM2_TOOLS]. 

[IBM_TPM2]:   https://sourceforge.net/projects/ibmswtpm2/ 
[TPM2_TOOLS]: https://github.com/tpm2-software/tpm2-tools

## Pull Docker Image

```
$ docker pull strongx509/tpm
```

## Build Docker Image

Alternatively the docker image can be built from scratch in the `tpm` directory with
```console
$ docker build -t strongx509/tpm .
```
The build rules are defined in [Dockerfile](Dockerfile).

## Create Docker Container

```console
$ docker-compose up
Creating tpm-server ... done
Attaching to tpm-server

```
with the setup defined in [docker-compose.yml](docker-compose.yml).

In an additional console window we open a `bash` shell to start the IBM TPM 2.0 simulator in the `tpm-server` container
```console
$ docker exec -ti tpm-server /bin/bash
# /usr/bin/tpm_server &
LIBRARY_COMPATIBILITY_CHECK is ON
Manufacturing NV state...
Size of OBJECT = 2600
Size of components in TPMT_SENSITIVE = 1096
    TPMI_ALG_PUBLIC                 2
    TPM2B_AUTH                      66
    TPM2B_DIGEST                    66
    TPMU_SENSITIVE_COMPOSITE        962
Starting ACT thread...
TPM command server listening on port 2321
Platform server listening on port 2322
```
After `tpm_server` has started in the background, its internal state must be initialized
```console
# tpm2_startup -c 
Command IPv4 client accepted
Platform IPv4 client accepted
Platform server listening on port 2322
TPM command server listening on port 2321
```
List the SHA-256 PCR bank to check if the TPM is now working
```console
# tpm2_pcrlist -g sha256
sha256 :
  0  : 0000000000000000000000000000000000000000000000000000000000000000
  1  : 0000000000000000000000000000000000000000000000000000000000000000
  2  : 0000000000000000000000000000000000000000000000000000000000000000
  3  : 0000000000000000000000000000000000000000000000000000000000000000
  4  : 0000000000000000000000000000000000000000000000000000000000000000
  5  : 0000000000000000000000000000000000000000000000000000000000000000
  6  : 0000000000000000000000000000000000000000000000000000000000000000
  7  : 0000000000000000000000000000000000000000000000000000000000000000
  8  : 0000000000000000000000000000000000000000000000000000000000000000
  9  : 0000000000000000000000000000000000000000000000000000000000000000
  10 : 0000000000000000000000000000000000000000000000000000000000000000
  11 : 0000000000000000000000000000000000000000000000000000000000000000
  12 : 0000000000000000000000000000000000000000000000000000000000000000
  13 : 0000000000000000000000000000000000000000000000000000000000000000
  14 : 0000000000000000000000000000000000000000000000000000000000000000
  15 : 0000000000000000000000000000000000000000000000000000000000000000
  16 : 0000000000000000000000000000000000000000000000000000000000000000
  17 : ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
  18 : ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
  19 : ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
  20 : ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
  21 : ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
  22 : ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
  23 : 0000000000000000000000000000000000000000000000000000000000000000
```

Author:  [Andreas Steffen][AS] [CC BY 4.0][CC]

[AS]: mailto:andreas.steffen@strongsec.net
[CC]: http://creativecommons.org/licenses/by/4.0/

