# pq-strongswan

Build and run a [strongSwan][STRONGSWAN] 6.0beta Post-Quantum IKEv2 Daemon in a Docker image. The current prototype implementation is based on the two following IETF documents:

* [RFC 9242][IKEV2_INTERMEDIATE]: Intermediate Exchange in the IKEv2 Protocol
* [RFC 9370][IKEV2_MULTIPLE_KE]: Multiple Key Exchanges in IKEv2

[STRONGSWAN]:         https://www.strongswan.org
[IKEV2_MULTIPLE_KE]:  https://tools.ietf.org/html/rfc9370
[IKEV2_INTERMEDIATE]: https://tools.ietf.org/html/rfc9242

## Table of Contents

 1. [Docker Setup](#section1)
 2. [strongSwan Configuration](#section2)
 3. [Start up the IKEv2 Daemons](#section3)
 4. [Establish the IKE SA and first Child SA](#section4)
 5. [Establish a second CHILD SA](#section5)
 6. [Use the IPsec Tunnels](#section6)
 7. [Rekeying of first CHILD SA](#section7)
 8. [Rekeying of second CHILD SA](#section9)
 9. [Rekeying of IKE SA](#section8)
10. [SA Status after Rekeying](#section10)

## Docker Setup <a name="section1"></a>

### Pull Docker Image

```
$ docker pull strongx509/pq-strongswan
```

### Build Docker Image

Alternatively the docker image can be built from scratch in the `pq-strongswan` directory with
```console
$ docker build -t strongx509/pq-strongswan .
```
The build rules are defined in [Dockerfile](Dockerfile).

### Create Docker Containers and Local Networks

We clone the strongSwan `docker-compose` environment which automatically installs the `strongx509/pq-strongswan` docker image and brings the `moon` and `carol` docker containers up:
```console
$ git clone https://github.com/strongX509/docker.git
$ cd docker/pq-strongswan
$ sh scripts/gen_dirs.sh
$ docker-compose up
Creating moon ... done
Creating carol ... done
Attaching to moon, carol
```
The network topology that has been created looks as follows:
```
               +-------+                        +--------+
  10.3.0.1 --- | carol | === 192.168.0.0/24 === |  moon  | --- 10.1.0.0/16
 Virtual IP    +-------+ .3     Internet     .2 +--------+ .2    Intranet
```
VPN client `carol` and VPN gateway `moon` are connected with each other via the `192.168.0.0/24` network emulating the `Internet`. Behind `moon` there is an additional `10.1.0.0/16` network acting as an `Intranet`. Within the IPsec tunnel `carol` is going to use the virtual IP address `10.3.0.1`  that will be assigned to the client  by the gateway via the IKEv2 protocol.

## strongSwan Configuration <a name="section2"></a>

strongSwan options can be configured in the `/etc/strongswan.conf` file which in our case contains the startup scripts and a logging directive diverting the debug output to `stderr`. We also define the size of the IP fragments and the maximum IKEv2 packet size which can be quite considerable with some post-quantum Key Exchange Methods.
```console
charon {
   start-scripts {
      creds = swanctl --load-creds
      conns = swanctl --load-conns
      pools = swanctl --load-pools
   }
   filelog {
      stderr {
         default = 1
      }
   }
   send_vendor_id = yes
   prefer_configured_proposals = no
   fragment_size = 1480
   max_packet = 30000
}
```

### NIST Selected KEM Algorithms 2022

| Keyword  | Key Exchange Method | Keyword  | Key Exchange Method | Keyword  | Key Exchange Method |
| :------- | :------------------ | :------- | :------------------ | :------- | :------------------ |
| `kyber1` | `KYBER_L1`          | `kyber3` | `KYBER_L3`          | `kyber5` | `KYBER_L5`          |


### BSI Recommended KEM Algorithms

| Keyword  | Key Exchange Method | Keyword  | Key Exchange Method | Keyword  | Key Exchange Method |
| :------- | :------------------ | :------- | :------------------ | :--------| :------------------ |
| `frodoa1`| `FRODO_AES_L1`      | `frodoa3`| `FRODO_AES_L3`      | `frodoa5`| `FRODO_AES_L5`      |
| `frodos1`| `FRODO_SHAKE_L1`    | `frodos3`| `FRODO_SHAKE_L3`    | `frodos5`| `FRODO_SHAKE_L5`    |

### NIST Round 4 Submission KEM Algorithms

| Keyword  | Key Exchange Method | Keyword  | Key Exchange Method | Keyword  | Key Exchange Method |
| :------- | :------------------ | :------- | :------------------ | :--------| :------------------ |
| `bike1`  | `BIKE_L1`           | `bike3`  | `BIKE_L3`           | `bike5`  | `BIKE_L5`           |
| `hqc1`   | `HQC_L1`            | `hqc3`   | `HQC_L3`            | `hqc5`   | `HQC_L5`            |

The KEM algorithms listed above are implemented by the strongSwan `oqs` plugin which in turn uses the  [liboqs][LIBOQS]  Open Quantum-Safe library. There is also a `frodo` plugin which implements the `FrodoKEM` algorithm with strongSwan crypto primitives. There is currently no support for the `Classic McEliece` , although being a NIST round 4 KEM submission candidate, is not an option for IKE due to the huge public key size of more than 100 kB.

### NIST Selected Signature Algorithms 2022

| Keyword     | Signature Key Type | Keyword     | Signature Key Type | Keyword     | Signature Key Type |
| :---------- | :----------------- | :---------- | :----------------- | :---------- | :----------------- |
| `dilithium2`| `KEY_DILITHIUM_2`  | `dilithium3`| `KEY_DILITHIUM_3`  | `dilithium5`| `KEY_DILITHIUM_5`  |
| `falcon512` | `KEY_FALCON_512`   |             |                    | `falcon1024`| `KEY_FALCON_1024`  |

Currently the lattice-based `Crystals-Dilithium` and `Falcon`  NIST Selected Signature Algorithms 2022 are supported by the strongSwan `oqs` plugin. We explicitly add the `oqs` plugin to the `load` list of the `pki` tool in `strongswan.conf` so that the post-quantum signature algorithms are loaded.
```console
pki {
   load = plugins: random drbg x509 pubkey pkcs1 pkcs8 pkcs12 pem openssl oqs
}
```

[LIBOQS]: https://github.com/open-quantum-safe/liboqs

### VPN Client Configuration

This is the `swanctl.conf`  connection  configuration file of the client `carol`
```console
connections {
   home {
      remote_addrs = 192.168.0.2
      vips = 0.0.0.0
   
      local {
         auth = pubkey
         certs = carolCert.pem
         id = carol@strongswan.org
      }
      remote {
         auth = pubkey
         id = moon.strongswan.org
      }
      children {
         net {
            remote_ts = 10.1.0.0/16
            esp_proposals = aes256-sha256-x25519-ke1_kyber3-ke2_bike3-ke3_hqc3
            rekey_time = 20m
          }
         host {
            esp_proposals = aes256-sha256-modp3072-ke1_frodoa3-ke2_bike3
            rekey_time = 20m
         }
      }
      version = 2
      proposals = aes256-sha256-x25519-ke1_kyber3-ke2_bike3-ke3_hqc3
      rekey_time = 30m
   }
}
```
Two child security associations are defined:
* The `net` `CHILD_SA`  connecting the client with the subnet`10.1.0.0/16` behind the gateway
* The `host` `CHILD_SA` connecting the client with the outer IP address of the gateway itself.

Due to  the `rekey` parameter the `CHILD_SAs` will be periodically rekeyed every `20` minutes (`1200` seconds ) whereas the `IKE_SA` will be rekeyed every `30` minutes (`1800` seconds) in order to demonstrate the post-quantum multi-key rekeying process. The default rekeying values are `1` hour (`3600` seconds) and `4` hours (`14400` seconds), respectively.

### VPN Gateway Configuration

This is the `swanctl.conf`  connection  configuration file of the gateway `moon`
```console
connections {
   rw {
      pools = rw_pool

      local {
         auth = pubkey
         certs = moonCert.pem
         id = moon.strongswan.org
      }
      remote {
         auth = pubkey
         cacerts = caCert.pem
      }
      children {
         net {
            local_ts = 10.1.0.0/24

            esp_proposals = aes256-sha256-x25519-ke1_kyber3-ke2_bike3-ke3_hqc3-ke3_none-ke4_hqc5-ke4_none
         }
         host {
            esp_proposals = aes256-sha256-modp3072-ke1_frodoa3-ke2_bike3
         }
      }
      version = 2
      proposals = aes256-sha256-x25519-modp3072-ke1_kyber3-ke1_frodoa3-ke2_bike3-ke2_hqc3-ke3_hqc3-ke3_none-ke4_hqc5-ke4_none
   }
}

pools {

   rw_pool {
      addrs = 10.3.0.0/24
   }
}
```

## Start up the IKEv2 Daemons <a name="section3"></a>

### On VPN Gateway "moon"

In an additional console window we open a `bash` shell to start and manage the strongSwan `charon` daemon in the `moon` container
```console
moon$ docker exec -ti moon /bin/bash
moon# ./charon &
00[DMN] Starting IKE charon daemon (strongSwan 6.0.0beta4, Linux 6.2.0-26-generic, x86_64)
00[LIB] providers loaded by OpenSSL: legacy default
00[CFG] install DNS servers in '/etc/resolv.conf'
00[LIB] loaded plugins: charon random nonce x509 revocation constraints pubkey pkcs1 pkcs7 pgp dnskey sshkey pem openssl pkcs8 xcbc cmac kdf frodo oqs drbg attr kernel-netlink resolve socket-default vici updown
00[JOB] spawning 16 worker threads
00[DMN] executing start script 'creds' (swanctl --load-creds)
08[CFG] loaded certificate 'C=CH, O=Cyber, CN=moon.strongswan.org'
11[CFG] loaded certificate 'C=CH, O=Cyber, CN=Cyber Root CA'
01[CFG] loaded Dilithium5 private key
00[DMN] creds: loaded certificate from '/etc/swanctl/x509/moonCert.pem'
00[DMN] creds: loaded certificate from '/etc/swanctl/x509ca/caCert.pem'
00[DMN] creds: loaded Dilithium5 key from '/etc/swanctl/pkcs8/moonKey.pem'
00[DMN] executing start script 'conns' (swanctl --load-conns)
06[CFG] added vici connection: rw
00[DMN] conns: loaded connection 'rw'
00[DMN] conns: successfully loaded 1 connections, 0 unloaded
00[DMN] executing start script 'pools' (swanctl --load-pools)
15[CFG] added vici pool rw_pool: 10.3.0.0, 254 entries
00[DMN] pools: loaded pool 'rw_pool'
00[DMN] pools: successfully loaded 1 pools, 0 unloaded
```
The connection definition loaded via the VICI interface to gateway `moon` can be viewed with the command
```console
moon# swanctl --list-conns
rw: IKEv2, no reauthentication, rekeying every 14400s
  local:  %any
  remote: %any
  local public key authentication:
    id: moon.strongswan.org
    certs: C=CH, O=Cyber, CN=moon.strongswan.org
  remote public key authentication:
    cacerts: C=CH, O=Cyber, CN=Cyber Root CA
  net: TUNNEL, rekeying every 3600s
    local:  10.1.0.0/24
    remote: dynamic
  host: TUNNEL, rekeying every 3600s
    local:  dynamic
    remote: dynamic
```
and the loaded X.509 certificates based on post-quantum `Dilithium4` signature keys with the command
```console
moon# swanctl --list-certs
```
```console
List of X.509 End Entity Certificates

  subject:  "C=CH, O=Cyber, CN=moon.strongswan.org"
  issuer:   "C=CH, O=Cyber, CN=Cyber Root CA"
  validity:  not before Aug 29 10:33:30 2023, ok
             not after  Aug 29 10:33:30 2027, ok (expires in 1460 days)
  serial:    62:cf:a6:81:ef:f1:97:08
  altNames:  moon.strongswan.org
  flags:     
  authkeyId: a7:9c:ed:6f:79:27:b0:85:1f:e3:e3:a3:ea:41:e7:15:24:45:80:ea
  subjkeyId: 0f:87:d3:ba:b7:e4:36:38:61:e1:c0:9f:8e:5e:e2:db:8d:24:da:70
  pubkey:    Dilithium5 20736 bits, has private key
  keyid:     0a:3d:09:23:52:53:14:c5:da:3a:5a:a0:2f:29:76:68:c8:cf:75:d1
  subjkey:   0f:87:d3:ba:b7:e4:36:38:61:e1:c0:9f:8e:5e:e2:db:8d:24:da:70

List of X.509 CA Certificates

  subject:  "C=CH, O=Cyber, CN=Cyber Root CA"
  issuer:   "C=CH, O=Cyber, CN=Cyber Root CA"
  validity:  not before Aug 29 10:33:30 2023, ok
             not after  Aug 28 10:33:30 2033, ok (expires in 3651 days)
  serial:    4d:1c:d2:20:0f:52:67:73
  flags:     CA CRLSign self-signed 
  subjkeyId: a7:9c:ed:6f:79:27:b0:85:1f:e3:e3:a3:ea:41:e7:15:24:45:80:ea
  pubkey:    Falcon1024 14344 bits
  keyid:     bb:2a:5f:ed:88:f8:16:c2:5f:59:c0:f1:0d:1f:24:97:23:7a:3a:9d
  subjkey:   a7:9c:ed:6f:79:27:b0:85:1f:e3:e3:a3:ea:41:e7:15:24:45:80:ea
```

### On VPN Client "carol"

In a third console window we open a `bash`shell to start and manage the strongSwan `charon` daemon in the `carol` container
```console
carol$ docker exec -ti carol /bin/bash
carol# ./charon &
00[DMN] Starting IKE charon daemon (strongSwan 6.0.0beta4, Linux 6.2.0-26-generic, x86_64)
00[LIB] providers loaded by OpenSSL: legacy default
00[CFG] install DNS servers in '/etc/resolv.conf'
00[LIB] loaded plugins: charon random nonce x509 revocation constraints pubkey pkcs1 pkcs7 pgp dnskey sshkey pem openssl pkcs8 xcbc cmac kdf frodo oqs drbg attr kernel-netlink resolve socket-default vici updown
00[JOB] spawning 16 worker threads
00[DMN] executing start script 'creds' (swanctl --load-creds)
06[CFG] loaded certificate 'C=CH, O=Cyber, CN=carol@strongswan.org'
11[CFG] loaded certificate 'C=CH, O=Cyber, CN=Cyber Root CA'
15[CFG] loaded Dilithium5 private key
00[DMN] creds: loaded certificate from '/etc/swanctl/x509/carolCert.pem'
00[DMN] creds: loaded certificate from '/etc/swanctl/x509ca/caCert.pem'
00[DMN] creds: loaded Dilithium5 key from '/etc/swanctl/pkcs8/carolKey.pem'
00[DMN] executing start script 'conns' (swanctl --load-conns)
14[CFG] added vici connection: home
00[DMN] conns: loaded connection 'home'
00[DMN] conns: successfully loaded 1 connections, 0 unloaded
00[DMN] executing start script 'pools' (swanctl --load-pools)
00[DMN] pools: no pools found, 0 unloaded
```
We also list the connection definition on `carol`
```console
carol# swanctl --list-conns
home: IKEv2, no reauthentication, rekeying every 1800s
  local:  %any
  remote: 192.168.0.2
  local public key authentication:
    id: carol@strongswan.org
    certs: C=CH, O=Cyber, CN=carol@strongswan.org
  remote public key authentication:
    id: moon.strongswan.org
  net: TUNNEL, rekeying every 1200s
    local:  dynamic
    remote: 10.1.0.0/16
  host: TUNNEL, rekeying every 1200s
    local:  dynamic
    remote: dynamic
```
and the loaded X.509 certificates based on post-quantum `Dilithium4` signature keys
```console
carol# swanctl --list-certs
```
```console
  subject:  "C=CH, O=Cyber, CN=carol@strongswan.org"
  issuer:   "C=CH, O=Cyber, CN=Cyber Root CA"
  validity:  not before Aug 29 10:33:30 2023, ok
             not after  Aug 29 10:33:30 2027, ok (expires in 1460 days)
  serial:    64:a9:3e:7b:1f:0d:9c:ec
  altNames:  carol@strongswan.org
  flags:     
  authkeyId: a7:9c:ed:6f:79:27:b0:85:1f:e3:e3:a3:ea:41:e7:15:24:45:80:ea
  subjkeyId: 0a:ca:7a:bf:74:9b:ed:2c:ee:82:90:78:93:16:db:e5:e6:13:48:5c
  pubkey:    Dilithium5 20736 bits, has private key
  keyid:     88:4d:87:3d:30:af:5b:bb:7c:50:21:8a:fd:04:fd:7b:e8:05:14:ec
  subjkey:   0a:ca:7a:bf:74:9b:ed:2c:ee:82:90:78:93:16:db:e5:e6:13:48:5c

List of X.509 CA Certificates

  subject:  "C=CH, O=Cyber, CN=Cyber Root CA"
  issuer:   "C=CH, O=Cyber, CN=Cyber Root CA"
  validity:  not before Aug 29 10:33:30 2023, ok
             not after  Aug 28 10:33:30 2033, ok (expires in 3651 days)
  serial:    4d:1c:d2:20:0f:52:67:73
  flags:     CA CRLSign self-signed 
  subjkeyId: a7:9c:ed:6f:79:27:b0:85:1f:e3:e3:a3:ea:41:e7:15:24:45:80:ea
  pubkey:    Falcon1024 14344 bits
  keyid:     bb:2a:5f:ed:88:f8:16:c2:5f:59:c0:f1:0d:1f:24:97:23:7a:3a:9d
  subjkey:   a7:9c:ed:6f:79:27:b0:85:1f:e3:e3:a3:ea:41:e7:15:24:45:80:ea
```
We can also list all supported legacy as well as post-quantum key exchange algorithms
```console
carol# swanctl --list-algs
```
```console
ke:
  MODP_3072[openssl]
  MODP_4096[openssl]
  MODP_6144[openssl]
  MODP_8192[openssl]
  MODP_2048[openssl]
  MODP_2048_224[openssl]
  MODP_2048_256[openssl]
  MODP_1536[openssl]
  MODP_1024[openssl]
  MODP_1024_160[openssl]
  MODP_768[openssl]
  MODP_CUSTOM[openssl]
  ECP_256[openssl]
  ECP_384[openssl]
  ECP_521[openssl]
  ECP_224[openssl]
  ECP_192[openssl]
  ECP_256_BP[openssl]
  ECP_384_BP[openssl]
  ECP_512_BP[openssl]
  ECP_224_BP[openssl]
  CURVE_25519[openssl]
  CURVE_448[openssl]
  FRODO_SHAKE_L1[frodo]
  FRODO_SHAKE_L3[frodo]
  FRODO_SHAKE_L5[frodo]
  FRODO_AES_L1[frodo]
  FRODO_AES_L3[frodo]
  FRODO_AES_L5[frodo]
  KYBER_L1[oqs]
  KYBER_L3[oqs]
  KYBER_L5[oqs]
  BIKE_L1[oqs]
  BIKE_L3[oqs]
  BIKE_L5[oqs]
  HQC_L1[oqs]
  HQC_L3[oqs]
  HQC_L5[oqs]
```

## Establish the IKE SA and first Child SA <a name="section4"></a>

Since in the docker container  the `charon` daemon has been started on the command line and put in the background, we suppress the duplicate output of the `swanctl --initiate` command. Normally `charon` is started as a `systemd` service and writes to `syslog`.
```console
carol# swanctl --initiate --child net > /dev/null
12[CFG] vici initiate CHILD_SA 'net'
13[IKE] initiating IKE_SA home[1] to 192.168.0.2
13[ENC] generating IKE_SA_INIT request 0 [ SA KE No N(NATD_S_IP) N(NATD_D_IP) N(FRAG_SUP) N(HASH_ALG) N(REDIR_SUP) N(IKE_INT_SUP) V ]
13[NET] sending packet: from 192.168.0.3[500] to 192.168.0.2[500] (292 bytes)
```
We see that client `carol` sends the `IKEV2_FRAGMENTATION_SUPPORTED` (`FRAG_SUP`) and `INTERMEDIATE_EXCHANGE_SUPPORTED` (`IKE_INT_SUP`) notifications in the `IKE_SA_INIT` request, for the two mechanisms required to enable a post-quantum key exchange.

Also a traditional `KEY_EXCHANGE` (`KE`) payload is sent which contains the public factor of the legacy `X25519` elliptic curve Diffie-Hellman group.
```console
06[NET] received packet: from 192.168.0.2[500] to 192.168.0.3[500] (325 bytes)
06[ENC] parsed IKE_SA_INIT response 0 [ SA KE No N(NATD_S_IP) N(NATD_D_IP) CERTREQ N(FRAG_SUP) N(HASH_ALG) N(CHDLESS_SUP) N(IKE_INT_SUP) N(MULT_AUTH) V ]
```
Gateway `moon` supports the same mechanisms so that a post-quantum key exchange should succeed and its `KE` payload in turn allows to form a first `SKEYSEED` master secret that is used  to derive IKEv2 encryption and data integrity session keys so that the subsequent `IKE_INTERMEDIATE` messages in a secure way.
```console
06[IKE] received strongSwan vendor ID
06[CFG] selected proposal: IKE:AES_CBC_256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/CURVE_25519/KE1_KYBER_L3/KE2_BIKE_L3/KE3_HQC_L3
06[IKE] received cert request for "C=CH, O=Cyber, CN=Cyber Root CA"
```
The negotiated *hybrid* key exchange will use Dan Bernstein's `X25519` elliptic curve for the initial exchange, followed by three rounds of post-quantum key exchanges consisting of the `Kyber`, `BIKE` and `HQC` algorithms, all of them on NIST security level 3. 
```console
06[ENC] generating IKE_INTERMEDIATE request 1 [ KE ]
06[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1264 bytes)
05[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1168 bytes)
05[ENC] parsed IKE_INTERMEDIATE response 1 [ KE ]
```
The `Kyber` key exchange has been completed and the derived secret has been added to the `SKEYSEED` master secret.
```console
05[ENC] generating IKE_INTERMEDIATE request 2 [ KE ]
05[ENC] splitting IKE message (3168 bytes) into 3 fragments
05[ENC] generating IKE_INTERMEDIATE request 2 [ EF(1/3) ]
05[ENC] generating IKE_INTERMEDIATE request 2 [ EF(2/3) ]
05[ENC] generating IKE_INTERMEDIATE request 2 [ EF(3/3) ]
05[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
05[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
05[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (420 bytes)
08[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
08[ENC] parsed IKE_INTERMEDIATE response 2 [ EF(1/3) ]
08[ENC] received fragment #1 of 3, waiting for complete IKE message
06[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
06[ENC] parsed IKE_INTERMEDIATE response 2 [ EF(2/3) ]
06[ENC] received fragment #2 of 3, waiting for complete IKE message
11[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (452 bytes)
11[ENC] parsed IKE_INTERMEDIATE response 2 [ EF(3/3) ]
11[ENC] received fragment #3 of 3, reassembled fragmented IKE message (3200 bytes)
11[ENC] parsed IKE_INTERMEDIATE response 2 [ KE ]
```
The `BIKE` key exchange has been completed and the derived secret has been added to the `SKEYSEED` master secret.
```console
11[ENC] generating IKE_INTERMEDIATE request 3 [ KE ]
11[ENC] splitting IKE message (4608 bytes) into 4 fragments
11[ENC] generating IKE_INTERMEDIATE request 3 [ EF(1/4) ]
11[ENC] generating IKE_INTERMEDIATE request 3 [ EF(2/4) ]
11[ENC] generating IKE_INTERMEDIATE request 3 [ EF(3/4) ]
11[ENC] generating IKE_INTERMEDIATE request 3 [ EF(4/4) ]
11[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
11[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
11[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
11[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (484 bytes)
04[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
04[ENC] parsed IKE_INTERMEDIATE response 3 [ EF(1/7) ]
04[ENC] received fragment #1 of 7, waiting for complete IKE message
14[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
14[ENC] parsed IKE_INTERMEDIATE response 3 [ EF(2/7) ]
14[ENC] received fragment #2 of 7, waiting for complete IKE message
08[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
08[ENC] parsed IKE_INTERMEDIATE response 3 [ EF(3/7) ]
08[ENC] received fragment #3 of 7, waiting for complete IKE message
13[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
13[ENC] parsed IKE_INTERMEDIATE response 3 [ EF(4/7) ]
13[ENC] received fragment #4 of 7, waiting for complete IKE message
09[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
09[ENC] parsed IKE_INTERMEDIATE response 3 [ EF(5/7) ]
09[ENC] received fragment #5 of 7, waiting for complete IKE message
05[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
05[ENC] parsed IKE_INTERMEDIATE response 3 [ EF(6/7) ]
05[ENC] received fragment #6 of 7, waiting for complete IKE message
06[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (868 bytes)
06[ENC] parsed IKE_INTERMEDIATE response 3 [ EF(7/7) ]
06[ENC] received fragment #7 of 7, reassembled fragmented IKE message (9104 bytes)
06[ENC] parsed IKE_INTERMEDIATE response 3 [ KE ]
```
The `HQC` key exchange has been completed and the derived secret has been added to the `SKEYSEED` master secret.
```console
06[IKE] sending cert request for "C=CH, O=Cyber, CN=Cyber Root CA"
06[IKE] authentication of 'carol@strongswan.org' (myself) with DILITHIUM_5 successful
06[IKE] sending end entity cert "C=CH, O=Cyber, CN=carol@strongswan.org"
06[IKE] establishing CHILD_SA net{1}
06[ENC] generating IKE_AUTH request 4 [ IDi CERT N(INIT_CONTACT) CERTREQ IDr AUTH CPRQ(ADDR DNS) SA TSi TSr N(MOBIKE_SUP) N(NO_ADD_ADDR) N(MULT_AUTH) N(EAP_ONLY) N(MSG_ID_SYN_SUP) ]
06[ENC] splitting IKE message (9088 bytes) into 7 fragments
06[ENC] generating IKE_AUTH request 4 [ EF(1/7) ]
06[ENC] generating IKE_AUTH request 4 [ EF(2/7) ]
06[ENC] generating IKE_AUTH request 4 [ EF(3/7) ]
06[ENC] generating IKE_AUTH request 4 [ EF(4/7) ]
06[ENC] generating IKE_AUTH request 4 [ EF(5/7) ]
06[ENC] generating IKE_AUTH request 4 [ EF(6/7) ]
06[ENC] generating IKE_AUTH request 4 [ EF(7/7) ]
06[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
06[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
06[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
06[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
06[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
06[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
06[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (836 bytes)
```
The `IKE_AUTH` request containing a post-quantum `Dilithium5`  X.509  client certificate and a corresponding NIST security level 5 digital signature gets so large that it has to be split into 7 IKEv2 fragments.
```console
15[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
15[ENC] parsed IKE_AUTH response 4 [ EF(1/7) ]
15[ENC] received fragment #1 of 7, waiting for complete IKE message
05[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
05[ENC] parsed IKE_AUTH response 4 [ EF(2/7) ]
05[ENC] received fragment #2 of 7, waiting for complete IKE message
11[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
11[ENC] parsed IKE_AUTH response 4 [ EF(3/7) ]
11[ENC] received fragment #3 of 7, waiting for complete IKE message
09[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
09[ENC] parsed IKE_AUTH response 4 [ EF(4/7) ]
09[ENC] received fragment #4 of 7, waiting for complete IKE message
14[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
14[ENC] parsed IKE_AUTH response 4 [ EF(5/7) ]
14[ENC] received fragment #5 of 7, waiting for complete IKE message
08[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
08[ENC] parsed IKE_AUTH response 4 [ EF(6/7) ]
08[ENC] received fragment #6 of 7, waiting for complete IKE message
04[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (756 bytes)
04[ENC] parsed IKE_AUTH response 4 [ EF(7/7) ]
04[ENC] received fragment #7 of 7, reassembled fragmented IKE message (9008 bytes)
04[ENC] parsed IKE_AUTH response 4 [ IDr CERT AUTH CPRP(ADDR) SA TSi TSr N(MOBIKE_SUP) N(ADD_4_ADDR) ]
04[IKE] received end entity cert "C=CH, O=Cyber, CN=moon.strongswan.org"
04[CFG]   using certificate "C=CH, O=Cyber, CN=moon.strongswan.org"
04[CFG]   using trusted ca certificate "C=CH, O=Cyber, CN=Cyber Root CA"
04[CFG]   reached self-signed root ca with a path length of 0
04[CFG] checking certificate status of "C=CH, O=Cyber, CN=moon.strongswan.org"
04[CFG] certificate status is not available
04[IKE] authentication of 'moon.strongswan.org' with DILITHIUM_5 successful
```
IKEv2 fragmentation has also to be applied to the `IKE_AUTH` response containing a post-quantum `Dilithium5` X.509  gateway certificate and a corresponding NIST security level 5 digital signature as well. Both the client and gateway certificates are signed by a NIST security level 5 `Falcon1024` CA.
```console
04[IKE] installing new virtual IP 10.3.0.1
04[IKE] peer supports MOBIKE
04[IKE] IKE_SA home[1] established between 192.168.0.3[carol@strongswan.org]...192.168.0.2[moon.strongswan.org]
04[IKE] scheduling rekeying in 1695s
04[IKE] maximum IKE_SA lifetime 1875s
04[CFG] selected proposal: ESP:AES_CBC_256/HMAC_SHA2_256_128/NO_EXT_SEQ
04[IKE] CHILD_SA net{1} established with SPIs cd5c1aef_i cb0c1fd9_o and TS 10.3.0.1/32 === 10.1.0.0/24
```

## Establish a second CHILD SA <a name="section5"></a>

```console
carol# swanctl --initiate --child host > /dev/null
13[CFG] vici initiate CHILD_SA 'host'
09[IKE] establishing CHILD_SA host{2}
09[ENC] generating CREATE_CHILD_SA request 5 [ SA No KE TSi TSr ]
09[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (624 bytes)
12[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (624 bytes)
12[ENC] parsed CREATE_CHILD_SA response 5 [ SA No KE TSi TSr N(ADD_KE) ]
```
The `KE` payload in the `CREATE_CHILD_SA` message exchange transports the public factors of the `3072 bit` prime Diffie-Hellman group.
```console
12[CFG] selected proposal: ESP:AES_CBC_256/HMAC_SHA2_256_128/MODP_3072/NO_EXT_SEQ/KE1_FRODO_AES_L3/KE2_BIKE_L3
```
The negotiated *hybrid* key exchange will use the `3072 bit`prime Diffie-Hellman group for the initial exchange, followed by two rounds of post-quantum key exchanges consisting of the `FrodoKEM` and `BIKE` algorithms, both of them on NIST security level 3. 
```console
112[ENC] generating IKE_FOLLOWUP_KE request 6 [ KE N(ADD_KE) ]
12[ENC] splitting IKE message (15728 bytes) into 12 fragments
12[ENC] generating IKE_FOLLOWUP_KE request 6 [ EF(1/12) ]
12[ENC] generating IKE_FOLLOWUP_KE request 6 [ EF(2/12) ]
12[ENC] generating IKE_FOLLOWUP_KE request 6 [ EF(3/12) ]
12[ENC] generating IKE_FOLLOWUP_KE request 6 [ EF(4/12) ]
12[ENC] generating IKE_FOLLOWUP_KE request 6 [ EF(5/12) ]
12[ENC] generating IKE_FOLLOWUP_KE request 6 [ EF(6/12) ]
12[ENC] generating IKE_FOLLOWUP_KE request 6 [ EF(7/12) ]
12[ENC] generating IKE_FOLLOWUP_KE request 6 [ EF(8/12) ]
12[ENC] generating IKE_FOLLOWUP_KE request 6 [ EF(9/12) ]
12[ENC] generating IKE_FOLLOWUP_KE request 6 [ EF(10/12) ]
12[ENC] generating IKE_FOLLOWUP_KE request 6 [ EF(11/12) ]
12[ENC] generating IKE_FOLLOWUP_KE request 6 [ EF(12/12) ]
12[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
12[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
12[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
12[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
12[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
12[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
12[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
12[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
12[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
12[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
12[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
12[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (596 bytes)
```
The design of FrodoKEM is quite conservative so that the large public key sent by the initiator via the `IKE_FOLLOWUP_KE` message has to be split into 12 IKEv2 fragments.
```console
09[ENC] parsed IKE_FOLLOWUP_KE response 6 [ EF(1/12) ]
09[ENC] received fragment #1 of 12, waiting for complete IKE message
09[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (708 bytes)
09[ENC] parsed IKE_FOLLOWUP_KE response 6 [ EF(12/12) ]
09[ENC] received fragment #12 of 12, waiting for complete IKE message
07[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
07[ENC] parsed IKE_FOLLOWUP_KE response 6 [ EF(3/12) ]
07[ENC] received fragment #3 of 12, waiting for complete IKE message
10[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
10[ENC] parsed IKE_FOLLOWUP_KE response 6 [ EF(4/12) ]
10[ENC] received fragment #4 of 12, waiting for complete IKE message
11[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
11[ENC] parsed IKE_FOLLOWUP_KE response 6 [ EF(5/12) ]
11[ENC] received fragment #5 of 12, waiting for complete IKE message
05[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
05[ENC] parsed IKE_FOLLOWUP_KE response 6 [ EF(6/12) ]
05[ENC] received fragment #6 of 12, waiting for complete IKE message
04[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
04[ENC] parsed IKE_FOLLOWUP_KE response 6 [ EF(7/12) ]
04[ENC] received fragment #7 of 12, waiting for complete IKE message
14[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
14[ENC] parsed IKE_FOLLOWUP_KE response 6 [ EF(8/12) ]
14[ENC] received fragment #8 of 12, waiting for complete IKE message
08[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
08[ENC] parsed IKE_FOLLOWUP_KE response 6 [ EF(9/12) ]
08[ENC] received fragment #9 of 12, waiting for complete IKE message
12[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
12[ENC] parsed IKE_FOLLOWUP_KE response 6 [ EF(10/12) ]
12[ENC] received fragment #10 of 12, waiting for complete IKE message
06[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
06[ENC] parsed IKE_FOLLOWUP_KE response 6 [ EF(11/12) ]
06[ENC] received fragment #11 of 12, waiting for complete IKE message
15[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
15[ENC] parsed IKE_FOLLOWUP_KE response 6 [ EF(2/12) ]
15[ENC] received fragment #2 of 12, reassembled fragmented IKE message (15840 bytes)
15[ENC] parsed IKE_FOLLOWUP_KE response 6 [ KE N(ADD_KE) ]
```
The encrypted session secret sent by the responder has to be fragmented into 12 parts as well.  The `FrodoKEM` key exchange has been completed and the derived secret has been added to the `SKEYSEED` master secret.
```console
15[ENC] generating IKE_FOLLOWUP_KE request 7 [ KE N(ADD_KE) ]
15[ENC] splitting IKE message (3168 bytes) into 3 fragments
15[ENC] generating IKE_FOLLOWUP_KE request 7 [ EF(1/3) ]
15[ENC] generating IKE_FOLLOWUP_KE request 7 [ EF(2/3) ]
15[ENC] generating IKE_FOLLOWUP_KE request 7 [ EF(3/3) ]
15[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
15[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
15[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (420 bytes)
10[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
10[ENC] parsed IKE_FOLLOWUP_KE response 7 [ EF(1/3) ]
10[ENC] received fragment #1 of 3, waiting for complete IKE message
09[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
09[ENC] parsed IKE_FOLLOWUP_KE response 7 [ EF(2/3) ]
09[ENC] received fragment #2 of 3, waiting for complete IKE message
04[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (452 bytes)
04[ENC] parsed IKE_FOLLOWUP_KE response 7 [ EF(3/3) ]
04[ENC] received fragment #3 of 3, reassembled fragmented IKE message (3200 bytes)
04[ENC] parsed IKE_FOLLOWUP_KE response 7 [ KE ]
```
The `BIKE` public key and encrypted secret need three `IKE_FOLLOWUP_KE` fragments each. The `BIKE` key exchange has been completed and the derived secret has been added to the `SKEYSEED` master secret.
```console
04[IKE] CHILD_SA host{2} established with SPIs cced9093_i cde7a04b_o and TS 10.3.0.1/32 === 192.168.0.2/32
```

## Use the IPsec Tunnels <a name="section6"></a>

First we ping the network behind gateway `moon`
```console
carol# ping -c 2 10.1.0.2
PING 10.1.0.2 (10.1.0.2) 56(84) bytes of data.
64 bytes from 10.1.0.2: icmp_seq=1 ttl=64 time=0.108 ms
64 bytes from 10.1.0.2: icmp_seq=2 ttl=64 time=0.225 ms
```
and then the gateway `moon` on its external IP address itself
```console
carol# ping -c 1 192.168.0.2
PING 192.168.0.2 (192.168.0.2) 56(84) bytes of data.
64 bytes from 192.168.0.2: icmp_seq=1 ttl=64 time=0.293 ms
```
```console
carol# swanctl --list-sas
home: #1, ESTABLISHED, IKEv2, cb469ea1a7223567_i* 6010c9fd60119c5b_r
  local  'carol@strongswan.org' @ 192.168.0.3[4500] [10.3.0.1]
  remote 'moon.strongswan.org' @ 192.168.0.2[4500]
  AES_CBC-256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/CURVE_25519/KE1_KYBER_L3/KE2_BIKE_L3/KE3_HQC_L3
  established 298s ago, rekeying in 1397s
  net: #1, reqid 1, INSTALLED, TUNNEL, ESP:AES_CBC-256/HMAC_SHA2_256_128
    installed 298s ago, rekeying in 782s, expires in 1022s
    in  cd5c1aef,    168 bytes,     2 packets,    44s ago
    out cb0c1fd9,    168 bytes,     2 packets,    44s ago
    local  10.3.0.1/32
    remote 10.1.0.0/24
  host: #2, reqid 2, INSTALLED, TUNNEL, ESP:AES_CBC-256/HMAC_SHA2_256_128/MODP_3072/KE1_FRODO_AES_L3/KE2_BIKE_L3
    installed 270s ago, rekeying in 846s, expires in 1050s
    in  cced9093,     84 bytes,     1 packets,    25s ago
    out cde7a04b,     84 bytes,     1 packets,    25s ago
    local  10.3.0.1/32
    remote 192.168.0.2/32
```

## Rekeying of first CHILD SA <a name="section7"></a>

The rekeying of the first 'CHILD_SA' takes place automatically after the `rekey_time` interval of `20` minutes.
```console
14[KNL] creating rekey job for CHILD_SA ESP/0xcb0c1fd9/192.168.0.2
14[IKE] establishing CHILD_SA net{3} reqid 1
14[ENC] generating CREATE_CHILD_SA request 8 [ N(REKEY_SA) SA No KE TSi TSr ]
14[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (288 bytes)
12[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (288 bytes)
12[ENC] parsed CREATE_CHILD_SA response 8 [ SA No KE TSi TSr N(ADD_KE) ]
```
```console
12[CFG] selected proposal: ESP:AES_CBC_256/HMAC_SHA2_256_128/CURVE_25519/NO_EXT_SEQ/KE1_KYBER_L3/KE2_BIKE_L3/KE3_HQC_L3
```
```console
12[ENC] generating IKE_FOLLOWUP_KE request 9 [ KE N(ADD_KE) ]
12[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1280 bytes)
07[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1184 bytes)
07[ENC] parsed IKE_FOLLOWUP_KE response 9 [ KE N(ADD_KE) ]
```
```console
07[ENC] generating IKE_FOLLOWUP_KE request 10 [ KE N(ADD_KE) ]
07[ENC] splitting IKE message (3168 bytes) into 3 fragments
07[ENC] generating IKE_FOLLOWUP_KE request 10 [ EF(1/3) ]
07[ENC] generating IKE_FOLLOWUP_KE request 10 [ EF(2/3) ]
07[ENC] generating IKE_FOLLOWUP_KE request 10 [ EF(3/3) ]
07[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
07[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
07[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (420 bytes)
15[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
15[ENC] parsed IKE_FOLLOWUP_KE response 10 [ EF(1/3) ]
15[ENC] received fragment #1 of 3, waiting for complete IKE message
09[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
09[ENC] parsed IKE_FOLLOWUP_KE response 10 [ EF(2/3) ]
09[ENC] received fragment #2 of 3, waiting for complete IKE message
11[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (452 bytes)
11[ENC] parsed IKE_FOLLOWUP_KE response 10 [ EF(3/3) ]
11[ENC] received fragment #3 of 3, reassembled fragmented IKE message (3200 bytes)
11[ENC] parsed IKE_FOLLOWUP_KE response 10 [ KE N(ADD_KE) ]
```
```console
11[ENC] generating IKE_FOLLOWUP_KE request 11 [ KE N(ADD_KE) ]
11[ENC] splitting IKE message (4608 bytes) into 4 fragments
11[ENC] generating IKE_FOLLOWUP_KE request 11 [ EF(1/4) ]
11[ENC] generating IKE_FOLLOWUP_KE request 11 [ EF(2/4) ]
11[ENC] generating IKE_FOLLOWUP_KE request 11 [ EF(3/4) ]
11[ENC] generating IKE_FOLLOWUP_KE request 11 [ EF(4/4) ]
11[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
11[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
11[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
11[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (484 bytes)
08[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
08[ENC] parsed IKE_FOLLOWUP_KE response 11 [ EF(1/7) ]
08[ENC] received fragment #1 of 7, waiting for complete IKE message
05[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
05[ENC] parsed IKE_FOLLOWUP_KE response 11 [ EF(2/7) ]
05[ENC] received fragment #2 of 7, waiting for complete IKE message
04[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
04[ENC] parsed IKE_FOLLOWUP_KE response 11 [ EF(3/7) ]
04[ENC] received fragment #3 of 7, waiting for complete IKE message
06[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
06[ENC] parsed IKE_FOLLOWUP_KE response 11 [ EF(4/7) ]
06[ENC] received fragment #4 of 7, waiting for complete IKE message
14[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
14[ENC] parsed IKE_FOLLOWUP_KE response 11 [ EF(5/7) ]
14[ENC] received fragment #5 of 7, waiting for complete IKE message
13[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
13[ENC] parsed IKE_FOLLOWUP_KE response 11 [ EF(6/7) ]
13[ENC] received fragment #6 of 7, waiting for complete IKE message
10[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (868 bytes)
10[ENC] parsed IKE_FOLLOWUP_KE response 11 [ EF(7/7) ]
10[ENC] received fragment #7 of 7, reassembled fragmented IKE message (9104 bytes)
10[ENC] parsed IKE_FOLLOWUP_KE response 11 [ KE ]
```
```console
10[IKE] inbound CHILD_SA net{3} established with SPIs cd159185_i c5c4a85f_o and TS 10.3.0.1/32 === 10.1.0.0/24
10[IKE] outbound CHILD_SA net{3} established with SPIs cd159185_i c5c4a85f_o and TS 10.3.0.1/32 === 10.1.0.0/24
```
The new `CHILD_SA` has been established..
```console
10[IKE] rekeyed CHILD_SA net{1} with SPIs cd5c1aef_i cb0c1fd9_o with net{3} with SPIs cd159185_i c5c4a85f_o
10[IKE] closing CHILD_SA net{1} with SPIs cd5c1aef_i (168 bytes) cb0c1fd9_o (168 bytes) and TS 10.3.0.1/32 === 10.1.0.0/24
10[IKE] sending DELETE for ESP CHILD_SA with SPI cd5c1aef
10[ENC] generating INFORMATIONAL request 12 [ D ]
10[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (80 bytes)
12[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (80 bytes)
12[ENC] parsed INFORMATIONAL response 12 [ D ]
12[IKE] received DELETE for ESP CHILD_SA with SPI cb0c1fd9
12[IKE] delay closing of inbound CHILD_SA net{1} for 5s
05[IKE] CHILD_SA net{1} closed
```
The old `CHILD_SA` has been deleted.

## Rekeying of second CHILD SA <a name="section9"></a>

The rekeying of the second  'CHILD_SA' takes place automatically after the `rekey_time` interval of `20` minutes.
```console
04[KNL] creating rekey job for CHILD_SA ESP/0xcde7a04b/192.168.0.2
04[IKE] establishing CHILD_SA host{4} reqid 2
04[ENC] generating CREATE_CHILD_SA request 13 [ N(REKEY_SA) SA No KE TSi TSr ]
04[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (624 bytes)
14[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (624 bytes)
14[ENC] parsed CREATE_CHILD_SA response 13 [ SA No KE TSi TSr N(ADD_KE) ]
```
```console
14[CFG] selected proposal: ESP:AES_CBC_256/HMAC_SHA2_256_128/MODP_3072/NO_EXT_SEQ/KE1_FRODO_AES_L3/KE2_BIKE_L3
```
```console
14[ENC] generating IKE_FOLLOWUP_KE request 14 [ KE N(ADD_KE) ]
14[ENC] splitting IKE message (15728 bytes) into 12 fragments
14[ENC] generating IKE_FOLLOWUP_KE request 14 [ EF(1/12) ]
14[ENC] generating IKE_FOLLOWUP_KE request 14 [ EF(2/12) ]
14[ENC] generating IKE_FOLLOWUP_KE request 14 [ EF(3/12) ]
14[ENC] generating IKE_FOLLOWUP_KE request 14 [ EF(4/12) ]
14[ENC] generating IKE_FOLLOWUP_KE request 14 [ EF(5/12) ]
14[ENC] generating IKE_FOLLOWUP_KE request 14 [ EF(6/12) ]
14[ENC] generating IKE_FOLLOWUP_KE request 14 [ EF(7/12) ]
14[ENC] generating IKE_FOLLOWUP_KE request 14 [ EF(8/12) ]
14[ENC] generating IKE_FOLLOWUP_KE request 14 [ EF(9/12) ]
14[ENC] generating IKE_FOLLOWUP_KE request 14 [ EF(10/12) ]
14[ENC] generating IKE_FOLLOWUP_KE request 14 [ EF(11/12) ]
14[ENC] generating IKE_FOLLOWUP_KE request 14 [ EF(12/12) ]
14[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
14[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
14[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
14[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
14[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
14[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
14[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
14[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
14[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
14[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
14[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
14[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (596 bytes)
```
```console
13[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
13[ENC] parsed IKE_FOLLOWUP_KE response 14 [ EF(1/12) ]
13[ENC] received fragment #1 of 12, waiting for complete IKE message
10[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
10[ENC] parsed IKE_FOLLOWUP_KE response 14 [ EF(2/12) ]
10[ENC] received fragment #2 of 12, waiting for complete IKE message
12[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
12[ENC] parsed IKE_FOLLOWUP_KE response 14 [ EF(3/12) ]
12[ENC] received fragment #3 of 12, waiting for complete IKE message
07[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
07[ENC] parsed IKE_FOLLOWUP_KE response 14 [ EF(4/12) ]
07[ENC] received fragment #4 of 12, waiting for complete IKE message
15[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
15[ENC] parsed IKE_FOLLOWUP_KE response 14 [ EF(5/12) ]
15[ENC] received fragment #5 of 12, waiting for complete IKE message
09[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
09[ENC] parsed IKE_FOLLOWUP_KE response 14 [ EF(6/12) ]
09[ENC] received fragment #6 of 12, waiting for complete IKE message
08[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
08[ENC] parsed IKE_FOLLOWUP_KE response 14 [ EF(8/12) ]
08[ENC] received fragment #8 of 12, waiting for complete IKE message
11[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
11[ENC] parsed IKE_FOLLOWUP_KE response 14 [ EF(7/12) ]
11[ENC] received fragment #7 of 12, waiting for complete IKE message
06[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
06[ENC] parsed IKE_FOLLOWUP_KE response 14 [ EF(9/12) ]
06[ENC] received fragment #9 of 12, waiting for complete IKE message
04[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
04[ENC] parsed IKE_FOLLOWUP_KE response 14 [ EF(10/12) ]
04[ENC] received fragment #10 of 12, waiting for complete IKE message
14[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
14[ENC] parsed IKE_FOLLOWUP_KE response 14 [ EF(11/12) ]
14[ENC] received fragment #11 of 12, waiting for complete IKE message
05[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (708 bytes)
05[ENC] parsed IKE_FOLLOWUP_KE response 14 [ EF(12/12) ]
05[ENC] received fragment #12 of 12, reassembled fragmented IKE message (15840 bytes)
05[ENC] parsed IKE_FOLLOWUP_KE response 14 [ KE N(ADD_KE) ]
```
```console
05[ENC] generating IKE_FOLLOWUP_KE request 15 [ KE N(ADD_KE) ]
05[ENC] splitting IKE message (3168 bytes) into 3 fragments
05[ENC] generating IKE_FOLLOWUP_KE request 15 [ EF(1/3) ]
05[ENC] generating IKE_FOLLOWUP_KE request 15 [ EF(2/3) ]
05[ENC] generating IKE_FOLLOWUP_KE request 15 [ EF(3/3) ]
05[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
05[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
05[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (420 bytes)
13[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
13[ENC] parsed IKE_FOLLOWUP_KE response 15 [ EF(1/3) ]
13[ENC] received fragment #1 of 3, waiting for complete IKE message
12[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
12[ENC] parsed IKE_FOLLOWUP_KE response 15 [ EF(2/3) ]
12[ENC] received fragment #2 of 3, waiting for complete IKE message
10[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (452 bytes)
10[ENC] parsed IKE_FOLLOWUP_KE response 15 [ EF(3/3) ]
10[ENC] received fragment #3 of 3, reassembled fragmented IKE message (3200 bytes)
10[ENC] parsed IKE_FOLLOWUP_KE response 15 [ KE ]
```
```console
10[IKE] inbound CHILD_SA host{4} established with SPIs c4099340_i c234e9f5_o and TS 10.3.0.1/32 === 192.168.0.2/32
10[IKE] outbound CHILD_SA host{4} established with SPIs c4099340_i c234e9f5_o and TS 10.3.0.1/32 === 192.168.0.2/32
```
The new `CHILD_SA` has been  established..
```console
10[IKE] rekeyed CHILD_SA host{2} with SPIs cced9093_i cde7a04b_o with host{4} with SPIs c4099340_i c234e9f5_o
10[IKE] closing CHILD_SA host{2} with SPIs cced9093_i (84 bytes) cde7a04b_o (84 bytes) and TS 10.3.0.1/32 === 192.168.0.2/32
10[IKE] sending DELETE for ESP CHILD_SA with SPI cced9093
10[ENC] generating INFORMATIONAL request 16 [ D ]
10[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (80 bytes)
07[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (80 bytes)
07[ENC] parsed INFORMATIONAL response 16 [ D ]
07[IKE] received DELETE for ESP CHILD_SA with SPI cde7a04b
07[IKE] delay closing of inbound CHILD_SA host{2} for 5s
06[IKE] CHILD_SA host{2} closed
```
The old `CHILD_SA` has been deleted.

## Rekeying of IKE SA <a name="section8"></a>

The rekeying of the first 'IKE_SA' takes place automatically after the `rekey_time` interval of `30` minutes.
```console
14[IKE] initiating IKE_SA home[2] to 192.168.0.2
14[ENC] generating CREATE_CHILD_SA request 17 [ SA No KE ]
14[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (224 bytes)
04[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (240 bytes)
04[ENC] parsed CREATE_CHILD_SA response 17 [ SA No KE N(ADD_KE) ]
```
```console
04[CFG] selected proposal: IKE:AES_CBC_256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/CURVE_25519/KE1_KYBER_L3/KE2_BIKE_L3/KE3_HQC_L3
```
```console
04[ENC] generating IKE_FOLLOWUP_KE request 18 [ KE N(ADD_KE) ]
04[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1280 bytes)
13[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1184 bytes)
13[ENC] parsed IKE_FOLLOWUP_KE response 18 [ KE N(ADD_KE) ]
```
```console
13[ENC] generating IKE_FOLLOWUP_KE request 19 [ KE N(ADD_KE) ]
13[ENC] splitting IKE message (3168 bytes) into 3 fragments
13[ENC] generating IKE_FOLLOWUP_KE request 19 [ EF(1/3) ]
13[ENC] generating IKE_FOLLOWUP_KE request 19 [ EF(2/3) ]
13[ENC] generating IKE_FOLLOWUP_KE request 19 [ EF(3/3) ]
13[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
13[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
13[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (420 bytes)
05[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
05[ENC] parsed IKE_FOLLOWUP_KE response 19 [ EF(1/3) ]
05[ENC] received fragment #1 of 3, waiting for complete IKE message
12[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
12[ENC] parsed IKE_FOLLOWUP_KE response 19 [ EF(2/3) ]
12[ENC] received fragment #2 of 3, waiting for complete IKE message
10[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (452 bytes)
10[ENC] parsed IKE_FOLLOWUP_KE response 19 [ EF(3/3) ]
10[ENC] received fragment #3 of 3, reassembled fragmented IKE message (3200 bytes)
10[ENC] parsed IKE_FOLLOWUP_KE response 19 [ KE N(ADD_KE) ]
```
```console
10[ENC] generating IKE_FOLLOWUP_KE request 20 [ KE N(ADD_KE) ]
10[ENC] splitting IKE message (4608 bytes) into 4 fragments
10[ENC] generating IKE_FOLLOWUP_KE request 20 [ EF(1/4) ]
10[ENC] generating IKE_FOLLOWUP_KE request 20 [ EF(2/4) ]
10[ENC] generating IKE_FOLLOWUP_KE request 20 [ EF(3/4) ]
10[ENC] generating IKE_FOLLOWUP_KE request 20 [ EF(4/4) ]
10[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
10[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
10[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
10[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (484 bytes)
15[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
15[ENC] parsed IKE_FOLLOWUP_KE response 20 [ EF(1/7) ]
15[ENC] received fragment #1 of 7, waiting for complete IKE message
15[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (868 bytes)
15[ENC] parsed IKE_FOLLOWUP_KE response 20 [ EF(7/7) ]
15[ENC] received fragment #7 of 7, waiting for complete IKE message
07[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
07[ENC] parsed IKE_FOLLOWUP_KE response 20 [ EF(2/7) ]
07[ENC] received fragment #2 of 7, waiting for complete IKE message
08[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
08[ENC] parsed IKE_FOLLOWUP_KE response 20 [ EF(4/7) ]
08[ENC] received fragment #4 of 7, waiting for complete IKE message
11[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
11[ENC] parsed IKE_FOLLOWUP_KE response 20 [ EF(5/7) ]
11[ENC] received fragment #5 of 7, waiting for complete IKE message
06[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
06[ENC] parsed IKE_FOLLOWUP_KE response 20 [ EF(6/7) ]
06[ENC] received fragment #6 of 7, waiting for complete IKE message
09[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
09[ENC] parsed IKE_FOLLOWUP_KE response 20 [ EF(3/7) ]
09[ENC] received fragment #3 of 7, reassembled fragmented IKE message (9104 bytes)
09[ENC] parsed IKE_FOLLOWUP_KE response 20 [ KE ]
```
```console
09[IKE] scheduling rekeying in 1654s
09[IKE] maximum IKE_SA lifetime 1834s
09[IKE] IKE_SA home[2] rekeyed between 192.168.0.3[carol@strongswan.org]...192.168.0.2[moon.strongswan.org]
```
The new `IKE_SA` has been rekeyed.
```console
09[IKE] deleting IKE_SA home[1] between 192.168.0.3[carol@strongswan.org]...192.168.0.2[moon.strongswan.org]
09[IKE] sending DELETE for IKE_SA home[1]
09[ENC] generating INFORMATIONAL request 21 [ D ]
09[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (80 bytes)
04[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (80 bytes)
04[ENC] parsed INFORMATIONAL response 21 [ ]
04[IKE] IKE_SA deleted
```
The old `IKE_SA` has been deleted.

## SA Status after Rekeying <a name="section10"></a>

```console
carol# swanctl --list-sas
home: #2, ESTABLISHED, IKEv2, 586f3b137ae4cb77_i* 11c45664348c8922_r
  local  'carol@strongswan.org' @ 192.168.0.3[4500] [10.3.0.1]
  remote 'moon.strongswan.org' @ 192.168.0.2[4500]
  AES_CBC-256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/CURVE_25519/KE1_KYBER_L3/KE2_BIKE_L3/KE3_HQC_L3
  established 90s ago, rekeying in 1564s
  net: #3, reqid 1, INSTALLED, TUNNEL, ESP:AES_CBC-256/HMAC_SHA2_256_128/CURVE_25519/KE1_KYBER_L3/KE2_BIKE_L3/KE3_HQC_L3
    installed 705s ago, rekeying in 379s, expires in 615s
    in  cd159185,      0 bytes,     0 packets
    out c5c4a85f,      0 bytes,     0 packets
    local  10.3.0.1/32
    remote 10.1.0.0/24
  host: #4, reqid 2, INSTALLED, TUNNEL, ESP:AES_CBC-256/HMAC_SHA2_256_128/MODP_3072/KE1_FRODO_AES_L3/KE2_BIKE_L3
    installed 641s ago, rekeying in 446s, expires in 679s
    in  c4099340,      0 bytes,     0 packets
    out c234e9f5,      0 bytes,     0 packets
    local  10.3.0.1/32
    remote 192.168.0.2/32
```

Author:  [Andreas Steffen][AS] [CC BY 4.0][CC]

[AS]: mailto:andreas.steffen@strongsec.net
[CC]: http://creativecommons.org/licenses/by/4.0/

