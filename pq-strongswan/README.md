# pq-strongswan

Build and run a [strongSwan][STRONGSWAN] 6.0dr Post-Quantum IKEv2 Daemon in a Docker image. The current prototype implementation is based on the two following IETF Internet Drafts:

* [draft-ietf-ipsecme-ikev2-multiple-ke][IKEV2_MULTIPLE_KE]: Multiple Key Exchanges in IKEv2
* [draft-ietf-ipsecme-ikev2-intermediate][IKEV2_INTERMEDIATE]: Intermediate Exchange in the IKEv2 Protocol

[STRONGSWAN]: https://www.strongswan.org
[IKEV2_MULTIPLE_KE]:https://tools.ietf.org/html/draft-ietf-ipsecme-ikev2-multiple-ke
[IKEV2_INTERMEDIATE]:https://tools.ietf.org/html/draft-ietf-ipsecme-ikev2-intermediate

## Table of Contents

 1. [Docker Setup](#section1)
 2. [strongSwan Configuration](#section2)
 3. [Start up the IKEv2 Daemons](#section3)
 4. [Establish the IKE SA and first Child SA](#section4)
 5. [Establish a second CHILD SA](#section5)
 6. [Use the IPsec Tunnels](#section6)
 7. [Rekeying of first CHILD SA](#section7)
 8. [Rekeying of IKE SA](#section8)
 9. [Rekeying of second CHILD SA](#section9)
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

### NIST Round 3 KEM Finalists

| Keyword  | Key Exchange Method | Keyword  | Key Exchange Method | Keyword  | Key Exchange Method |
| :------- | :------------------ | :------- | :------------------ | :------- | :------------------ |
| `kyber1` | `KYBER_L1`          | `kyber3` | `KYBER_L3`          | `kyber5` | `KYBER_L5`          |
| `ntrup1` | `NTRU_HPS_L1`       | `ntrup3` | `NTRU_HPS_L3`       | `ntrup5` | `NTRU_HPS_L5`       |
|          |                     | `ntrur3` | `NTRU_HRSS_L3`      |          |                     |
| `saber1` | `SABER_L1`          | `saber3` | `SABER_L3`          | `saber5` | `SABER_L5`          |


### NIST Alternate KEM Candidates

| Keyword  | Key Exchange Method | Keyword  | Key Exchange Method | Keyword  | Key Exchange Method |
| :------- | :------------------ | :------- | :------------------ | :--------| :------------------ |
| `bike1`  | `BIKE_L1`           | `bike3`  | `BIKE_L3`           |          |                     |
| `frodoa1`| `FRODO_AES_L1`      | `frodoa3`| `FRODO_AES_L3`      | `frodoa5`| `FRODO_AES_L5`      |
| `frodos1`| `FRODO_SHAKE_L1`    | `frodos3`| `FRODO_SHAKE_L3`    | `frodos5`| `FRODO_SHAKE_L5`    |
| `hqc1`   | `HQC_L1`            | `hqc3`   | `HQC_L3`            | `hqc5`   | `HQC_L5`            |
| `sike1`  | `SIKE_L1`           | `sike3`  | `SIKE_L3`           | `sike5`  | `SIKE_L5`           |
|          |                     | `sike2`  | `SIKE_L2`           |          |                     |

The KEM algorithms listed above are implemented by the strongSwan `oqs` plugin which in turn uses the  [liboqs][LIBOQS]  Open Quantum-Safe library. There is also a `frodo` plugin which implements the `FrodoKEM` algorithm with strongSwan crypto primitives. There is currently no support for the `BIKE` alternate KEM candidate. `Classic McEliece` , although being a NIST round 3 KEM finalist, is not an option for IKE due to the huge public key size of more than 100 kB.

### NIST Round 3 Signature Finalists

| Keyword     | Signature Key Type | Keyword     | Signature Key Type | Keyword     | Signature Key Type |
| :---------- | :----------------- | :---------- | :----------------- | :---------- | :----------------- |
| `dilithium2`| `KEY_DILITHIUM_2`  | `dilithium3`| `KEY_DILITHIUM_3`  | `dilithium5`| `KEY_DILITHIUM_5`  |
| `falcon512`| `KEY_FALCON_512`    |             |                    | `falcon1024`| `KEY_FALCON_1024`  |

Currently the lattice-based `Crystals-Dilithium` and `Falcon`  NIST Round 3 signature finalists are supported by the strongSwan `oqs` plugin. We explicitly add the `oqs` plugin to the `load` list of the `pki` tool in `strongswan.conf` so that the post-quantum signature algorithms are loaded.
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
            esp_proposals = aes256-sha256-x25519-ke1_kyber3-ke2_ntrup3-ke3_saber3
            rekey_time = 20m
          }
         host {
            esp_proposals = aes256-sha256-modp3072-ke1_frodoa3-ke2_sike3
            rekey_time = 20m
         }
      }
      version = 2
      proposals = aes256-sha256-x25519-ke1_kyber3-ke2_ntrup3-ke3_saber3
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

            esp_proposals = aes256-sha256-x25519-ke1_kyber3-ke2_ntrup3-ke3_saber3-ke3_none-ke4_hqc3-ke4_none
         }
         host {
            esp_proposals = aes256-sha256-modp3072-ke1_frodoa3-ke2_sike3
         }
      }
      version = 2
      proposals = aes256-sha256-x25519-modp3072-ke1_kyber3-ke1_frodoa3-ke2_ntrup3-ke2_sike3-ke3_saber3-ke3_none-ke4_hqc3-ke4_none
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
00[DMN] Starting IKE charon daemon (strongSwan 6.0dr9, Linux 5.11.0-27-generic, x86_64)
00[LIB] loaded plugins: charon random nonce x509 constraints pubkey pkcs1 pkcs8 pkcs12 pem openssl frodo oqs drbg kernel-netlink resolve socket-default vici updown
00[JOB] spawning 16 worker threads
00[DMN] executing start script 'creds' (swanctl --load-creds)
15[CFG] loaded certificate 'C=CH, O=Cyber, CN=moon.strongswan.org'
09[CFG] loaded certificate 'C=CH, O=Cyber, CN=Cyber Root CA'
11[CFG] loaded Dilithium5 private key
00[DMN] creds: loaded certificate from '/etc/swanctl/x509/moonCert.pem'
00[DMN] creds: loaded certificate from '/etc/swanctl/x509ca/caCert.pem'
00[DMN] creds: loaded Dilithium5 key from '/etc/swanctl/pkcs8/moonKey.pem'
00[DMN] executing start script 'conns' (swanctl --load-conns)
12[CFG] added vici connection: rw
00[DMN] conns: loaded connection 'rw'
00[DMN] conns: successfully loaded 1 connections, 0 unloaded
00[DMN] executing start script 'pools' (swanctl --load-pools)
11[CFG] added vici pool rw_pool: 10.3.0.0, 254 entries
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
  validity:  not before Mar 21 16:02:20 2021, ok
             not after  Mar 21 16:02:20 2025, ok (expires in 1460 days)
  serial:    06:da:98:7b:a8:04:0b:c9
  altNames:  moon.strongswan.org
  flags:     
  authkeyId: 96:ac:24:0d:60:b6:25:4e:6d:ec:77:e1:93:ad:1b:c0:14:7b:ed:dc
  subjkeyId: e6:e7:16:df:51:f8:67:ec:b9:0b:19:29:dd:c7:54:c7:68:0f:3b:62
  pubkey:    Dilithium5 20736 bits, has private key
  keyid:     01:4a:15:0d:ca:75:54:8a:7b:ef:96:4f:62:df:a2:06:f6:9d:43:2d
  subjkey:   e6:e7:16:df:51:f8:67:ec:b9:0b:19:29:dd:c7:54:c7:68:0f:3b:62
```
```console
List of X.509 CA Certificates
  subject:  "C=CH, O=Cyber, CN=Cyber Root CA"
  issuer:   "C=CH, O=Cyber, CN=Cyber Root CA"
  validity:  not before Nov 24 18:40:24 2020, ok
             not after  Nov 24 18:40:24 2030, ok (expires in 3651 days)
  serial:    2e:c2:a2:33:60:b3:b3:5b
  flags:     CA CRLSign self-signed 
  subjkeyId: 23:1d:1f:d3:c6:18:30:8d:9c:88:99:37:0d:98:41:73:b2:99:ec:c5
  pubkey:    Falcon1024 14344 bits
  keyid:     ca:87:0b:6f:05:52:4b:cd:e0:79:a4:1a:5a:33:6f:aa:92:55:eb:47
  subjkey:   23:1d:1f:d3:c6:18:30:8d:9c:88:99:37:0d:98:41:73:b2:99:ec:c5
```

### On VPN Client "carol"

In a third console window we open a `bash`shell to start and manage the strongSwan `charon` daemon in the `carol` container
```console
carol$ docker exec -ti carol /bin/bash
carol# ./charon &
00[DMN] Starting IKE charon daemon (strongSwan 6.0dr9, Linux 5.11.0-27-generic, x86_64)
00[LIB] loaded plugins: charon random nonce x509 constraints pubkey pkcs1 pkcs8 pkcs12 pem openssl frodo oqs drbg kernel-netlink resolve socket-default vici updown
00[JOB] spawning 16 worker threads
00[DMN] executing start script 'creds' (swanctl --load-creds)
01[CFG] loaded certificate 'C=CH, O=Cyber, CN=carol@strongswan.org'
08[CFG] loaded certificate 'C=CH, O=Cyber, CN=Cyber Root CA'
11[CFG] loaded Dilithium5 private key
00[DMN] creds: loaded certificate from '/etc/swanctl/x509/carolCert.pem'
00[DMN] creds: loaded certificate from '/etc/swanctl/x509ca/caCert.pem'
00[DMN] creds: loaded Dilithium5 key from '/etc/swanctl/pkcs8/carolKey.pem'
00[DMN] executing start script 'conns' (swanctl --load-conns)
14[CFG] added vici connection: home
00[DMN] conns: loaded connection 'home'
00[DMN] conns: successfully loaded 1 connections, 0 unloaded
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
List of X.509 End Entity Certificates
  subject:  "C=CH, O=Cyber, CN=carol@strongswan.org"
  issuer:   "C=CH, O=Cyber, CN=Cyber Root CA"
  validity:  not before Mar 21 16:02:20 2021, ok
             not after  Mar 21 16:02:20 2025, ok (expires in 1460 days)
  serial:    02:6d:ca:f8:89:a3:57:90
  altNames:  carol@strongswan.org
  flags:     
  authkeyId: 96:ac:24:0d:60:b6:25:4e:6d:ec:77:e1:93:ad:1b:c0:14:7b:ed:dc
  subjkeyId: 99:fd:48:1d:09:c4:92:fe:eb:40:f4:39:c2:76:09:96:5b:85:3c:db
  pubkey:    Dilithium5 20736 bits, has private key
  keyid:     d1:c8:2c:fa:48:8f:0f:95:8d:3d:6e:b6:56:4a:dd:ad:4d:d0:c5:b2
  subjkey:   99:fd:48:1d:09:c4:92:fe:eb:40:f4:39:c2:76:09:96:5b:85:3c:db
```
```console
List of X.509 CA Certificates
  subject:  "C=CH, O=Cyber, CN=Cyber Root CA"
  issuer:   "C=CH, O=Cyber, CN=Cyber Root CA"
  validity:  not before Mar 21 16:02:20 2021, ok
             not after  Mar 21 16:02:20 2031, ok (expires in 3651 days)
  serial:    4c:47:36:2d:a5:73:1b:a4
  flags:     CA CRLSign self-signed 
  subjkeyId: 96:ac:24:0d:60:b6:25:4e:6d:ec:77:e1:93:ad:1b:c0:14:7b:ed:dc
  pubkey:    Falcon1024 14344 bits
  keyid:     88:3b:e2:11:bc:3a:af:38:07:c7:a6:cf:fe:35:ab:fd:2b:90:75:e5
  subjkey:   96:ac:24:0d:60:b6:25:4e:6d:ec:77:e1:93:ad:1b:c0:14:7b:ed:dc
```
We can also list all supported legacy as well as post-quantum key exchange algorithms
```console
carol# swanctl --list-algs
```
```console
ke:
  ECP_256[openssl]
  ECP_384[openssl]
  ECP_521[openssl]
  ECP_224[openssl]
  ECP_192[openssl]
  ECP_256_BP[openssl]
  ECP_384_BP[openssl]
  ECP_512_BP[openssl]
  ECP_224_BP[openssl]
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
  NTRU_HPS_L1[oqs]
  NTRU_HPS_L3[oqs]
  NTRU_HPS_L5[oqs]
  NTRU_HRSS_L3[oqs]
  SABER_L1[oqs]
  SABER_L3[oqs]
  SABER_L5[oqs]
  BIKE_L1[oqs]
  BIKE_L3[oqs]
  HQC_L1[oqs]
  HQC_L3[oqs]
  HQC_L5[oqs]
  SIKE_L1[oqs]
  SIKE_L2[oqs]
  SIKE_L3[oqs]
  SIKE_L5[oqs]
```

## Establish the IKE SA and first Child SA <a name="section4"></a>

Since in the docker container  the `charon` daemon has been started on the command line and put in the background, we suppress the duplicate output of the `swanctl --initiate` command. Normally `charon` is started as a `systemd` service and writes to `syslog`.
```console
carol# swanctl --initiate --child net > /dev/null
08[CFG] vici initiate CHILD_SA 'net'
05[IKE] initiating IKE_SA home[1] to 192.168.0.2
05[ENC] generating IKE_SA_INIT request 0 [ SA KE No N(NATD_S_IP) N(NATD_D_IP) N(FRAG_SUP) N(HASH_ALG) N(REDIR_SUP) N(IKE_INT_SUP) V ]
05[NET] sending packet: from 192.168.0.3[500] to 192.168.0.2[500] (292 bytes)
```
We see that client `carol` sends the `IKEV2_FRAGMENTATION_SUPPORTED` (`FRAG_SUP`) and `INTERMEDIATE_EXCHANGE_SUPPORTED` (`IKE_INT_SUP`) notifications in the `IKE_SA_INIT` request, for the two mechanisms required to enable a post-quantum key exchange.

Also a traditional `KEY_EXCHANGE` (`KE`) payload is sent which contains the public factor of the legacy `X25519` elliptic curve Diffie-Hellman group.
```console
07[NET] received packet: from 192.168.0.2[500] to 192.168.0.3[500] (325 bytes)
07[ENC] parsed IKE_SA_INIT response 0 [ SA KE No N(NATD_S_IP) N(NATD_D_IP) CERTREQ N(FRAG_SUP) N(HASH_ALG) N(CHDLESS_SUP) N(IKE_INT_SUP) N(MULT_AUTH) V ]
```
Gateway `moon` supports the same mechanisms so that a post-quantum key exchange should succeed and its `KE` payload in turn allows to form a first `SKEYSEED` master secret that is used  to derive IKEv2 encryption and data integrity session keys so that the subsequent `IKE_INTERMEDIATE` messages in a secure way.
```console
06[IKE] received strongSwan vendor ID
06[CFG] selected proposal: IKE:AES_CBC_256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/CURVE_25519/KE1_KYBER_L3/KE2_NTRU_HPS_L3/KE3_SABER_L3
06[IKE] received cert request for "C=CH, O=Cyber, CN=Cyber Root CA"
```
The negotiated *hybrid* key exchange will use Dan Bernstein's `X25519` elliptic curve for the initial exchange, followed by three rounds of post-quantum key exchanges consisting of the `Kyber`, `NTRU` and `Saber` algorithms, all of them on NIST security level 3. 
```console
06[ENC] generating IKE_INTERMEDIATE request 1 [ KE ]
06[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1264 bytes)
09[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1168 bytes)
09[ENC] parsed IKE_INTERMEDIATE response 1 [ KE ]
```
The `Kyber` key exchange has been completed and the derived secret has been added to the `SKEYSEED` master secret.
```console
09[ENC] generating IKE_INTERMEDIATE request 2 [ KE ]
09[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1008 bytes)
06[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1008 bytes)
06[ENC] parsed IKE_INTERMEDIATE response 2 [ KE ]
```
The `NTRU` key exchange has been completed and the derived secret has been added to the `SKEYSEED` master secret.
```console
06[ENC] generating IKE_INTERMEDIATE request 3 [ KE ]
06[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1072 bytes)
14[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1168 bytes)
14[ENC] parsed IKE_INTERMEDIATE response 3 [ KE ]
```
The `Saber` key exchange has been completed and the derived secret has been added to the `SKEYSEED` master secret.
```console
14[IKE] sending cert request for "C=CH, O=Cyber, CN=Cyber Root CA"
14[IKE] authentication of 'carol@strongswan.org' (myself) with DILITHIUM_5 successful
14[IKE] sending end entity cert "C=CH, O=Cyber, CN=carol@strongswan.org"
14[IKE] establishing CHILD_SA net{1}
14[ENC] generating IKE_AUTH request 4 [ IDi CERT N(INIT_CONTACT) CERTREQ IDr AUTH CPRQ(ADDR) SA TSi TSr N(MOBIKE_SUP) N(NO_ADD_ADDR) N(MULT_AUTH) N(EAP_ONLY) N(MSG_ID_SYN_SUP) ]
14[ENC] splitting IKE message (9088 bytes) into 7 fragments
14[ENC] generating IKE_AUTH request 4 [ EF(1/7) ]
14[ENC] generating IKE_AUTH request 4 [ EF(2/7) ]
14[ENC] generating IKE_AUTH request 4 [ EF(3/7) ]
14[ENC] generating IKE_AUTH request 4 [ EF(4/7) ]
14[ENC] generating IKE_AUTH request 4 [ EF(5/7) ]
14[ENC] generating IKE_AUTH request 4 [ EF(6/7) ]
14[ENC] generating IKE_AUTH request 4 [ EF(7/7) ]
14[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
14[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
14[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
14[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
14[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
14[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
14[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (836 bytes)
```
The `IKE_AUTH` request containing a post-quantum `Dilithium5`  X.509  client certificate and a corresponding NIST security level 5 digital signature gets so large that it has to be split into 7 IKEv2 fragments.
```console
16[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
16[ENC] parsed IKE_AUTH response 4 [ EF(1/7) ]
16[ENC] received fragment #1 of 7, waiting for complete IKE message
07[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
07[ENC] parsed IKE_AUTH response 4 [ EF(2/7) ]
07[ENC] received fragment #2 of 7, waiting for complete IKE message
10[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
10[ENC] parsed IKE_AUTH response 4 [ EF(3/7) ]
10[ENC] received fragment #3 of 7, waiting for complete IKE message
05[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
05[ENC] parsed IKE_AUTH response 4 [ EF(4/7) ]
05[ENC] received fragment #4 of 7, waiting for complete IKE message
14[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
14[ENC] parsed IKE_AUTH response 4 [ EF(5/7) ]
14[ENC] received fragment #5 of 7, waiting for complete IKE message
16[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
16[ENC] parsed IKE_AUTH response 4 [ EF(6/7) ]
16[ENC] received fragment #6 of 7, waiting for complete IKE message
11[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (756 bytes)
11[ENC] parsed IKE_AUTH response 4 [ EF(7/7) ]
11[ENC] received fragment #7 of 7, reassembled fragmented IKE message (9008 bytes)
11[ENC] parsed IKE_AUTH response 4 [ IDr CERT AUTH CPRP(ADDR) SA TSi TSr N(MOBIKE_SUP) N(ADD_4_ADDR) ]
11[IKE] received end entity cert "C=CH, O=Cyber, CN=moon.strongswan.org"
11[CFG]   using certificate "C=CH, O=Cyber, CN=moon.strongswan.org"
11[CFG]   using trusted ca certificate "C=CH, O=Cyber, CN=Cyber Root CA"
11[CFG]   reached self-signed root ca with a path length of 0
11[IKE] authentication of 'moon.strongswan.org' with DILITHIUM_5 successful
```
IKEv2 fragmentation has also to be applied to the `IKE_AUTH` response containing a post-quantum `Dilithium5` X.509  gateway certificate and a corresponding NIST security level 5 digital signature as well. Both the client and gateway certificates are signed by a NIST security level 5 `Falcon1024` CA.
```console
11[IKE] IKE_SA home[1] established between 192.168.0.3[carol@strongswan.org]...192.168.0.2[moon.strongswan.org]
11[IKE] scheduling rekeying in 1791s
11[IKE] maximum IKE_SA lifetime 1971s
11[IKE] installing new virtual IP 10.3.0.1
11[CFG] selected proposal: ESP:AES_CBC_256/HMAC_SHA2_256_128/NO_EXT_SEQ
11[IKE] CHILD_SA net{1} established with SPIs cb2b8ea0_i c2de0917_o and TS 10.3.0.1/32 === 10.1.0.0/24
11[IKE] peer supports MOBIKE
```

## Establish a second CHILD SA <a name="section5"></a>

```console
carol# swanctl --initiate --child host > /dev/null
10[CFG] vici initiate CHILD_SA 'host'
16[IKE] establishing CHILD_SA host{2}
16[ENC] generating CREATE_CHILD_SA request 5 [ SA No KE TSi TSr ]
16[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (624 bytes)
08[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (624 bytes)
08[ENC] parsed CREATE_CHILD_SA response 5 [ SA No KE TSi TSr N(ADD_KE) ]
```
The `KE` payload in the `CREATE_CHILD_SA` message exchange transports the public factors of the `3072 bit` prime Diffie-Hellman group.
```console
08[CFG] selected proposal: ESP:AES_CBC_256/HMAC_SHA2_256_128/MODP_3072/NO_EXT_SEQ/KE1_FRODO_AES_L3/KE2_SIKE_L3
```
The negotiated *hybrid* key exchange will use the `3072 bit`prime Diffie-Hellman group for the initial exchange, followed by two rounds of post-quantum key exchanges consisting of the `FrodoKEM` and `SIKE` algorithms, both of them on NIST security level 3. 
```console
08[ENC] generating IKE_FOLLOWUP_KE request 6 [ KE N(ADD_KE) ]
08[ENC] splitting IKE message (15728 bytes) into 12 fragments
08[ENC] generating IKE_FOLLOWUP_KE request 6 [ EF(1/12) ]
08[ENC] generating IKE_FOLLOWUP_KE request 6 [ EF(2/12) ]
08[ENC] generating IKE_FOLLOWUP_KE request 6 [ EF(3/12) ]
08[ENC] generating IKE_FOLLOWUP_KE request 6 [ EF(4/12) ]
08[ENC] generating IKE_FOLLOWUP_KE request 6 [ EF(5/12) ]
08[ENC] generating IKE_FOLLOWUP_KE request 6 [ EF(6/12) ]
08[ENC] generating IKE_FOLLOWUP_KE request 6 [ EF(7/12) ]
08[ENC] generating IKE_FOLLOWUP_KE request 6 [ EF(8/12) ]
08[ENC] generating IKE_FOLLOWUP_KE request 6 [ EF(9/12) ]
08[ENC] generating IKE_FOLLOWUP_KE request 6 [ EF(10/12) ]
08[ENC] generating IKE_FOLLOWUP_KE request 6 [ EF(11/12) ]
08[ENC] generating IKE_FOLLOWUP_KE request 6 [ EF(12/12) ]
08[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
08[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
08[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
08[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
08[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
08[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
08[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
08[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
08[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
08[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
08[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
08[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (596 bytes)
```
The design of FrodoKEM is quite conservative so that the large public key sent by the initiator via the `IKE_FOLLOWUP_KE` message has to be split into 12 IKEv2 fragments.
```console
14[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
14[ENC] parsed IKE_FOLLOWUP_KE response 6 [ EF(1/12) ]
14[ENC] received fragment #1 of 12, waiting for complete IKE message
07[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
07[ENC] parsed IKE_FOLLOWUP_KE response 6 [ EF(2/12) ]
07[ENC] received fragment #2 of 12, waiting for complete IKE message
16[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
16[ENC] parsed IKE_FOLLOWUP_KE response 6 [ EF(3/12) ]
16[ENC] received fragment #3 of 12, waiting for complete IKE message
08[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
08[ENC] parsed IKE_FOLLOWUP_KE response 6 [ EF(4/12) ]
08[ENC] received fragment #4 of 12, waiting for complete IKE message
09[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
09[ENC] parsed IKE_FOLLOWUP_KE response 6 [ EF(5/12) ]
09[ENC] received fragment #5 of 12, waiting for complete IKE message
13[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
13[ENC] parsed IKE_FOLLOWUP_KE response 6 [ EF(6/12) ]
13[ENC] received fragment #6 of 12, waiting for complete IKE message
12[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
12[ENC] parsed IKE_FOLLOWUP_KE response 6 [ EF(7/12) ]
12[ENC] received fragment #7 of 12, waiting for complete IKE message
06[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
06[ENC] parsed IKE_FOLLOWUP_KE response 6 [ EF(8/12) ]
06[ENC] received fragment #8 of 12, waiting for complete IKE message
07[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
07[ENC] parsed IKE_FOLLOWUP_KE response 6 [ EF(9/12) ]
07[ENC] received fragment #9 of 12, waiting for complete IKE message
01[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
01[ENC] parsed IKE_FOLLOWUP_KE response 6 [ EF(10/12) ]
01[ENC] received fragment #10 of 12, waiting for complete IKE message
11[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
11[ENC] parsed IKE_FOLLOWUP_KE response 6 [ EF(11/12) ]
11[ENC] received fragment #11 of 12, waiting for complete IKE message
14[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (708 bytes)
14[ENC] parsed IKE_FOLLOWUP_KE response 6 [ EF(12/12) ]
14[ENC] received fragment #12 of 12, reassembled fragmented IKE message (15840 bytes)
14[ENC] parsed IKE_FOLLOWUP_KE response 6 [ KE N(ADD_KE) ]
```
The encrypted session secret sent by the responder has to be fragmented into 12 parts as well.  The `FrodoKEM` key exchange has been completed and the derived secret has been added to the `SKEYSEED` master secret.
```console
14[ENC] generating IKE_FOLLOWUP_KE request 7 [ KE N(ADD_KE) ]
14[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (544 bytes)
05[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (560 bytes)
05[ENC] parsed IKE_FOLLOWUP_KE response 7 [ KE ]
```
The `SIKE` public key and encrypted secret are extremely compact and can be exchanged with an unfragmented `IKE_FOLLOWUP_KE` message each. The `SIKE` key exchange has been completed and the derived secret has been added to the `SKEYSEED` master secret.
```console
05[IKE] CHILD_SA host{2} established with SPIs cf45a426_i cd44246f_o and TS 10.3.0.1/32 === 192.168.0.2/32
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
home: #1, ESTABLISHED, IKEv2, 14c4437249b504f5_i* c986e5bb5bc561c3_r
  local  'carol@strongswan.org' @ 192.168.0.3[4500] [10.3.0.1]
  remote 'moon.strongswan.org' @ 192.168.0.2[4500]
  AES_CBC-256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/CURVE_25519/KE1_KYBER_L3/KE2_NTRU_HPS_L3/KE3_SABER_L3
  established 1043s ago, rekeying in 748s
  net: #1, reqid 1, INSTALLED, TUNNEL, ESP:AES_CBC-256/HMAC_SHA2_256_128
    installed 1043s ago, rekeying in 40s, expires in 277s
    in  cb2b8ea0,    168 bytes,     2 packets,    19s ago
    out c2de0917,    168 bytes,     2 packets,    19s ago
    local  10.3.0.1/32
    remote 10.1.0.0/24
  host: #2, reqid 2, INSTALLED, TUNNEL, ESP:AES_CBC-256/HMAC_SHA2_256_128/MODP_3072/KE1_FRODO_AES_L3/KE2_SIKE_L3
    installed 242s ago, rekeying in 935s, expires in 1078s
    in  cf45a426,     84 bytes,     1 packets,     6s ago
    out cd44246f,     84 bytes,     1 packets,     6s ago
    local  10.3.0.1/32
    remote 192.168.0.2/32
```
Since we have waited quite some time before we established the second `CHILD_SA` the `IKE_SA` rekeying will happen after the rekeying of the first `CHILD_SA` but before the rekeying of the second `CHILD_SA`.


## Rekeying of first CHILD SA <a name="section7"></a>

The rekeying of the first 'CHILD_SA' takes place automatically after the `rekey_time` interval of `20` minutes.
```console
08[KNL] creating rekey job for CHILD_SA ESP/0xcb2b8ea0/192.168.0.3
08[IKE] establishing CHILD_SA net{3} reqid 1
08[ENC] generating CREATE_CHILD_SA request 8 [ N(REKEY_SA) SA No KE TSi TSr ]
08[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (288 bytes)
05[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (288 bytes)
05[ENC] parsed CREATE_CHILD_SA response 8 [ SA No KE TSi TSr N(ADD_KE) ]
```
```console
05[CFG] selected proposal: ESP:AES_CBC_256/HMAC_SHA2_256_128/CURVE_25519/NO_EXT_SEQ/KE1_KYBER_L3/KE2_NTRU_HPS_L3/KE3_SABER_L3
```
```console
05[ENC] generating IKE_FOLLOWUP_KE request 9 [ KE N(ADD_KE) ]
05[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1280 bytes)
07[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1184 bytes)
07[ENC] parsed IKE_FOLLOWUP_KE response 9 [ KE N(ADD_KE) ]
```
```console
07[ENC] generating IKE_FOLLOWUP_KE request 10 [ KE N(ADD_KE) ]
07[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1024 bytes)
13[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1024 bytes)
13[ENC] parsed IKE_FOLLOWUP_KE response 10 [ KE N(ADD_KE) ]
```
```console
13[ENC] generating IKE_FOLLOWUP_KE request 11 [ KE N(ADD_KE) ]
13[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1088 bytes)
09[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1168 bytes)
09[ENC] parsed IKE_FOLLOWUP_KE response 11 [ KE ]
```
```console
09[IKE] inbound CHILD_SA net{3} established with SPIs c88bc11f_i cd992e50_o and TS 10.3.0.1/32 === 10.1.0.0/16
09[IKE] outbound CHILD_SA net{3} established with SPIs c88bc11f_i cd992e50_o and TS 10.3.0.1/32 === 10.1.0.0/16
```
The new `CHILD_SA` has been established..
```console
09[IKE] closing CHILD_SA net{1} with SPIs cb2b8ea0_i (168 bytes) c2de0917_o (168 bytes) and TS 10.3.0.1/32 === 10.1.0.0/24
09[IKE] sending DELETE for ESP CHILD_SA with SPI cb2b8ea0
09[ENC] generating INFORMATIONAL request 12 [ D ]
09[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (80 bytes)
10[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (80 bytes)
10[ENC] parsed INFORMATIONAL response 12 [ D ]
10[IKE] received DELETE for ESP CHILD_SA with SPI c2de0917
10[IKE] CHILD_SA closed
```
The old `CHILD_SA` has been deleted.

## Rekeying of IKE SA <a name="section8"></a>

The rekeying of the first 'IKE_SA' takes place automatically after the `rekey_time` interval of `30` minutes.
```console
13[ENC] generating CREATE_CHILD_SA request 13 [ SA No KE ]
13[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (224 bytes)
07[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (240 bytes)
07[ENC] parsed CREATE_CHILD_SA response 13 [ SA No KE N(ADD_KE) ]
```
```console
07[CFG] selected proposal: IKE:AES_CBC_256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/CURVE_25519/KE1_KYBER_L3/KE2_NTRU_HPS_L3/KE3_SABER_L3
```
```console
07[ENC] generating IKE_FOLLOWUP_KE request 14 [ KE N(ADD_KE) ]
07[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1280 bytes)
09[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1184 bytes)
09[ENC] parsed IKE_FOLLOWUP_KE response 14 [ KE N(ADD_KE) ]
```
```console
09[ENC] generating IKE_FOLLOWUP_KE request 15 [ KE N(ADD_KE) ]
09[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1024 bytes)
14[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1024 bytes)
14[ENC] parsed IKE_FOLLOWUP_KE response 15 [ KE N(ADD_KE) ]
```
```console
14[ENC] generating IKE_FOLLOWUP_KE request 16 [ KE N(ADD_KE) ]
14[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1088 bytes)
11[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1168 bytes)
11[ENC] parsed IKE_FOLLOWUP_KE response 16 [ KE ]
```
```console
11[IKE] scheduling rekeying in 1721s
11[IKE] maximum IKE_SA lifetime 1901s
11[IKE] IKE_SA home[2] rekeyed between 192.168.0.3[carol@strongswan.org]...192.168.0.2[moon.strongswan.org]
```
The new `IKE_SA` has been rekeyed.
```console
11[IKE] deleting IKE_SA home[1] between 192.168.0.3[carol@strongswan.org]...192.168.0.2[moon.strongswan.org]
11[IKE] sending DELETE for IKE_SA home[1]
11[ENC] generating INFORMATIONAL request 17 [ D ]
11[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (80 bytes)
10[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (80 bytes)
10[ENC] parsed INFORMATIONAL response 17 [ ]
10[IKE] IKE_SA deleted
```
The old `IKE_SA` has been deleted.

## Rekeying of second CHILD SA <a name="section9"></a>

The rekeying of the second  'CHILD_SA' takes place automatically after the `rekey_time` interval of `20` minutes.
```console
13[KNL] creating rekey job for CHILD_SA ESP/0xcf45a426/192.168.0.3
13[IKE] establishing CHILD_SA host{4} reqid 2
13[ENC] generating CREATE_CHILD_SA request 0 [ N(REKEY_SA) SA No KE TSi TSr ]
13[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (624 bytes)
09[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (624 bytes)
09[ENC] parsed CREATE_CHILD_SA response 0 [ SA No KE TSi TSr N(ADD_KE) ]
```
```console
09[CFG] selected proposal: ESP:AES_CBC_256/HMAC_SHA2_256_128/MODP_3072/NO_EXT_SEQ/KE1_FRODO_AES_L3/KE2_SIKE_L3
```
```console
09[ENC] generating IKE_FOLLOWUP_KE request 1 [ KE N(ADD_KE) ]
09[ENC] splitting IKE message (15728 bytes) into 12 fragments
09[ENC] generating IKE_FOLLOWUP_KE request 1 [ EF(1/12) ]
09[ENC] generating IKE_FOLLOWUP_KE request 1 [ EF(2/12) ]
09[ENC] generating IKE_FOLLOWUP_KE request 1 [ EF(3/12) ]
09[ENC] generating IKE_FOLLOWUP_KE request 1 [ EF(4/12) ]
09[ENC] generating IKE_FOLLOWUP_KE request 1 [ EF(5/12) ]
09[ENC] generating IKE_FOLLOWUP_KE request 1 [ EF(6/12) ]
09[ENC] generating IKE_FOLLOWUP_KE request 1 [ EF(7/12) ]
09[ENC] generating IKE_FOLLOWUP_KE request 1 [ EF(8/12) ]
09[ENC] generating IKE_FOLLOWUP_KE request 1 [ EF(9/12) ]
09[ENC] generating IKE_FOLLOWUP_KE request 1 [ EF(10/12) ]
09[ENC] generating IKE_FOLLOWUP_KE request 1 [ EF(11/12) ]
09[ENC] generating IKE_FOLLOWUP_KE request 1 [ EF(12/12) ]
09[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
09[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
09[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
09[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
09[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
09[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
09[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
09[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
09[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
09[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
09[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
09[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (596 bytes)
```
```console
14[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
14[ENC] parsed IKE_FOLLOWUP_KE response 1 [ EF(1/12) ]
14[ENC] received fragment #1 of 12, waiting for complete IKE message
05[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
05[ENC] parsed IKE_FOLLOWUP_KE response 1 [ EF(11/12) ]
05[ENC] received fragment #11 of 12, waiting for complete IKE message
10[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
10[ENC] parsed IKE_FOLLOWUP_KE response 1 [ EF(3/12) ]
10[ENC] received fragment #3 of 12, waiting for complete IKE message
01[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
01[ENC] parsed IKE_FOLLOWUP_KE response 1 [ EF(4/12) ]
01[ENC] received fragment #4 of 12, waiting for complete IKE message
06[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
06[ENC] parsed IKE_FOLLOWUP_KE response 1 [ EF(5/12) ]
06[ENC] received fragment #5 of 12, waiting for complete IKE message
12[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
12[ENC] parsed IKE_FOLLOWUP_KE response 1 [ EF(6/12) ]
12[ENC] received fragment #6 of 12, waiting for complete IKE message
08[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
08[ENC] parsed IKE_FOLLOWUP_KE response 1 [ EF(7/12) ]
08[ENC] received fragment #7 of 12, waiting for complete IKE message
16[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
16[ENC] parsed IKE_FOLLOWUP_KE response 1 [ EF(8/12) ]
16[ENC] received fragment #8 of 12, waiting for complete IKE message
07[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
07[ENC] parsed IKE_FOLLOWUP_KE response 1 [ EF(9/12) ]
07[ENC] received fragment #9 of 12, waiting for complete IKE message
13[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
13[ENC] parsed IKE_FOLLOWUP_KE response 1 [ EF(10/12) ]
13[ENC] received fragment #10 of 12, waiting for complete IKE message
11[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
11[ENC] parsed IKE_FOLLOWUP_KE response 1 [ EF(2/12) ]
11[ENC] received fragment #2 of 12, waiting for complete IKE message
14[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (708 bytes)
14[ENC] parsed IKE_FOLLOWUP_KE response 1 [ EF(12/12) ]
14[ENC] received fragment #12 of 12, reassembled fragmented IKE message (15840 bytes)
14[ENC] parsed IKE_FOLLOWUP_KE response 1 [ KE N(ADD_KE) ]
```
```console
14[ENC] generating IKE_FOLLOWUP_KE request 2 [ KE N(ADD_KE) ]
14[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (544 bytes)
09[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (560 bytes)
09[ENC] parsed IKE_FOLLOWUP_KE response 2 [ KE ]
```
```console
09[IKE] inbound CHILD_SA host{4} established with SPIs c1c094b4_i cc6eadca_o and TS 10.3.0.1/32 === 192.168.0.2/32
09[IKE] outbound CHILD_SA host{4} established with SPIs c1c094b4_i cc6eadca_o and TS 10.3.0.1/32 === 192.168.0.2/32
```
The new `CHILD_SA` has been  established..
```console
09[IKE] closing CHILD_SA host{2} with SPIs cf45a426_i (84 bytes) cd44246f_o (84 bytes) and TS 10.3.0.1/32 === 192.168.0.2/32
09[IKE] sending DELETE for ESP CHILD_SA with SPI cf45a426
09[ENC] generating INFORMATIONAL request 3 [ D ]
09[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (80 bytes)
05[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (80 bytes)
05[ENC] parsed INFORMATIONAL response 3 [ D ]
05[IKE] received DELETE for ESP CHILD_SA with SPI cd44246f
05[IKE] CHILD_SA closed
```
The old `CHILD_SA` has been deleted.

## SA Status after Rekeying <a name="section10"></a>

```console
carol# swanctl --list-sas
home: #2, ESTABLISHED, IKEv2, a0895d1c146f9a5a_i* 2c8316459c33944c_r
  local  'carol@strongswan.org' @ 192.168.0.3[4500] [10.3.0.1]
  remote 'moon.strongswan.org' @ 192.168.0.2[4500]
  AES_CBC-256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/CURVE_25519/KE1_KYBER_L3/KE2_NTRU_HPS_L3/KE3_SABER_L3
  established 429s ago, rekeying in 1292s
  net: #3, reqid 1, INSTALLED, TUNNEL, ESP:AES_CBC-256/HMAC_SHA2_256_128/CURVE_25519/KE1_KYBER_L3/KE2_NTRU_HPS_L3/KE3_SABER_L3
    installed 684s ago, rekeying in 409s, expires in 636s
    in  c88bc11f,      0 bytes,     0 packets
    out cd992e50,      0 bytes,     0 packets
    local  10.3.0.1/32
    remote 10.1.0.0/16
  host: #4, reqid 2, INSTALLED, TUNNEL, ESP:AES_CBC-256/HMAC_SHA2_256_128/MODP_3072/KE1_FRODO_AES_L3/KE2_SIKE_L3
    installed 242s ago, rekeying in 879s, expires in 1078s
    in  c1c094b4,      0 bytes,     0 packets
    out cc6eadca,      0 bytes,     0 packets
    local  10.3.0.1/32
    remote 192.168.0.2/32
```

Author:  [Andreas Steffen][AS] [CC BY 4.0][CC]

[AS]: mailto:andreas.steffen@strongsec.net
[CC]: http://creativecommons.org/licenses/by/4.0/

