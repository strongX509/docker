# pq-strongswan

Build and run a [strongSwan][STRONGSWAN] 6.0dr Post-Quantum IKEv2 Daemon.

[STRONGSWAN]: https://www.strongswan.org

## Pull Docker Image

```
$ docker pull strongx509/pq-strongswan
```

## Build Docker Image

Alternatively the docker image can be built from scratch in the `strongswan` directory with
```console
$ docker build -t strongx509/pq-strongswan .
```
The build rules are defined in [Dockerfile](Dockerfile).

## Create Docker Containers and Local Networks

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

## strongSwan Configuration

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
   fragment_size = 1480
   max_packet = 30000
}
```

### NIST Round 3 Submission KEM Candidates

| Keyword  | Key Exchange Method | Keyword  | Key Exchange Method | Keyword  | Key Exchange Method |
| :------- | :------------------ | :------- | :------------------ | :------- | :------------------ |
| `kyber1` | `KE_KYBER_L1`       | `kyber3` | `KE_KYBER_L3`       | `kyber5` | `KE_KYBER_L5`       |
| `ntrup1` | `KE_NTRU_HPS_L1`    | `ntrup3` | `KE_NTRU_HPS_L3`    | `ntrup5` | `KE_NTRU_HPS_L5`    |
|          |                     | `ntrur3` | `KE_NTRU_HRSS_L3`   |          |                     |
| `saber1` | `KE_SABER_L1`       | `saber3` | `KE_SABER_L3`       | `saber5` | `KE_SABER_L5`       |


### NIST Alternate KEM Candidates

| Keyword   | Key Exchange Method | Keyword   | Key Exchange Method | Keyword   | Key Exchange Method |
| :-------- | :------------------ | :-------- | :------------------ | :-------- | :------------------ |
| `frodoa1` | `KE_FRODO_AES_L1`   | `frodoa3` | `KE_FRODO_AES_L3`   | `frodoa5` | `KE_FRODO_AES_L5`   |
| `frodos1` | `KE_FRODO_SHAKE_L1` | `frodos3` | `KE_FRODO_SHAKE_L3` | `frodos5` | `KE_FRODO_SHAKE_L5` |
| `sike1`   | `KE_SIKE_L1`        | `sike3`   | `KE_SIKE_L3`        | `sike5`   | `KE_SIKE_L5`        |
|           |                     | `sike2`   | `KE_SIKE_L2`        |           |                     |

The KEM algorithms listed above are implemented by the strongSwan `oqs` plugin which in turn uses the  [liboqs][LIBOQS]  Open Quantum-Safe library. There is also a `frodo` plugin which implements the `FrodoKEM` algorithm with strongSwan crypto primitives. There is currently no support for the `BIKE` and  `HQC` alternate KEM candidates. `Classic McEliece` , although being a NIST round 3 submission KEM candidate, is not an option for IKE due to the huge public key size of more than 100 kB.

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
          }
         host {
            esp_proposals = aes256-sha256-modp3072-ke1_frodoa3-ke2_sike3
         }
      }
      version = 2
      proposals = aes256-sha256-x25519-ke1_kyber3-ke2_ntrup3-ke3_saber3
   }
}
```

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

            esp_proposals = aes256-sha256-x25519-ke1_kyber3-ke2_ntrup3-ke3_saber3
         }
         host {
            esp_proposals = aes256-sha256-modp3072-ke1_frodoa3-ke2_sike3
         }
      }
      version = 2
      proposals = aes256-sha256-x25519-modp3072-ke1_kyber3-ke1_frodoa3-ke2_ntrup3-ke2_sike3-ke3_saber3
   }
}

pools {

   rw_pool {
      addrs = 10.3.0.0/24
   }
}
```

## Starting up the IKEv2 Daemons

### On VPN Gateway "moon"

In an additional console window we open a `bash` shell to start and manage the strongSwan `charon` daemon in the `moon` container
```console
moon$ docker exec -ti moon /bin/bash
moon# ./charon &
00[DMN] Starting IKE charon daemon (strongSwan 6.0dr1, Linux 5.4.0-48-generic, x86_64)
00[LIB] loaded plugins: charon random nonce x509 constraints pubkey pkcs1 pkcs8 pkcs12 pem openssl frodo oqs drbg kernel-netlink socket-default vici updown
00[JOB] spawning 16 worker threads
00[DMN] executing start script 'creds' (swanctl --load-creds)
15[CFG] loaded certificate 'C=CH, O=Cyber, CN=moon.strongswan.org'
09[CFG] loaded certificate 'C=CH, O=Cyber, CN=Cyber Root CA'
13[CFG] loaded ECDSA private key
00[DMN] creds: loaded certificate from '/etc/swanctl/x509/moonCert.pem'
00[DMN] creds: loaded certificate from '/etc/swanctl/x509ca/caCert.pem'
00[DMN] creds: loaded ecdsa key from '/etc/swanctl/ecdsa/moonKey.pem'
00[DMN] executing start script 'conns' (swanctl --load-conns)
12[CFG] added vici connection: rw
00[DMN] conns: loaded connection 'rw'
00[DMN] conns: successfully loaded 1 connections, 0 unloaded
00[DMN] executing start script 'pools' (swanctl --load-pools)
12[CFG] added vici pool rw_pool: 10.3.0.0, 254 entries
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

### On VPN Client "carol"

In a third console window we open a `bash`shell to start and manage the strongSwan `charon` daemon in the `carol` container
```console
carol$ docker exec -ti carol /bin/bash
carol# ./charon &
00[DMN] Starting IKE charon daemon (strongSwan 6.0dr1, Linux 5.4.0-48-generic, x86_64)
00[LIB] loaded plugins: charon random nonce x509 constraints pubkey pkcs1 pkcs8 pkcs12 pem openssl frodo oqs drbg kernel-netlink socket-default vici updown
00[JOB] spawning 16 worker threads
00[DMN] executing start script 'creds' (swanctl --load-creds)
01[CFG] loaded certificate 'C=CH, O=Cyber, CN=carol@strongswan.org'
08[CFG] loaded certificate 'C=CH, O=Cyber, CN=Cyber Root CA'
13[CFG] loaded ECDSA private key
00[DMN] creds: loaded certificate from '/etc/swanctl/x509/carolCert.pem'
00[DMN] creds: loaded certificate from '/etc/swanctl/x509ca/caCert.pem'
00[DMN] creds: loaded ecdsa key from '/etc/swanctl/ecdsa/carolKey.pem'
00[DMN] executing start script 'conns' (swanctl --load-conns)
12[CFG] added vici connection: home
00[DMN] conns: loaded connection 'home'
00[DMN] conns: successfully loaded 1 connections, 0 unloaded
```
We also list the connection definition on `carol`
```console
carol# swanctl --list-conns
home: IKEv2, no reauthentication, rekeying every 14400s
  local:  %any
  remote: 192.168.0.2
  local public key authentication:
    id: carol@strongswan.org
    certs: C=CH, O=Cyber, CN=carol@strongswan.org
  remote public key authentication:
    id: moon.strongswan.org
  net: TUNNEL, rekeying every 3600s
    local:  dynamic
    remote: 10.1.0.0/16
  host: TUNNEL, rekeying every 3600s
    local:  dynamic
    remote: dynamic
```
## Establish the IKE SA and first Child SA

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
06[NET] received packet: from 192.168.0.2[500] to 192.168.0.3[500] (325 bytes)
06[ENC] parsed IKE_SA_INIT response 0 [ SA KE No N(NATD_S_IP) N(NATD_D_IP) CERTREQ N(FRAG_SUP) N(HASH_ALG) N(CHDLESS_SUP) N(IKE_INT_SUP) N(MULT_AUTH) V ]
```
Gateway `moon` supports the same mechanisms so that a post-quantum key exchange should succeed and its `KE` payload in turn will allow it to send the subsequent `IKE_INTERMEDIATE` messages in a cryptographically secure way.
```console
06[IKE] received strongSwan vendor ID
06[CFG] selected proposal: IKE:AES_CBC_256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/CURVE_25519/KE_KYBER_L3/KE_NTRU_HPS_L3/KE_SABER_L3
06[IKE] received cert request for "C=CH, O=Cyber, CN=Cyber Root CA"
```
The negotiated *hybrid* key exchange will use Dan Bernstein's `X25519` elliptic curve for the initial exchange, followed by three rounds of post-quantum key exchanges consisting of the `Kyber`, `NTRU` and `Saber` algorithms, all of them on NIST security level 3. 
```console
06[ENC] generating IKE_INTERMEDIATE request 1 [ KE ]
06[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1264 bytes)
09[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1168 bytes)
09[ENC] parsed IKE_INTERMEDIATE response 1 [ KE ]
```
The `Kyber` key exchange has been completed and the derived secret has been added to the master session key.
```console
09[ENC] generating IKE_INTERMEDIATE request 2 [ KE ]
09[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1008 bytes)
06[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1008 bytes)
06[ENC] parsed IKE_INTERMEDIATE response 2 [ KE ]
```
The `NTRU` key exchange has been completed and the derived secret has been added to the master session key.
```console
06[ENC] generating IKE_INTERMEDIATE request 3 [ KE ]
06[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1072 bytes)
09[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1168 bytes)
09[ENC] parsed IKE_INTERMEDIATE response 3 [ KE ]
```
The `Saber` key exchange has been completed and the derived secret has been added to the master session key.
```console
09[IKE] sending cert request for "C=CH, O=Cyber, CN=Cyber Root CA"
09[IKE] authentication of 'carol@strongswan.org' (myself) with ECDSA_WITH_SHA384_DER successful
09[IKE] sending end entity cert "C=CH, O=Cyber, CN=carol@strongswan.org"
09[IKE] establishing CHILD_SA net{1}
09[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (928 bytes)
13[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (848 bytes)
13[ENC] parsed IKE_AUTH response 4 [ IDr CERT AUTH CPRP(ADDR) SA TSi TSr N(MOBIKE_SUP) N(ADD_4_ADDR) ]
13[IKE] received end entity cert "C=CH, O=Cyber, CN=moon.strongswan.org"
13[CFG]   using certificate "C=CH, O=Cyber, CN=moon.strongswan.org"
13[CFG]   using trusted ca certificate "C=CH, O=Cyber, CN=Cyber Root CA"
13[CFG]   reached self-signed root ca with a path length of 0
13[IKE] authentication of 'moon.strongswan.org' with ECDSA_WITH_SHA384_DER successful
13[IKE] IKE_SA home[1] established between 192.168.0.3[carol@strongswan.org]...192.168.0.2[moon.strongswan.org]
13[IKE] scheduling rekeying in 13241s
13[IKE] maximum IKE_SA lifetime 14681s
13[IKE] installing new virtual IP 10.3.0.1
13[CFG] selected proposal: ESP:AES_CBC_256/HMAC_SHA2_256_128/NO_EXT_SEQ
13[IKE] CHILD_SA net{1} established with SPIs c18035b3_i c83dfda9_o and TS 10.3.0.1/32 === 10.1.0.0/24
13[IKE] peer supports MOBIKE
```

## Establish a second CHILD SA

```console
carol# swanctl --initiate --child host > /dev/null
06[CFG] vici initiate CHILD_SA 'host'
01[IKE] establishing CHILD_SA host{2}
01[ENC] generating CREATE_CHILD_SA request 5 [ SA No KE TSi TSr ]
01[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (624 bytes)
13[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (624 bytes)
13[ENC] parsed CREATE_CHILD_SA response 5 [ SA No KE TSi TSr N(ADD_KE) ]
```
The `KE` payload in the `CREATE_CHILD_SA` message exchange transports the public factors of the `3072 bit` prime Diffie-Hellman group.
```console
13[CFG] selected proposal: ESP:AES_CBC_256/HMAC_SHA2_256_128/MODP_3072/NO_EXT_SEQ/KE_FRODO_AES_L3/KE_SIKE_L3
```
The negotiated *hybrid* key exchange will use the `3072 bit`prime Diffie-Hellman group for the initial exchange, followed by two rounds of post-quantum key exchanges consisting of the `FrodoKEM` and `SIKE` algorithms, both of them on NIST security level 3. 
```console
13[ENC] generating IKE_FOLLOWUP_KE request 6 [ KE N(ADD_KE) ]
13[ENC] splitting IKE message (15728 bytes) into 12 fragments
13[ENC] generating IKE_FOLLOWUP_KE request 6 [ EF(1/12) ]
13[ENC] generating IKE_FOLLOWUP_KE request 6 [ EF(2/12) ]
13[ENC] generating IKE_FOLLOWUP_KE request 6 [ EF(3/12) ]
13[ENC] generating IKE_FOLLOWUP_KE request 6 [ EF(4/12) ]
13[ENC] generating IKE_FOLLOWUP_KE request 6 [ EF(5/12) ]
13[ENC] generating IKE_FOLLOWUP_KE request 6 [ EF(6/12) ]
13[ENC] generating IKE_FOLLOWUP_KE request 6 [ EF(7/12) ]
13[ENC] generating IKE_FOLLOWUP_KE request 6 [ EF(8/12) ]
13[ENC] generating IKE_FOLLOWUP_KE request 6 [ EF(9/12) ]
13[ENC] generating IKE_FOLLOWUP_KE request 6 [ EF(10/12) ]
13[ENC] generating IKE_FOLLOWUP_KE request 6 [ EF(11/12) ]
13[ENC] generating IKE_FOLLOWUP_KE request 6 [ EF(12/12) ]
13[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
13[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
13[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
13[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
13[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
13[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
13[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
13[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
13[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
13[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
13[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (1444 bytes)
13[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (596 bytes)
```
The design of FrodoKEM is quite conservative so that the large public key sent by the initiator via the `IKE_FOLLOWUP_KE` message has to be split into 12 IKEv2 fragments.
```console
07[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
07[ENC] parsed IKE_FOLLOWUP_KE response 6 [ EF(1/12) ]
07[ENC] received fragment #1 of 12, waiting for complete IKE message
15[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
15[ENC] parsed IKE_FOLLOWUP_KE response 6 [ EF(2/12) ]
15[ENC] received fragment #2 of 12, waiting for complete IKE message
10[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
10[ENC] parsed IKE_FOLLOWUP_KE response 6 [ EF(3/12) ]
10[ENC] received fragment #3 of 12, waiting for complete IKE message
12[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
12[ENC] parsed IKE_FOLLOWUP_KE response 6 [ EF(4/12) ]
12[ENC] received fragment #4 of 12, waiting for complete IKE message
13[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
13[ENC] parsed IKE_FOLLOWUP_KE response 6 [ EF(5/12) ]
13[ENC] received fragment #5 of 12, waiting for complete IKE message
14[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
14[ENC] parsed IKE_FOLLOWUP_KE response 6 [ EF(6/12) ]
14[ENC] received fragment #6 of 12, waiting for complete IKE message
08[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
08[ENC] parsed IKE_FOLLOWUP_KE response 6 [ EF(7/12) ]
08[ENC] received fragment #7 of 12, waiting for complete IKE message
01[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
01[ENC] parsed IKE_FOLLOWUP_KE response 6 [ EF(8/12) ]
01[ENC] received fragment #8 of 12, waiting for complete IKE message
11[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
11[ENC] parsed IKE_FOLLOWUP_KE response 6 [ EF(9/12) ]
11[ENC] received fragment #9 of 12, waiting for complete IKE message
05[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
05[ENC] parsed IKE_FOLLOWUP_KE response 6 [ EF(10/12) ]
05[ENC] received fragment #10 of 12, waiting for complete IKE message
09[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (1444 bytes)
09[ENC] parsed IKE_FOLLOWUP_KE response 6 [ EF(11/12) ]
09[ENC] received fragment #11 of 12, waiting for complete IKE message
12[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (708 bytes)
12[ENC] parsed IKE_FOLLOWUP_KE response 6 [ EF(12/12) ]
12[ENC] received fragment #12 of 12, reassembled fragmented IKE message (15840 bytes)
12[ENC] parsed IKE_FOLLOWUP_KE response 6 [ KE N(ADD_KE) ]
```
The encrypted session secret sent by the responder has to be fragmented into 12 parts as well.
```console
12[ENC] generating IKE_FOLLOWUP_KE request 7 [ KE N(ADD_KE) ]
12[NET] sending packet: from 192.168.0.3[4500] to 192.168.0.2[4500] (544 bytes)
13[NET] received packet: from 192.168.0.2[4500] to 192.168.0.3[4500] (560 bytes)
13[ENC] parsed IKE_FOLLOWUP_KE response 7 [ KE ]
```
The `SIKE` public key and encrypted secret are extremely compact and can be exchanged with an unfragmented `IKE_FOLLOWUP_KE` message each.
```console
13[IKE] CHILD_SA host{2} established with SPIs cc078656_i c80f82a6_o and TS 10.3.0.1/32 === 192.168.0.2/32
```

## Use the IPsec Tunnels

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
Now let's have a look at the established tunnel connections:
```console
carol# swanctl --list-sas
home: #1, ESTABLISHED, IKEv2, f0cf2c2a9ed74b79_i* d84e3da56391fa69_r
  local  'carol@strongswan.org' @ 192.168.0.3[4500] [10.3.0.1]
  remote 'moon.strongswan.org' @ 192.168.0.2[4500]
  AES_CBC-256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/CURVE_25519/KE_KYBER_L3/KE_NTRU_HPS_L3/KE_SABER_L3
  established 368s ago, rekeying in 12873s
  net: #1, reqid 1, INSTALLED, TUNNEL, ESP:AES_CBC-256/HMAC_SHA2_256_128
    installed 368s ago, rekeying in 2873s, expires in 3592s
    in  c18035b3,    168 bytes,     2 packets,    15s ago
    out c83dfda9,    168 bytes,     2 packets,    15s ago
    local  10.3.0.1/32
    remote 10.1.0.0/24
  host: #2, reqid 2, INSTALLED, TUNNEL, ESP:AES_CBC-256/HMAC_SHA2_256_128/MODP_3072
    installed 104s ago, rekeying in 3147s, expires in 3856s
    in  cc078656,     84 bytes,     1 packets,     7s ago
    out c80f82a6,     84 bytes,     1 packets,     7s ago
    local  10.3.0.1/32
    remote 192.168.0.2/32
```
Author:  [Andreas Steffen][AS] [CC BY 4.0][CC]

[AS]: mailto:andreas.steffen@strongsec.net
[CC]: http://creativecommons.org/licenses/by/4.0/

