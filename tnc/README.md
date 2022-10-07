# tnc

Build and run both a TNC Client and a TNC Server collocated with a [strongSwan][STRONGSWAN]
IKEv2 Daemon managed via the Versatile IKE Control Interface (VICI).

[STRONGSWAN]: https://www.strongswan.org

## Pull Docker Images

```
$ docker pull strongx509/tnc-client
$ docker pull strongX509/tnc-server
```

## Build Docker Image

Alternatively the docker image can be built from scratch in the `tnc` directory with
```console
$ docker build -f Dockerfile.client -t strongx509/tnc-client .
$ docker build -f Dockerfile.server -t strongx509/tnc-server .

```
The build rules are defined in [Dockerfile.client](Dockerfile.client) and
[Dockerfile.server](Dockerfile.server), respectively.

## Create Docker Containers and Local Networks


```
               +----------------+                        +----------------+
  10.3.0.1 --- | VPN/TNC Client | === 192.168.0.0/24 === | VPN/TNC Server | --- 10.1.0.0/16
 Virtual IP    +----------------+ .3     Internet     .2 +----------------+ .2    Intranet
```
The two docker containers `tnc-server` and  `tnc-client` as well as the local networks
`strongswan_internet` and `strongswan_intranet` are created with the command
```console
$ docker-compose up
Creating tnc-server ... done
Creating tnc-client ... done
Attaching to tnc-server, tnc-client

```
with the setup defined in [docker-compose.yml](docker-compose.yml).

In an additional console window we open a `bash` shell onto the `tnc-server` container and
initialize the strongTNC web-based tool running on an Apache server
```console
server$ docker exec -ti tnc-server /bin/bash
server# init_tnc
```
Then we start the strongSwan `charon` daemon in the background
```console
server# ./charon &
00[DMN] Starting IKE charon daemon (strongSwan 5.9.8, Linux 5.15.0-48-generic, x86_64)
00[TNC] TNC recommendation policy is 'default'
00[TNC] loading IMVs from '/etc/tnc_config'
00[TNC] added IETF attributes
00[TNC] added ITA-HSR attributes
00[TNC] added PWG attributes
00[TNC] added TCG attributes
00[LIB] libimcv initialized
00[IMV] IMV 1 "OS" initialized
00[TNC] IMV 1 supports 1 message type: 'IETF/Operating System' 0x000000/0x00000001
00[TNC] IMV 1 "OS" loaded from '/usr/lib/ipsec/imcvs/imv-os.so'
00[IMV] IMV 2 "Scanner" initialized
00[TNC] IMV 2 supports 1 message type: 'IETF/Firewall' 0x000000/0x00000005
00[TNC] IMV 2 "Scanner" loaded from '/usr/lib/ipsec/imcvs/imv-scanner.so'
```
The `OS` and `Scanner` Integrity Measurement Verifiers (`IMVs`) are loaded since
they have been enabled in `/etc/tnc_config`.
```console
00[LIB] loaded plugins: charon random nonce x509 constraints pubkey pem openssl curl sqlite kernel-netlink resolve socket-default vici updown eap-identity eap-md5 eap-ttls eap-tnc tnc-imv tnc-tnccs tnccs-20
00[JOB] spawning 16 worker threads
00[DMN] executing start script 'creds' (swanctl --load-creds)
01[CFG] loaded certificate 'C=CH, O=Cyber, CN=server.strongswan.org'
08[CFG] loaded certificate 'C=CH, O=Cyber, CN=Cyber Root CA'
11[CFG] loaded ECDSA private key
16[CFG] loaded EAP shared key with id 'eap-jane' for: 'jane'
08[CFG] loaded EAP shared key with id 'eap-hacker' for: 'hacker'
00[DMN] creds: loaded certificate from '/etc/swanctl/x509/serverCert.pem'
00[DMN] creds: loaded certificate from '/etc/swanctl/x509ca/caCert.pem'
00[DMN] creds: loaded ECDSA key from '/etc/swanctl/ecdsa/serverKey.pem'
00[DMN] creds: loaded eap secret 'eap-jane'
00[DMN] creds: loaded eap secret 'eap-hacker'
00[DMN] executing start script 'conns' (swanctl --load-conns)
08[CFG] added vici connection: tnc
00[DMN] conns: loaded connection 'tnc'
00[DMN] conns: successfully loaded 1 connections, 0 unloaded
00[DMN] executing start script 'pools' (swanctl --load-pools)
10[CFG] added vici pool rw_pool: 10.3.0.0, 254 entries
00[DMN] pools: loaded pool 'rw_pool'
00[DMN] pools: successfully loaded 1 pools, 0 unloaded
```
And in a third console window we open a `bash`shell to start and manage the strongSwan `charon` daemon in the `tnc-client` container
```console
client$ docker exec -ti tnc-client /bin/bash
client# ./charon &
00[DMN] Starting IKE charon daemon (strongSwan 5.9.8, Linux 5.15.0-48-generic, x86_64)
00[LIB] providers loaded by OpenSSL: legacy default
00[TNC] loading IMCs from '/etc/tnc_config'
00[TNC] added IETF attributes
00[TNC] added ITA-HSR attributes
00[TNC] added PWG attributes
00[TNC] added TCG attributes
00[LIB] libimcv initialized
00[IMC] IMC 1 "OS" initialized
00[IMC] processing "/etc/os-release" file
00[IMC] operating system type is 'Ubuntu'
00[IMC] operating system name is 'Ubuntu'
00[IMC] operating system version is '22.04 x86_64'
00[TNC] IMC 1 supports 1 message type: 'IETF/Operating System' 0x000000/0x00000001
00[TNC] IMC 1 "OS" loaded from '/usr/lib/ipsec/imcvs/imc-os.so'
00[IMC] IMC 2 "Scanner" initialized
00[TNC] IMC 2 supports 1 message type: 'IETF/Firewall' 0x000000/0x00000005
00[TNC] IMC 2 "Scanner" loaded from '/usr/lib/ipsec/imcvs/imc-scanner.so'
```
The `OS` and `Scanner` Integrity Measurement Collectors (`IMCs`) are loaded since
they have been enabled in `/etc/tnc_config`.
```console
00[LIB] loaded plugins: charon random nonce x509 constraints pubkey pem openssl curl sqlite kernel-netlink resolve socket-default vici updown eap-identity eap-md5 eap-ttls eap-tnc tnc-imc tnc-tnccs tnccs-20
00[JOB] spawning 16 worker threads
00[DMN] executing start script 'creds' (swanctl --load-creds)
15[CFG] loaded certificate 'C=CH, O=Cyber, CN=client.strongswan.org'
08[CFG] loaded certificate 'C=CH, O=Cyber, CN=Cyber Root CA'
12[CFG] loaded ECDSA private key
01[CFG] loaded EAP shared key with id 'eap-hacker' for: 'hacker'
00[DMN] creds: loaded certificate from '/etc/swanctl/x509/clientCert.pem'
00[DMN] creds: loaded certificate from '/etc/swanctl/x509ca/caCert.pem'
00[DMN] creds: loaded ECDSA key from '/etc/swanctl/ecdsa/clientKey.pem'
00[DMN] creds: loaded eap secret 'eap-hacker'
00[DMN] executing start script 'conns' (swanctl --load-conns)
01[CFG] added vici connection: tnc
00[DMN] conns: loaded connection 'tnc'
00[DMN] conns: successfully loaded 1 connections, 0 unloaded
```
The setup defines the EAP-TTLS-based configuration `tnc` .
```console
client# swanctl --list-conns
```
```console
tnc: IKEv2, no reauthentication, rekeying every 14400s
  local:  %any
  remote: 192.168.0.2
  local EAP_TTLS authentication:
    eap_id: client.strongswan.org
  remote EAP_TTLS authentication:
    id: server.strongswan.org
  tnc: TUNNEL, rekeying every 3600s
    local:  dynamic
    remote: 10.1.0.0/16 192.168.0.2/32

```

Author:  [Andreas Steffen][AS] [CC BY 4.0][CC]

[AS]: mailto:andreas.steffen@strongsec.net
[CC]: http://creativecommons.org/licenses/by/4.0/

