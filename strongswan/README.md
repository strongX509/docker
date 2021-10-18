# strongswan

Build and run a [strongSwan][STRONGSWAN]  IKEv2 Daemon with a Versatile IKE Control Interface (VICI).

[STRONGSWAN]: https://www.strongswan.org

## Pull Docker Image

```
$ docker pull strongx509/strongswan
```

## Build Docker Image

Alternatively the docker image can be built from scratch in the `strongswan` directory with
```console
$ docker build -t strongx509/strongswan .
```
The build rules are defined in [Dockerfile](Dockerfile).

## Create Docker Containers and Local Networks


```
               +------------+                        +------------+
  10.3.0.1 --- | VPN Client | === 192.168.0.0/24 === | VPN Server | --- 10.1.0.0/16 
 Virtual IP    +------------+ .3     Internet     .2 +------------+ .2    Intranet
```
The two docker containers `vpn-server` and  `vpn-client` as well as the local networks `strongswan_internet` and `strongswan_intranet` are created with the command
```console
$ docker-compose up
Creating vpn-server ... done
Creating vpn-client ... done
Attaching to vpn-server, vpn-client

```
with the setup defined in [docker-compose.yml](docker-compose.yml).

In an additional console window we open a `bash` shell to start and manage the strongSwan `charon` daemon in the `vpn-server` container
```console
server$ docker exec -ti vpn-server /bin/bash
server# ./charon &
00[DMN] Starting IKE charon daemon (strongSwan 5.9.4, Linux 5.11.0-37-generic, x86_64)
00[LIB] loaded plugins: charon random nonce x509 constraints pubkey pkcs1 pkcs8 pkcs12 pem openssl drbg kernel-netlink resolve socket-default vici updown eap-identity eap-md5 eap-dynamic eap-tls
00[JOB] spawning 16 worker threads
00[DMN] executing start script 'creds' (swanctl --load-creds)
15[CFG] loaded certificate 'C=CH, O=Cyber, CN=server.strongswan.org'
07[CFG] loaded certificate 'C=CH, O=Cyber, CN=Cyber Root CA'
12[CFG] loaded ECDSA private key
08[CFG] loaded IKE shared key with id 'ike-jane' for: 'jane@strongswan.org'
13[CFG] loaded IKE shared key with id 'ike-hacker' for: 'hacker@strongswan.org'
08[CFG] loaded EAP shared key with id 'eap-jane' for: 'jane'
11[CFG] loaded EAP shared key with id 'eap-hacker' for: 'hacker'
00[DMN] creds: loaded certificate from '/etc/swanctl/x509/serverCert.pem'
00[DMN] creds: loaded certificate from '/etc/swanctl/x509ca/caCert.pem'
00[DMN] creds: loaded ecdsa key from '/etc/swanctl/ecdsa/serverKey.pem'
00[DMN] creds: loaded ike secret 'ike-jane'
00[DMN] creds: loaded ike secret 'ike-hacker'
00[DMN] creds: loaded eap secret 'eap-jane'
00[DMN] creds: loaded eap secret 'eap-hacker'
00[DMN] executing start script 'conns' (swanctl --load-conns)
13[CFG] added vici connection: rw
16[CFG] added vici connection: psk
09[CFG] added vici connection: eap
00[DMN] conns: loaded connection 'rw'
00[DMN] conns: loaded connection 'psk'
00[DMN] conns: loaded connection 'eap'
00[DMN] conns: successfully loaded 3 connections, 0 unloaded
00[DMN] executing start script 'pools' (swanctl --load-pools)
07[CFG] added vici pool rw_pool: 10.3.0.0, 254 entries
00[DMN] pools: loaded pool 'rw_pool'
00[DMN] pools: successfully loaded 1 pools, 0 unloaded
```
And in a third console window we open a `bash`shell to start and manage the strongSwan `charon` daemon in the `vpn-client` container
```console
client$ docker exec -ti vpn-client /bin/bash
client# ./charon &
00[DMN] Starting IKE charon daemon (strongSwan 5.9.4, Linux 5.11.0-37-generic, x86_64)
00[LIB] loaded plugins: charon random nonce x509 constraints pubkey pkcs1 pkcs8 pkcs12 pem openssl drbg kernel-netlink resolve socket-default vici updown eap-identity eap-md5 eap-dynamic eap-tls
00[JOB] spawning 16 worker threads
00[DMN] executing start script 'creds' (swanctl --load-creds)
01[CFG] loaded certificate 'C=CH, O=Cyber, CN=client.strongswan.org'
08[CFG] loaded certificate 'C=CH, O=Cyber, CN=Cyber Root CA'
11[CFG] loaded ECDSA private key
01[CFG] loaded IKE shared key with id 'ike-hacker' for: 'hacker@strongswan.org'
07[CFG] loaded EAP shared key with id 'eap-hacker' for: 'hacker'
00[DMN] creds: loaded certificate from '/etc/swanctl/x509/clientCert.pem'
00[DMN] creds: loaded certificate from '/etc/swanctl/x509ca/caCert.pem'
00[DMN] creds: loaded ecdsa key from '/etc/swanctl/ecdsa/clientKey.pem'
00[DMN] creds: loaded ike secret 'ike-hacker'
00[DMN] creds: loaded eap secret 'eap-hacker'
00[DMN] executing start script 'conns' (swanctl --load-conns)
07[CFG] added vici connection: home
12[CFG] added vici connection: psk
05[CFG] added vici connection: eap
00[DMN] conns: loaded connection 'home'
00[DMN] conns: loaded connection 'psk'
00[DMN] conns: loaded connection 'eap'
00[DMN] conns: loaded connection 'eap-tls'
00[DMN] conns: successfully loaded 4 connections, 0 unloaded
00[DMN] executing start script 'pools' (swanctl --load-pools)
no pools found, 0 unloaded
```
The setup defines four VPN configurations `home`, `psk`, `eap` and `eap-tls` based on *X.509 certificates*,  *pre-shared keys*, *EAP MD5* and *EAP TLS*, respectively.
```console
client# swanctl --list-conns
```
```console
home: IKEv2, no reauthentication, rekeying every 14400s, dpd delay 60s
  local:  %any
  remote: 192.168.0.2
  local public key authentication:
    id: client.strongswan.org
    certs: C=CH, O=Cyber, CN=client.strongswan.org
  remote public key authentication:
    id: server.strongswan.org
  net: TUNNEL, rekeying every 3600s, dpd action is hold
    local:  dynamic
    remote: 10.1.0.0/16
  host: TUNNEL, rekeying every 3600s, dpd action is hold
    local:  dynamic
    remote: dynamic
```
```console
psk: IKEv2, no reauthentication, rekeying every 14400s, dpd delay 60s
  local:  %any
  remote: 192.168.0.2
  local pre-shared key authentication:
    id: hacker@strongswan.org
  remote pre-shared key authentication:
    id: server.strongswan.org
  psk: TUNNEL, rekeying every 3600s, dpd action is hold
    local:  dynamic
    remote: 10.1.0.0/16
```
```console
eap: IKEv2, no reauthentication, rekeying every 14400s, dpd delay 60s
  local:  %any
  remote: 192.168.0.2
  local EAP_MD5 authentication:
    eap_id: hacker
  remote public key authentication:
    id: server.strongswan.org
  eap: TUNNEL, rekeying every 3600s, dpd action is hold
    local:  dynamic
    remote: 10.1.0.0/16 192.168.0.2/32
```
```console
eap-tls: IKEv2, no reauthentication, rekeying every 14400s, dpd delay 60s
  local:  %any
  remote: 192.168.0.2
  local EAP_TLS authentication:
    eap_id: client.strongswan.org
  remote public key authentication:
    id: server.strongswan.org
  eap-tls: TUNNEL, rekeying every 3600s, dpd action is hold
    local:  dynamic
    remote: 10.1.0.0/16 192.168.0.2/32
```

Author:  [Andreas Steffen][AS] [CC BY 4.0][CC]

[AS]: mailto:andreas.steffen@strongsec.net
[CC]: http://creativecommons.org/licenses/by/4.0/

