# strongswan

## Build Docker Image <a name="section1"></a>

In the `strongswan` directory the docker image can be built with
```console
$ docker build -t strongx509/strongswan .
```
The build rules are defined in [Dockerfile](Dockerfile).

## Create Docker Containers and Local Networks <a name="section2"></a>

The two docker containers `vpn-server` and  `vpn-client` as well as the local networks `strongswan_internet` and `strongswan_intranet` are created with the command
```console
$ docker-compose up
```
with the setup defined in [docker-compose.yml](docker-compose.yml).

In an additional console window we open a `bash` shell to administer the `vpn-server` container
```console
server$ docker exec -ti vpn-server /bin/bash
```
And  in a third console window we open a `bash`shell to administer the `vpn-client` container
```console
client$ docker exec -ti vpn-client /bin/bash
```

Author:  [Andreas Steffen][AS] [CC BY 4.0][CC]

[AS]: mailto:andreas.steffen@strongsec.net
[CC]: http://creativecommons.org/licenses/by/4.0/

