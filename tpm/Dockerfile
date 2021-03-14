FROM ubuntu:20.04
MAINTAINER Andreas Steffen <andreas.steffen@strongswan.org>
ENV TPM_VERSION="1637"
ENV TPM_TSS_VERSION="3.0.3"
ENV TPM_TOOLS_VERSION="5.0"
ENV STRONGSWAN_VERSION="5.9.2"
ENV TZ=Europe/Zurich
RUN \
  # set timezone
  ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone && \
  # install packages
  DEV_PACKAGES="wget make gcc g++ pkg-config libssl-dev libcurl4-openssl-dev libjson-c-dev uuid-dev" && \
  apt-get -y update && \
  apt-get -y install nano libcurl4 $DEV_PACKAGES && \
  \
  # download and build IBM TPM 2.0 simulator 
  mkdir /tpm-build && \
  cd /tpm-build && \
  wget https://sourceforge.net/projects/ibmswtpm2/files/ibmtpm$TPM_VERSION.tar.gz && \
  tar xf ibmtpm$TPM_VERSION.tar.gz && \
  cd src && \
  make all && make install && \
  cd / && rm -R tpm-build && \
  \
  # download and build TPM 2.0 TSS stack
  mkdir /tpm_tss-build && \
  cd /tpm_tss-build && \
  wget https://github.com/tpm2-software/tpm2-tss/releases/download/$TPM_TSS_VERSION/tpm2-tss-$TPM_TSS_VERSION.tar.gz && \
  tar xf tpm2-tss-$TPM_TSS_VERSION.tar.gz && \
  cd tpm2-tss-$TPM_TSS_VERSION && \
  ./configure --prefix=/usr --with-crypto=ossl --with-tctidefaultmodule=libtss2-tcti-mssim.so \
              --disable-tcti-device --disable-fapi --disable-doxygen-doc && \
  make all && make install && \
  cd / &&  rm -r tpm_tss-build && \
  \
  # download and build TPM 2.0 Tools
  mkdir /tpm_tools-build && \
  cd /tpm_tools-build && \
  wget https://github.com/tpm2-software/tpm2-tools/releases/download/$TPM_TOOLS_VERSION/tpm2-tools-$TPM_TOOLS_VERSION.tar.gz && \
  tar xf tpm2-tools-$TPM_TOOLS_VERSION.tar.gz && \
  cd tpm2-tools-$TPM_TOOLS_VERSION && \
  ./configure --prefix=/usr && \
  make all && make install && \
  cd / &&  rm -r tpm_tools-build && \
  \
  # download and build strongSwan pki tool
  mkdir /pki-build && \
  cd /pki-build && \
  wget https://download.strongswan.org/strongswan-$STRONGSWAN_VERSION.tar.bz2 && \
  tar xf strongswan-$STRONGSWAN_VERSION.tar.bz2 && \
  cd strongswan-$STRONGSWAN_VERSION && \
  ./configure --prefix=/usr --sysconfdir=/etc --disable-defaults      \
    --enable-nonce --enable-openssl --enable-pkcs1 --enable-pkcs8     \
    --enable-pkcs12 --enable-pem --enable-x509 --enable-pubkey        \
    --enable-constraints --enable-pki --enable-tpm --enable-tss-tss2  \
    --enable-silent-rules  && \
  make all && make install && \
  cd / &&  rm -r pki-build && \
  \
  # clean up
  apt-get -y remove $DEV_PACKAGES && \
  apt-get -y autoremove && \
  apt-get clean && \
  rm -rf /var/lib/apt/lists/*
