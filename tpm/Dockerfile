FROM ubuntu:18.04
MAINTAINER Andreas Steffen <andreas.steffen@strongswan.org>
ENV TPM_VERSION="1637"
ENV TPM_TSS_VERSION="2.3.1"
ENV TPM_TOOLS_VERSION="3.2.0"
RUN \
  # install packages
  DEV_PACKAGES="wget make gcc g++ pkg-config libssl-dev libcurl4-openssl-dev" && \
  apt-get -y update && \
  apt-get -y install nano $DEV_PACKAGES && \
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
  ./configure --prefix=/usr --disable-tcti-device --disable-esapi --disable-doxygen-doc && \
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
  # clean up
  apt-get -y remove $DEV_PACKAGES && \
  apt-get -y autoremove && \
  apt-get clean && \
  rm -rf /var/lib/apt/lists/*
