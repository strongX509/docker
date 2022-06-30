FROM rockylinux
MAINTAINER Andreas Steffen <andreas.steffen@strongswan.org>

RUN \
  # install packages
  dnf install -y epel-release && \
  dnf makecache --refresh && dnf install -y strongswan
  # Expose IKE and NAT-T ports
EXPOSE 500 4500
