FROM registry.access.redhat.com/ubi8/ubi-minimal:latest

RUN microdnf update -y && \
    microdnf install unzip file tar gzip && \
    rm -rf /var/cache/yum

WORKDIR /root

RUN mkdir -p .docker/machine/machines

COPY download_driver.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/download_driver.sh

RUN download_driver.sh "https://github.com/linode/docker-machine-driver-linode/releases/download/v0.1.8/docker-machine-driver-linode_linux-amd64.zip" "b31b6a504c59ee758d2dda83029fe4a85b3f5601e22dfa58700a5e6c8f450dc7"
RUN download_driver.sh "https://drivers.rancher.cn/node-driver-pinganyun/0.3.0/docker-machine-driver-pinganyunecs-linux.tgz" "f84ccec11c2c1970d76d30150916933efe8ca49fe4c422c8954fc37f71273bb5"
RUN download_driver.sh "https://github.com/cloud-ca/docker-machine-driver-cloudca/files/2446837/docker-machine-driver-cloudca_v2.0.0_linux-amd64.zip" "1757e2b807b0fea4a38eade4e961bcc609853986a44a99a4e86a37ccea1f7679"
RUN download_driver.sh "https://github.com/cloudscale-ch/docker-machine-driver-cloudscale/releases/download/v1.2.0/docker-machine-driver-cloudscale_v1.2.0_linux_amd64.tar.gz" "e33fbd6c2f87b1c470bcb653cc8aa50baf914a9d641a2f18f86a07c398cfb544"
RUN download_driver.sh "https://github.com/rancher-plugins/rancher-machine-driver-oci/releases/download/v1.0.1/docker-machine-driver-oci-linux" "6867f59e9f33bdbce34b5bf9476c48d2edc2ef4bca8a2ef82ccaa1de57af811c"
RUN download_driver.sh "https://github.com/rancher-plugins/docker-machine-driver-otc/releases/download/v2019.5.7/docker-machine-driver-otc" "a2cc921a64e6192d8036afdf07f13f0c8459fc4932d1cfb183efccfac7baea04"
RUN download_driver.sh "https://github.com/packethost/docker-machine-driver-packet/releases/download/v0.2.2/docker-machine-driver-packet_linux-amd64.zip" "e03c6bc9406c811e03e9bc2c39f43e6cc8c02d1615bd0e0b8ee1b38be6fe201c"
RUN download_driver.sh "https://github.com/phoenixnap/docker-machine-driver-pnap/releases/download/v0.1.0/docker-machine-driver-pnap_0.1.0_linux_amd64.zip" "5f25a7fbcaca0710b7290216464ca8433fa3d683b59d5e4e674bef2d0a3ff6c7"

COPY rancher-machine entrypoint.sh /usr/local/bin/

ENTRYPOINT ["entrypoint.sh"]
