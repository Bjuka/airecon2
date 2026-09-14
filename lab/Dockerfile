#airecon2 pentest lab - minimal Kali (lightweight) + WiFi/RF + web tooling
#Monitor mode works IF you pass a USB wifi adapter through (Docker Desktop: WSL usbipd).
FROM kalilinux/kali-rolling:latest

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      sudo \
      kali-tools-wireless \
      aircrack-ng \
      reaver \
      bully \
      hcxtools \
      hcxdumptool \
      wifite \
      nmap \
      masscan \
      sqlmap \
      nikto \
      hydra \
      tcpdump \
      tshark \
      netcat-openbsd \
      curl \
      wget \
      git \
      python3 \
      tcpdump \
      iproute2 \
      iw \
      wireless-tools \
      usbutils \
      kmod && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# non-root pentester with sudo
RUN useradd -m -s /bin/bash pentester && \
    usermod -aG sudo pentester && \
    echo "pentester ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/pentester

# long-running shell for exec
COPY labwrapper.sh /usr/local/bin/labwrapper.sh
RUN chmod +x /usr/local/bin/labwrapper.sh && \
    mkdir -p /workspace && chown pentester:pentester /workspace

WORKDIR /workspace
USER root
CMD ["/usr/local/bin/labwrapper.sh"]
