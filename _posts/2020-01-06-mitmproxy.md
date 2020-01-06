---
title: 树莓派3B+刷openwrt安装mitmproxy折腾记录
date: 2020-01-06 00:00:00
categories:
- IOT
tags: 
---

> 折腾了三个晚上终于搞定了

```c
https://downloads.openwrt.org/releases/19.07.0-rc2/targets/brcm2708/bcm2710/openwrt-19.07.0-rc2-brcm2708-bcm2710-rpi-3-ext4-sysupgrade.img.gz

sudo dd if=openwrt-19.07.0-rc2-brcm2708-bcm2710-rpi-3-ext4-factory.img of=/dev/disk2 bs=1m
sudo umount /dev/disk2
sudo diskutil unmount /dev/disk2
sudo diskutil unmountDisk /dev/disk2

linux gpart调整分区
openwrt配网
ssh 登录

sed -i 's/downloads.openwrt.org/mirrors.tuna.tsinghua.edu.cn\/lede/g' /etc/opkg/distfeeds.conf
opkg update
opkg install bash git python3 gcc make python3-dev python3-pip python3-six python3-cffi python3-openssl python3-cryptography tcpdump curl wget redsocks nc
pip3 config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple

git clone git://github.com/mitmproxy/mitmproxy.git

export cc=gcc
cp /usr/bin/aarch64-openwrt-linux-musl-gcc /usr/bin/cc


cd mitmproxy/
sed -i 's/cryptography>=2.1.4,<2.5/cryptography>=2.1.4,<3.5/g' ./setup.py
sed -i 's/python3 -m venv venv/python3 -m venv venv --without-pip/g' ./dev.sh
sed -i 's/127.0.0.1/0.0.0.0/g' ./mitmproxy/tools/web/webaddons.py
wget https://raw.githubusercontent.com/python/cpython/3.7/Lib/webbrowser.py


./dev.sh
. venv/bin/activate
mitmweb

cd mitmproxy/ && . venv/bin/activate && mitmweb
```




