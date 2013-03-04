#!/bin/bash
make clean
make
./setup.bash
java mitm.MITMProxyServer -keyStore mykey -keyStorePassword cs255keystore
