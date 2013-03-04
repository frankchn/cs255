#!/bin/bash
make clean
make
export CLASSPATH="${CLASSPATH}:.:iaik_jce.jar"
java mitm.MITMProxyServer -keyStore mykey -keyStorePassword cs255keystore -pwdFile pwdfile
