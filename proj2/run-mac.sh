#!/bin/bash
make clean
make
export CLASSPATH="${CLASSPATH}:.:iaik_jce.jar:bcprov-jdk15on-148.jar"
java mitm.MITMProxyServer -keyStore keystore -keyStorePassword cs255test -pwdFile pwdfileMAC -keyStoreAlias mykey -useMAC
