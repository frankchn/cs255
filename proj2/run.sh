#!/bin/bash
make clean
make
export CLASSPATH="${CLASSPATH}:.:iaik_jce.jar"
java mitm.MITMProxyServer -keyStore keystore -keyStorePassword cs255test -pwdFile pwdfile -keyStoreAlias mykey 
