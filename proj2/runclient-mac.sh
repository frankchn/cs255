#!/bin/bash
export CLASSPATH="${CLASSPATH}:.:iaik_jce.jar:bcprov-jdk15on-148.jar"
java mitm.MITMAdminClientMAC -password cs255MACpassword -cmd stats