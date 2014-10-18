#!/bin/sh
while(true)do
	myvar1=`netstat -tulpn | grep 8888`
	echo "$myvar1"
	sleep 3s
    clear
done
