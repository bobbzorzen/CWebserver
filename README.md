CWebserver
==========

A simple webserver in C written as a lab assignment in a UNIX programming course at BTH during the fall of 2014


##How to use?
 Compile using gcc
 run with sudo
 jail will be in /home/jail/webserver so you should put your www folder in there. 

##The commandFlags?
 * -p <port> - The port you wish the server to run on, if the default port(defined in .lab3-conf) is not wanted.
 * -l <logfile> - The file to log to. If exluded the server will use the syslog to log.
 * -d - This flag will turn the server program into a Daemon and print the Pid of the Daemon process.