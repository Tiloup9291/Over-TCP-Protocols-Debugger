## Description
Over-TCP Protocols Debugger

The executable Listener of Over-TCP Protocols Debugger is a process server that operate over the TCP layer of the OSI model in command line.
The Listener will output data receive through the sockets stripped from the bottom OSI layer header to STDOUT.
The Listener can also take input from STDIN to send it to the open client socket.
The executable gives you the possibility to bind to an IPv4 or IPv6 address, if none is specify, it will bind to ANY.
You can also specify the port you wish to connect the process.
You have access to an help option and a usage option.
Finally, you can output the license.

The source used the most of the standard libraries, ANSI C compatible. 

## Installation

Here how to build main.c with gcc (developped with gcc v14.1.1):
```
gcc -Wall -flto -O2 -Wextra -Wall -Wpedantic -D_FORTIFY_SOURCE=2 -fdata-sections -ffunction-sections -Wl,-z,relro,-z,now -fsanitize=address -fPIE -pie -fstack-protector-strong -fcf-protection=full -mshstk  -c /path/to/main.c -o path/to/store/main.o
gcc  -o path/to/store/Listener path/to/get/main.o  -O2 -flto -s
```
Alternately, you can use the Makefile. Here are the available flags and their initial value :
```
CC=gcc
CFLAGS=-O2 -flto -s
LDFLAGS=-Wall -flto -O2 -Wextra -Wall -Wpedantic -D_FORTIFY_SOURCE=2 -fdata-sections -ffunction-sections -Wl,-z,relro,-z,now -fsanitize=address -fPIE -pie -fstack-protector-strong -fcf-protection=full -mshstk
PREFIX = /usr
EXEC_PREFIX = $(PREFIX)
BINDIR = $(EXEC_PREFIX)/bin
```
To build the object file and executable :
```
make or make all or make build or make Listener
```
To install (copy) the executable in a common binaries folder :
```
make install
```
To remove the object file :
```
make clean
```

## Usage

Example of usage:
Case of debugging a browser:
Lets state that you want to debug a browser client.
1. Start Listener:
```
./Listener -l 80 -b 127.0.0.1
```
2. Open your browser and type the address to: localhost/

3. Listener will output the receive HTTP request :
```
GET / HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
```
4. Test the browser protocol implementation by taping an HTTP response :
```
HTTP/1.1 200 OK^M^JContent-Length: 27^M^JConnection: close^M^J^M^J<html>Hello world!!!</html>
```
5. If the browser protocol is well implemented, your browser should show your response

6. Finally, with the result you can now debug and test your service.

Listener could works with any protocols over the TCP layer.
