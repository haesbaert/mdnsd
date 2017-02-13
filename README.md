# Introduction

This extends Christiano Haesbaert's [openmdns](https://github.com/haesbaert/mdnsd) suite of tools
with a new daemon, *mdnshosts*.
It listens to the local [mdnsd(8)](http://www.haesbaert.org/openmdns/mdnsd.8.html) and maintains the
system's */etc/hosts* based upon what it finds.

The original */etc/hosts* is safely backed up and restored on exit---don't worry.

I'll post more information here as I develop the tool.
