apparecium
==========

Static Data Flow Tracking on Smali


Requirements:
---------------------
pydot: https://github.com/davidvilla/pydot

pyparsing-2.0.1: https://github.com/hachibeeDI/pyparsing/tree/master/

graphviz: http://www.graphviz.org/Download..php

install:
----------------------
on widows

1、pydot and pyparsing install

2、install graphviz

3、added this registry key to 64bit win7(for solve the problem of "GraphViz's executables not found on Windows 7 64-bit if user installs them in a custom directory")

[HKEY_LOCAL_MACHINE\SOFTWARE\ATT\Graphviz] "InstallPath"="C:\Program Files (x86)\Graphviz2.38"

Just change it based on your Graphviz installation directory.

you can see it at this page:https://code.google.com/p/pydot/issues/detail?id=65