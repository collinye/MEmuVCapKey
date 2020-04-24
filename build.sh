#!/bin/bash
export CXX=x86_64-w64-mingw32-g++ 
export AR=x86_64-w64-mingw32-ar
#export CXX=g++
#export AR=AR
$CXX MEmuVCapKey.cpp -c -o MEmuVCapKey.o
$AR -rcs libMEmuVCapKey.a MEmuVCapKey.o
