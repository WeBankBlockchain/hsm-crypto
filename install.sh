#!/bin/bash
mkdir -p build
cd build
get_arch=`arch`
C="CentOS"
U="Ubuntu"
if [[ $get_arch =~ "x86_64" ]];then
    FILE_EXE=/etc/redhat-release
    if [ -f "$FILE_EXE" ];then
        if [[ `cat /etc/redhat-release` =~ $C ]];then
            cmake3 .. -DBUILD_SHARED_LIBS=off   
        fi
    fi
    cmake .. -DBUILD_SHARED_LIBS=off
elif [[ $get_arch =~ "aarch64" ]];then
    cmake .. -DBUILD_SHARED_LIBS=off
elif [[ $get_arch =~ "mips64" ]];then
    echo "this is mips64, not support yet"
else
    echo "${get_arch} not support yet"
fi
make
cd ..
mkdir -p include
mkdir -p include/sdf
cp hsm/CryptoProvider.h  include/
cp hsm/Common.h include/
cp hsm/gmt0018.h include/
cp hsm/sdf/SDFCryptoProvider.h  include/sdf/
mkdir -p lib
if [[ $get_arch =~ "x86_64" ]];then
    cp build/output/libsdf-crypto_x86.a lib/libsdf-crypto_x86.a
else
    cp build/output/libsdf-crypto_arm.a lib/libsdf-crypto_arm.a
fi