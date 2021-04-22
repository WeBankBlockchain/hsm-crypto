#!/bin/bash
mkdir build
cd build
cmake ..
make
cd ..
mkdir include
cp deps/src/libsdf/NF2180M3/kylin_v10/csmsds.h  include/
cp sdf/SDFCryptoProvider.h  include/
mkdir lib
cp build/sdf/libsdf-crypto_arm_static.a lib/libsdf-crypto_arm.a
cp build/bin/libsdf-crypto_arm.so lib/libsdf-crypto_arm.so 