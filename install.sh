#!/bin/bash
mkdir build
cd build
cmake .. -BUILD_SDF=on
make
cd ..
mkdir include
cp hsm/CryptoProvider.h  include/
cp hsm/sdf/SDFCryptoProvider.h  include/
mkdir lib
cp build/output/libsdf-crypto_arm.a lib/libsdf-crypto_arm.a
cp build/output/libsdf-crypto_arm.so lib/libsdf-crypto_arm.so 