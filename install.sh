#!/bin/bash
mkdir build
cd build
cmake .. -DBUILD_SDF=on -DBUILD_STATIC_LIB=on
make
cd ..
mkdir include
cp hsm/CryptoProvider.h  include/
cp hsm/sdf/SDFCryptoProvider.h  include/
mkdir lib
cp build/output/libsdf-crypto_arm.a lib/libsdf-crypto_arm.a