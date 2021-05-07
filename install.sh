#!/bin/bash
mkdir build
cd build
cmake .. -DBUILD_SDF=on -DBUILD_SHARED_LIBS=off
make
cd ..
mkdir include
mkdir include/sdf
cp hsm/CryptoProvider.h  include/
cp hsm/Common.h include/
cp hsm/sdf/SDFCryptoProvider.h  include/sdf/
mkdir lib
cp build/output/libsdf-crypto_arm.a lib/libsdf-crypto_arm.a