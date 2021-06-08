#!/bin/bash
mkdir -p build
cd build
cmake .. -DBUILD_SDF=on -DBUILD_SHARED_LIBS=off
cmake3 .. -DBUILD_SDF=on -DBUILD_SHARED_LIBS=off
make
cd ..
mkdir -p include
mkdir -p include/sdf
cp hsm/CryptoProvider.h  include/
cp hsm/Common.h include/
cp hsm/sdf/SDFCryptoProvider.h  include/sdf/
mkdir -p lib
cp build/output/libsdf-crypto_arm.a lib/libsdf-crypto_arm.a