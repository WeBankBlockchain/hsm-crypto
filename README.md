# HSM-Crypto
HSM-Crypto是一个C++实现的硬件加密模块（Hardware secure module），能协助应用调用符合《GMT0018-2012密码设备通用接口规范》的PCI密码卡或者密码机进行国密算法SM2、SM3、SM4运算。

## 准备环境
请将实现了符合《GMT0018-2012密码设备通用接口规范》的头文件和库文件安装在了动态库默认的搜索路径中。
1. 确保头文件``gmt0018.h``在目录``/usr/include``中，并保证所有用户都有读权限。
2. 如果您使用的是Ubuntu操作系统，请将库文件``libgmt0018.so``放在默认的库搜索路径下，比如Ubuntu放在``/usr/lib``目录下，CentOS放在``/usr/lib64``下。保证用户具有读和执行权限。

## 编译
当您需要动态库时，请使用以下方法编译。
```bash
mkdir build
cd build
cmake .. -DBUILD_SHARED_LIBS=on -DBUILD_SDF=on 
make
```

当您需要静态库时，请使用以下方法编译。
```bash
mkdir build
cd build
cmake .. -DBUILD_SHARED_LIBS=off -DBUILD_SDF=on
make
```
## 运行测试

```bash
./output/test-sdf-crypto 10 100
# test-sdf-crypto [sessionPoolSize] [loopRound]
```
