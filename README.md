## 支持通配符的内积加密(WIB-IPFE)方案实现（基于 PBC Library）
### 测试环境：Ubuntu 20.04 及以上
### Install PBC Library
```bash
wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
tar zxvf pbc-0.5.14.tar.gz
cd pbc
./configure
make
sudo make install
sudo ldconfig
```


### Build
```bash
cd WIB_IPFE
mkdir build && cd build
cmake ..
make
```

### Run
```bash
./IPFE_test_wib {n} {d} {sch} {name[4:]} 0 {level} {ITS} 0
```
