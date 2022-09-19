We implement the efficient online-friendly two-party ECDSA signature of https://eprint.iacr.org/2022/318.pdf based on the library of Coinbase. And our contribution is in this subdirectory [pkg/tecdsa/2ecdsa](pkg/tecdsa/2ecdsa). Note that we split the signing process into two phases: the offline-sign phase and the online-sign phase.

## Direct Deployment 

### Specifications

- OS: Linux x64

- Language: go1.19 linux/amd64

- Requires: OpenSSL

- The default elliptic curve is "secp256k1"

### Installation

The current implementation is based on OpenSSL library. See the installment instructions of OpenSSL as below:  

1. Clone the code [openssl-master](https://github.com/openssl/openssl.git)

```
    git clone https://github.com/openssl/openssl.git
```

2. install openssl on your machine

```
    ./config --prefix=/usr/local/ssl shared
    make 
    sudo make install
    export OPENSSL_ROOT_DIR=/usr/local/ssl/
```
### OT-based 2-party ECDSA Benchmark

Run the benchmark of the system, you can 

1. Run the key generation benchmark for the OT-based 2-party ECDSA 

```
    go test -benchmem -run=^$ -bench ^BenchmarkDkgOT$ github.com/coinbase/kryptology/pkg/tecdsa/2ecdsa/dkg
```
2. Run the offline-sign benchmark for the OT-based 2-party ECDSA 

```
    go test -benchmem -run=^$ -bench ^BenchmarkOfflineOT$ github.com/coinbase/kryptology/pkg/tecdsa/2ecdsa/sign_offline
```

3. Run the online-sign benchmark for the OT-based 2-party ECDSA 

```
    go test -benchmem -run=^$ -bench ^BenchmarkOnlineOT$ github.com/coinbase/kryptology/pkg/tecdsa/2ecdsa/sign_online
```

### Paillier-based 2-party ECDSA Benchmark

Run the benchmark of the system, you can 

1. Run the key generation benchmark for the Paillier-based 2-party ECDSA 

```
    go test -benchmem -run=^$ -bench ^BenchmarkDkgPaillier$ github.com/coinbase/kryptology/pkg/tecdsa/2ecdsa/dkg
```
2. Run the offline-sign benchmark for the Paillier-based 2-party ECDSA 

```
    go test -benchmem -run=^$ -bench ^BenchmarkOfflinePaillier$ github.com/coinbase/kryptology/pkg/tecdsa/2ecdsa/sign_offline
```

3. Run the online-sign benchmark for the Paillier-based 2-party ECDSA 

```
    go test -benchmem -run=^$ -bench ^BenchmarkOnlinePaillier$ github.com/coinbase/kryptology/pkg/tecdsa/2ecdsa/sign_online
```
