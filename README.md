## Our Contribution

Our two solutions CRT-SM2 and Onion-SM2 place at the path pkg/tsm2.

## Environment

1. iMac 24-inch, Apple M1, 16 GB RA, running macOS Ventura 13.3.1
2. Install Go1.19 or Go1.19+. Official guideline (https://go.dev/doc/install)

## Test for CRT-SM2
1. Benchmark key generation 
```
go test -benchmem -run=^$ -bench ^BenchmarkDKGPaillier$ github.com/coinbase/kryptology/pkg/tsm2/crtsm2/scheme
```
1. Benchmark signing
```
go test -benchmem -run=^$ -bench ^BenchmarkDSPaillier$ github.com/coinbase/kryptology/pkg/tsm2/crtsm2/scheme
```

## Test for Onion-SM2
1. Benchmark key generation 
```
go test -benchmem -run=^$ -bench ^BenchmarkDKG$ github.com/coinbase/kryptology/pkg/tsm2/cetsm2/scheme
```
1. Benchmark signing
```
go test -benchmem -run=^$ -bench ^BenchmarkDS$ github.com/coinbase/kryptology/pkg/tsm2/cetsm2/scheme
```