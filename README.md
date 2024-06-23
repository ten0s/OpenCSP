## Make

[[OpenSSL STB]]

```
$ cd src
$ make
$ make wine-install
```

```
$ cd PATH/TO/drafts/ms-capi
$ export LD_LIBRARY_PATH=~/projects/bee/install/lib
$ export WINEDEBUG=fixme-all
```

```
$ wine create-rand -t 333
1583e53f38
$ wine create-rand -t 333 -s 16
d6aab1f0c2f2ae8a7ff64f0356ec07e2
```

```
$ wine enum-provider-algs.exe -t 333
```

Hash

```
$ echo -n HELLO | wine create-hash -t 333 -a 0x8003
eb61eead90e3b899c6bcbe27ac581660

$ echo -n HELLO | wine create-hash -t 333 -a 0x800c
3733cd977ff8eb18b987357e22ced99f46097f31ecb239e878ae637620000000

$ echo -n HELLO | wine create-hash -t 333 -a 0x8021
628d78193859861a63c8bf2eba3a37d0d8cb3b4617c371e33f07879c20000000

$ echo -n HELLO | wine create-hash -t 333 -a 0x8033
497bc3d653353a4b45885bc922dc3f7b483416447ade3931e86c22a120000000
```
