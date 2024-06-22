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
$ wine create-rand -t 333
1583e53f38
$ wine create-rand -t 333 -s 16
d6aab1f0c2f2ae8a7ff64f0356ec07e2
```
