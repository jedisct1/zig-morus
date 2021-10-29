# MORUS cipher for Zig

This is a Zig implementation of
[MORUS](https://competitions.cr.yp.to/round3/morusv2.pdf) (MORUS-1280-128)

MORUS is a fast authenticated cipher for platforms without hardware AES acceleration.

It performs especially well on WebAssembly compared to alternatives.

Its performance is comparable to AES-OCB, without using AES instructions.

Benchmark results on x86_64 (Macbook Pro, 2,4 GHz Core i9, single core):

```text
            morus:       5890 MiB/s
       aes128-ocb:       5824 MiB/s
```

Benchmark results for WebAssembly (WAVM)

```text
       aes128-gcm:        176 MiB/s
       aes128-ocb:        300 MiB/s
 xchacha8Poly1305:        319 MiB/s
       aegis-128l:        807 MiB/s
            rocca:        854 MiB/s
            morus:       3505 MiB/s
```

