## 更新日志

1.0 更新:
- 添加以下oid<br>
    SM3WithSM2 1.2.156.10197.1.501<br>
    SHA1WithSM2 1.2.156.10197.1.502<br>
    SHA256WithSM2 1.2.156.10197.1.503<br>

- x509生成的证书如今可以使用SM3作为hash算法

- 引入了以下hash算法
    RIPEMD160<br>
    SHA3_256<br>
    SHA3_384<br>
    SHA3_512<br>
    SHA3_SM3<br>
  用户需要自己安装golang.org/x/crypto

1.0.1 更新:
- 添加全局的sbox改进sm4效率(by https://github.com/QwertyJack)

1.1.0更新:
- 改进新能，具体提升如下
&emsp;注:本次优化并不彻底，只是第一次尝试优化，后续有时间还会继续优化
```
    old:
        generate key:
            BenchmarkSM2-4          1000   2517147 ns/op 1156476 B/op   11273 allocs/op
        sign:
            BenchmarkSM2-4           300   6297498 ns/op 2321890 B/op   22653 allocs/op
        verify:
            BenchmarkSM2-4          2000   8557215 ns/op 3550626 B/op   34627 allocs/op
        encrypt:
            BenchmarkSM2-4          2000   8304840 ns/op 3483113 B/op   33967 allocs/op
        decrypt:
            BenchmarkSM2-4          2000   5726181 ns/op 2321728 B/op   22644 allocs/op
    new:
        generate key:
            BenchmarkSM2-4          5000    303656 ns/op    2791 B/op      41 allocs/op
        sign:
            BenchmarkSM2-4          2000    652465 ns/op    8828 B/op     133 allocs/op
        verify:
            BenchmarkSM2-4          1000   2004511 ns/op  122709 B/op    1738 allocs/op
        encrpyt:
            BenchmarkSM2-4          1000   1984419 ns/op  118560 B/op    1687 allocs/op
        decrypt:
            BenchmarkSM2-4          1000   1725001 ns/op  118331 B/op    1679 allocs/op
```

1.1.1更新
- 新增以下函数支持用户其他信息<br>
    SignDigitToSignData 将签名所得的大数r和s转换为签名的格式<br>
    Sm2Sign     支持用户信息的签名<br>
    Sm2Verify   支持用户信息的验签<br>
