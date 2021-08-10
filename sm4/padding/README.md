# PCSK#7 填充读写流

直接使用分块加密，往往需要手动完成填充和去填充的过程。流程较为固定，但是比较繁琐，对于文件和流的处理，不是很友好。

PKCS#7填充和去除填充：

- `padding.PKCS7PaddingReader` 写入结束是添加填充
- `padding.PKCS7PaddingWriter` 读取时去除填充

封装的填充模式加密：

- `padding.P7BlockEnc`
- `padding.P7BlockDecrypt`

以上方法简化了，对文件和流类型的加密解密过程。

## 带填充的模式加密和解密

> 流：实现了 `io.Writer`、`io.Reader`接口的类型。

流的SM4分块CBC模式加密：

```go
func main() {
    src := bytes.Repeat([]byte{7}, 16)
    srcIn := bytes.NewBuffer(src)
    encOut := bytes.NewBuffer(make([]byte, 0, 1024))

    key := make([]byte, 16)
    iv := make([]byte, 16)
    _, _ = rand.Read(key)
    _, _ = rand.Read(iv)
    fmt.Printf("key: %02X\n", key)
    fmt.Printf("iv : %02X\n", iv)
    block, err := sm4.NewCipher(key)
    if err != nil {
        panic(err)
    }
    encrypter := cipher.NewCBCEncrypter(block, iv)
    // P7填充的CBC加密
    err = padding.P7BlockEnc(encrypter, srcIn, encOut)
    if err != nil {
        panic(err)
    }
    fmt.Printf("原文: %02X\n", src)
    fmt.Printf("加密: %02X\n", encOut.Bytes())
}
```

流的SM4分块CBC模式解密：

```go
func main() {
    /**
	key: 4C9CA3D17263F6F558D65ADB561465BD
	iv : 221908D1C4BD730BEB011319D1368E49
	原文: 07070707070707070707070707070707
	加密: 310CA2472DCE15CCC58E1BE69B876002F443556CCFB86B1BA0341B6BFBED4C1A
     */
	encOut := bytes.NewBuffer(make([]byte, 0, 1024))
	key,_ := hex.DecodeString("4C9CA3D17263F6F558D65ADB561465BD")
    iv,_ := hex.DecodeString("221908D1C4BD730BEB011319D1368E49")
    block, err := sm4.NewCipher(key)
    if err != nil {
        panic(err)
    }
    ciphertext, _ :=  hex.DecodeString("310CA2472DCE15CCC58E1BE69B876002F443556CCFB86B1BA0341B6BFBED4C1A")
    cipherReader := bytes.NewReader(ciphertext)
    decrypter := cipher.NewCBCDecrypter(block, iv)
    decOut := bytes.NewBuffer(make([]byte, 0, 1024))
    err = padding.P7BlockDecrypt(decrypter, ciphertext, decOut)
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("解密: %02X\n", decOut.Bytes())
}
```

## PKCS#7填充

见测试用例: [pkcs7_padding_io_test.go](./pkcs7_padding_io_test.go)
