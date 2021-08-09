package padding

import (
	"bytes"
	"errors"
	"io"
)

// PKCS7PaddingReader 符合PKCS#7填充的输入流
type PKCS7PaddingReader struct {
	fIn       io.Reader
	padding   io.Reader
	blockSize int
	readed    int64
	eof       bool
	eop       bool
}

// NewPKCS7PaddingReader 创建PKCS7填充Reader
// in: 输入流
// blockSize: 分块大小
func NewPKCS7PaddingReader(in io.Reader, blockSize int) *PKCS7PaddingReader {
	return &PKCS7PaddingReader{
		fIn:       in,
		padding:   nil,
		eof:       false,
		eop:       false,
		blockSize: blockSize,
	}
}

func (p *PKCS7PaddingReader) Read(buf []byte) (int, error) {
	/*
		- 读取文件
			- 文件长度充足， 直接返还
			- 不充足
		- 读取到 n 字节， 剩余需要 m 字节
		- 从 padding 中读取然后追加到 buff
			- EOF  直接返回， 整个Reader end
	*/
	// 都读取完了
	if p.eof && p.eop {
		return 0, io.EOF
	}

	var n, off = 0, 0
	var err error
	if !p.eof {
		// 读取文件
		n, err = p.fIn.Read(buf)
		if err != nil && !errors.Is(err, io.EOF) {
			// 错误返回
			return 0, err
		}
		p.readed += int64(n)
		if errors.Is(err, io.EOF) {
			// 标志文件结束
			p.eof = true
		}
		if n == len(buf) {
			// 长度足够直接返回
			return n, nil
		}
		// 文件长度已经不足，根据已经已经读取的长度创建Padding
		p.newPadding()
		// 长度不足向Padding中索要
		off = n
	}

	if !p.eop {
		// 读取流
		var n2 = 0
		n2, err = p.padding.Read(buf[off:])
		n += n2
		if errors.Is(err, io.EOF) {
			p.eop = true
		}
	}
	return n, err
}

// 新建Padding
func (p *PKCS7PaddingReader) newPadding() {
	if p.padding != nil {
		return
	}
	size := p.blockSize - int(p.readed%int64(p.blockSize))
	padding := bytes.Repeat([]byte{byte(size)}, size)
	p.padding = bytes.NewReader(padding)
}

// PKCS7PaddingWriter 符合PKCS#7去除的输入流，最后一个 分组根据会根据填充情况去除填充。
type PKCS7PaddingWriter struct {
	cache     *bytes.Buffer // 缓存区
	swap      []byte        // 临时交换区
	out       io.Writer     // 输出位置
	blockSize int           // 分块大小
}

// NewPKCS7PaddingWriter PKCS#7 填充Writer 可以去除填充
func NewPKCS7PaddingWriter(out io.Writer, blockSize int) *PKCS7PaddingWriter {
	cache := bytes.NewBuffer(make([]byte, 0, 1024))
	swap := make([]byte, 1024)
	return &PKCS7PaddingWriter{out: out, blockSize: blockSize, cache: cache, swap: swap}
}

// Write 保留一个填充大小的数据，其余全部写入输出中
func (p *PKCS7PaddingWriter) Write(buff []byte) (n int, err error) {
	// 写入缓存
	n, err = p.cache.Write(buff)
	if err != nil {
		return 0, err
	}
	if p.cache.Len() > p.blockSize {
		// 把超过一个分组长度的部分读取出来，写入到实际的out中
		size := p.cache.Len() - p.blockSize
		_, _ = p.cache.Read(p.swap[:size])
		_, err = p.out.Write(p.swap[:size])
		if err != nil {
			return 0, err
		}
	}
	return n, err

}

// Final 去除填充写入最后一个分块
func (p *PKCS7PaddingWriter) Final() error {
	// 在Write 之后 cache 只会保留一个Block长度数据
	b := p.cache.Bytes()
	length := len(b)
	if length != p.blockSize {
		return errors.New("非法的PKCS7填充")
	}
	if length == 0 {
		return nil
	}
	unpadding := int(b[length-1])
	if unpadding > p.blockSize || unpadding == 0 {
		return errors.New("非法的PKCS7填充")
	}
	_, err := p.out.Write(b[:(length - unpadding)])
	return err
}
