package padding

import (
	"bytes"
	"io"
	"testing"
)

// 测试P7填充Reader
func TestPaddingFileReader_Read(t *testing.T) {
	srcIn := bytes.NewBuffer(bytes.Repeat([]byte{'A'}, 16))
	p := NewPKCS7PaddingReader(srcIn, 16)

	tests := []struct {
		name    string
		buf     []byte
		want    int
		wantErr error
	}{
		{"读取文件 1B", make([]byte, 1), 1, nil},
		{"交叉读取 15B 文件 1B", make([]byte, 16), 16, nil},
		{"填充读取 3B", make([]byte, 3), 3, nil},
		{"超过填充读取 16B", make([]byte, 16), 12, nil},
		{"文件结束 16B", make([]byte, 16), 0, io.EOF},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := p.Read(tt.buf)
			if err != tt.wantErr {
				t.Errorf("Read() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Read() 读取到了 = %v, 但是需要 %v", got, tt.want)
			}
		})
	}
}

// 测试P7填充Writer
func TestPKCS7PaddingWriter_Write(t *testing.T) {
	src := []byte{
		0, 1, 2, 3, 4, 5, 6, 7,
	}
	paddedSrc := append(src, bytes.Repeat([]byte{0x08}, 8)...)
	reader := bytes.NewReader(paddedSrc)
	out := bytes.NewBuffer(make([]byte, 0, 64))
	writer := NewPKCS7PaddingWriter(out, 8)

	for {
		buf := make([]byte, 3)
		n, err := reader.Read(buf)
		if err != nil && err != io.EOF {
			t.Fatal(err)
		}
		if n == 0 {
			break
		}
		_, err = writer.Write(buf[:n])
		if err != nil {
			t.Fatal(err)
		}
	}
	err := writer.Final()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(out.Bytes(), src) {
		t.Fatalf("去除填充后实际为 %02X,期待去除填充之后的结果为 %02X", out.Bytes(), src)
	}
}
