/*
Copyright Suzhou Tongji Fintech Research Institute 2017 All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

                 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sm4

import (
	"fmt"
	"log"
	"testing"
)

func TestSM4(t *testing.T) {
	data := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	WriteKeyToPem("key.pem", data, []byte("123"))
	key, err := ReadKeyFromPem("key.pem", []byte("123"))
	if err != nil {
		log.Fatal(err)
	}
	d0 := make([]byte, 16)
	EncryptBlock(key, d0, data)
	fmt.Printf("d0 = %x\n", d0)
	d1 := make([]byte, 16)
	DecryptBlock(key, d1, d0)
	fmt.Printf("d1 = %x\n", d1)
}
