/*
Copyright Hyperledger-TWGC All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

                 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

writed by Zhiwei Yan, 2020 Oct
*/

package sm4

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)


func TestSM4GCM(t *testing.T){
	key := []byte("1234567890abcdef")
	data := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	IV :=make([]byte,BlockSize)
	testA:=[][]byte{ // the length of the A can be random
		[]byte{},
		[]byte{0x01, 0x23, 0x45, 0x67, 0x89},
		[]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
	}
	for _,A:=range testA{
		gcmMsg,T,err:=Sm4GCM(key,IV,data,A,true)
		if err !=nil{
			t.Errorf("sm4 enc error:%s", err)
		}
		fmt.Printf("gcmMsg = %x\n", gcmMsg)
		gcmDec,T_,err:=Sm4GCM(key,IV,gcmMsg,A,false)
		if err != nil{
			t.Errorf("sm4 dec error:%s", err)
		}
		fmt.Printf("gcmDec = %x\n", gcmDec)
		if bytes.Compare(T,T_)==0{
			fmt.Println("authentication successed")
		}
		//Failed Test : if we input the different A , that will be a falied result.
		A= []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd}
		gcmDec,T_,err=Sm4GCM(key,IV,gcmMsg,A ,false)
		if err != nil{
			t.Errorf("sm4 dec error:%s", err)
		}
		if bytes.Compare(T,T_)!=0{
			fmt.Println("authentication failed")
		}
	}

}

func TestGHASH(t *testing.T) {
	type args struct {
		hHex string
		aHex string
		cHex string
	}
	tests := []struct {
		name       string
		args       args
		wantOutHex string
	}{
		{
			name: "ok1",
			args: args{
				hHex: "66e94bd4ef8a2c3b884cfa59ca342b2e",
				aHex: "",
				cHex: "",
			},
			wantOutHex: "00000000000000000000000000000000",
		},
		{
			name: "ok2",
			args: args{
				hHex: "66e94bd4ef8a2c3b884cfa59ca342b2e",
				aHex: "",
				cHex: "0388dace60b6a392f328c2b971b2fe78",
			},
			wantOutHex: "f38cbb1ad69223dcc3457ae5b6b0f885",
		},
		{
			name: "ok3",
			args: args{
				hHex: "b83b533708bf535d0aa6e52980d53b78",
				aHex: "",
				cHex: "42831ec2217774244b7221b784d0d49c" +
					"e3aa212f2c02a4e035c17e2329aca12e" +
					"21d514b25466931c7d8f6a5aac84aa05" +
					"1ba30b396a0aac973d58e091473f5985",
			},
			wantOutHex: "7f1b32b81b820d02614f8895ac1d4eac",
		},
		{
			name: "ok4",
			args: args{
				hHex: "b83b533708bf535d0aa6e52980d53b78",
				aHex: "feedfacedeadbeeffeedfacedeadbeef" +
					"abaddad2",
				cHex: "42831ec2217774244b7221b784d0d49c" +
					"e3aa212f2c02a4e035c17e2329aca12e" +
					"21d514b25466931c7d8f6a5aac84aa05" +
					"1ba30b396a0aac973d58e091",
			},
			wantOutHex: "698e57f70e6ecc7fd9463b7260a9ae5f",
		},
		{
			name: "ok5",
			args: args{
				hHex: "b83b533708bf535d0aa6e52980d53b78",
				aHex: "feedfacedeadbeeffeedfacedeadbeef" +
					"abaddad2",
				cHex: "61353b4c2806934a777ff51fa22a4755" +
					"699b2a714fcdc6f83766e5f97b6c7423" +
					"73806900e49f24b22b097544d4896b42" +
					"4989b5e1ebac0f07c23f4598",
			},
			wantOutHex: "df586bb4c249b92cb6922877e444d37b",
		},
		{
			name: "ok6",
			args: args{
				hHex: "b83b533708bf535d0aa6e52980d53b78",
				aHex: "feedfacedeadbeeffeedfacedeadbeef" +
					"abaddad2",
				cHex: "8ce24998625615b603a033aca13fb894" +
					"be9112a5c3a211a8ba262a3cca7e2ca7" +
					"01e4a9a4fba43c90ccdcb281d48c7c6f" +
					"d62875d2aca417034c34aee5",
			},
			wantOutHex: "1c5afe9760d3932f3c9a878aac3dc3de",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := hex.DecodeString(tt.args.hHex)
			if err != nil {
				t.Errorf("GHash() error = %v, wrong h", err)
				return
			}
			a, err := hex.DecodeString(tt.args.aHex)
			if err != nil {
				t.Errorf("GHash() error = %v, wrong a", err)
				return
			}
			c, err := hex.DecodeString(tt.args.cHex)
			if err != nil {
				t.Errorf("GHash() error = %v, wrong c", err)
				return
			}
			gotOut := GHASH(h, a, c)
			gotOutStr := hex.EncodeToString(gotOut)
			if gotOutStr != tt.wantOutHex {
				t.Errorf("GHash() gotOut = %v, want %v", gotOutStr, tt.wantOutHex)
			}
		})
	}
}
