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