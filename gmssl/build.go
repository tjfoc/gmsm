/* +build cgo */

package gmssl

/*
#cgo CFLAGS: -I/usr/include
#cgo LDFLAGS: -L/usr/local/lib/ -lcrypto
*/
import "C"
