/* +build cgo */

package gmssl

/*
#cgo CFLAGS: -I/usr/include
#cgo LDFLAGS: -L/usr/local/ssl/lib/ -lcrypto
*/
import "C"
