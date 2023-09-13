package signer

import baseError "github.com/go-tron/base-error"

var (
	ErrorEncoding = baseError.System("1300", "encode error")
	ErrorPresent  = baseError.New("1301", "sign not present")
	ErrorVerify   = baseError.New("1303", "sign verify failed")
)
