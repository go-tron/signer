package signer

import baseError "github.com/go-estar/base-error"

var (
	ErrorEncoding = baseError.NewSystemCode("1300", "encode error")
	ErrorPresent  = baseError.NewCode("1301", "sign not present")
	ErrorVerify   = baseError.NewCode("1303", "sign verify failed")
)
