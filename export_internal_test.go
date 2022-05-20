package paseto

// This file is only compiled during tests due to the _test suffix. It serves
// the purpose of exporting some internal functions, which are used in
// paseto_test.

type Packet = packet

var NewMessage = newMessage
var NewPacket = newPacket

var V2LocalDecrypt = v2LocalDecrypt
var V2LocalEncrypt = v2LocalEncrypt
var V2PublicVerify = v2PublicVerify
var V2PublicSign = v2PublicSign

var V3LocalDecrypt = v3LocalDecrypt
var V3LocalEncrypt = v3LocalEncrypt
var V3PublicVerify = v3PublicVerify
var V3PublicSign = v3PublicSign

var V4LocalDecrypt = v4LocalDecrypt
var V4LocalEncrypt = v4LocalEncrypt
var V4PublicVerify = v4PublicVerify
var V4PublicSign = v4PublicSign

func (m message) Encoded() string {
	return m.encoded()
}

func (p packet) Content() []byte {
	return p.content
}

func (p packet) Footer() []byte {
	return p.footer
}
