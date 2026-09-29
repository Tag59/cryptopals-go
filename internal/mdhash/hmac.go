package mdhash

// HMACSHA1 returns HMAC-SHA1(key, msg) as defined in RFC 2104:
//
//	H((K ^ opad) || H((K ^ ipad) || msg))
//
// The outer hash is keyed too, so resuming from the tag (length extension,
// challenge 29) yields nothing useful: the tag is the state of the outer
// hash, never of the one that saw the message.
func HMACSHA1(key, msg []byte) [SHA1Size]byte {
	if len(key) > BlockSize {
		k := SHA1(key)
		key = k[:]
	}
	var ipad, opad [BlockSize]byte
	copy(ipad[:], key)
	copy(opad[:], key)
	for i := range BlockSize {
		ipad[i] ^= 0x36
		opad[i] ^= 0x5c
	}
	inner := SHA1(append(ipad[:], msg...))
	return SHA1(append(opad[:], inner[:]...))
}
