package secure

import "encoding/base64"

var strictRawBase64URL = base64.RawURLEncoding.Strict()

// DecodeCanonicalBase64URL accepts exactly one unpadded base64url spelling for
// a byte sequence. Rejecting equivalent aliases keeps signed and opaque tokens
// from having multiple wire representations.
func DecodeCanonicalBase64URL(value string) ([]byte, bool) {
	decoded, err := strictRawBase64URL.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, false
	}
	return decoded, true
}
