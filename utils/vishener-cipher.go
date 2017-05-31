package utils

// EncodeWithVishener - encode the text using Vishener cipher
// with defined key
func EncodeWithVishener(text []byte, key []byte) ([]byte, error) {
	j := 0
	keyLen := len(key)
	textLen := len(text)
	encodedText := make([]byte, textLen)
	// use XOR for text and key
	for i := 0; i < textLen; i++ {
		if j > keyLen-1 {
			j = 0
		}
		encodedText[i] = text[i] ^ key[j]
		j++
	}
	return encodedText, nil
}
