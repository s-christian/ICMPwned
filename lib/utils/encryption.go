package utils

func XorEncryptDecryptBytes(input, key []byte) (output []byte) {
	for i, b := range input {
		output = append(output, b^key[i%len(key)])
	}

	return output
}
