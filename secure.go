// Package secure exports secure encryption and decryption functions.
// It uses AES cyphers and HMAC from go libraries, and defines and uses PKCS#7 padding.
// Secure keys are created from a password with PBKDF2 and HKDF from the go crypto sub-repository.
// Some logic is based on go code examples from golang.org
//
// Cryptography is difficult to implement correctly.  My main body of knowledge came from the
// coursera.org class Cryptography I taught at Stanford by Dan Boneh.  This course emphasizes
// correctly applying cryptographic principals.  As of 2014 it is still being taught periodically
// and I highly recommend it.  Any errors or misunderstandings, of course, are solely my
// responsibility.

package secure

import (
	"bytes"
	"code.google.com/p/go.crypto/hkdf"
	"code.google.com/p/go.crypto/pbkdf2"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"math"
)

// This is the minimum number of iterations when Encrypt creates a masterkey from password.
// A random unsigned int < 32K will be added to it before key creation.  The sum must fit
// in an unsigned 32 bit integer.  These iterations are designed to make brute force key guessing
// unfeasible.  They cause a delay on both Encrypt and Decrypt of about a second on one core of a
// relatively fast i5 laptop.
const masterkeyGenBaseIterations = 250000

var errAuthFailure = fmt.Errorf("secure: Authentication failure")

// aesCBCEncrypt performs CBC Mode encryption with the AES cipher.
// The result ciphertext is preallocated because it is often embedded with other data.
// AES encryption is performed with full blocks. The input should be padded beforehand.
// The ciphertext can be created in place over the input data, but there must be one block
// in front of the ciphertext for the initialization vector (IV) that does not overwrite the
// input data (for example: input := ciphertext[aes.Blocksize:])
func aesCBCEncrypt(input []byte, key []byte, ciphertext []byte) error {

	if len(input)%aes.BlockSize != 0 {
		return fmt.Errorf("Encryption error: Input len %d is not a multiple of blocksize %d",
			len(input), aes.BlockSize)
	}

	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return fmt.Errorf("Encryption error: key len %d is not a valid AES key length",
			len(key))
	}

	if len(ciphertext) < aes.BlockSize+len(input) {
		return fmt.Errorf("Ciphertext destination has length %d but at least %d is required",
			len(ciphertext), aes.BlockSize+len(input))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	// iv points to the beginning of ciphertext, where the initialization
	// vector will be inserted
	iv := ciphertext[:aes.BlockSize]
	// Fill iv with random data (crypto/rand is cryptographically safe)
	// Security depends on iv not repeating.  Probability of repeat
	// (i.e. collision) is negligible (p < 2 ^ -32) if same key is not
	// used for more than 2^48 blocks.
	n, err := io.ReadFull(rand.Reader, iv)
	if err == nil && n != len(iv) {
		err = fmt.Errorf("IV data length is %d when %d is expected", n, len(iv))
	}
	if err != nil {
		return err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:aes.BlockSize+len(input)], input)

	return nil // Result returned in ciphertext parameter
}

// aesCBCDecrypt performs CBC Mode decryption with the AES cipher.
// Initialization vector iv must be at beginning of input.
// A valid input is a multiple of blocksize.  To avoid additional allocation,
// the plaintext can decrypted into the same memory as the input, keeping in mind
// that the output plaintext length is one aes.BlockSize less than the input length.
func aesCBCDecrypt(input []byte, key []byte, plaintext []byte) (err error) {

	if len(input)%aes.BlockSize != 0 {
		return fmt.Errorf("Decryption error: Input length %d is not a multiple of blocksize %d",
			len(input), aes.BlockSize)
	}

	if len(input) < aes.BlockSize {
		return fmt.Errorf("Decryption error: No room for iv in input length %d", len(input))
	}

	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return fmt.Errorf("Decryption error: key len %d is not a valid AES key length",
			len(key))
	}

	if len(plaintext) < len(input)-aes.BlockSize {
		return fmt.Errorf("Decryption error: plaintext length %d is insufficient for input length %d",
			len(plaintext), len(input))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	// iv is the first block
	iv := input[:aes.BlockSize]
	// ciphertext itself is the remainder of input
	ciphertext := input[aes.BlockSize:]

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	return nil
}

// pkcsPad implements PKCS#7 padding.  This padding ensures that there is a 1-1 relationship between
// messages and valid padded messages.
//
// PKCS#7 padding always adds at least 1 byte to the message.
// If the message is n bytes short of a multiple of the blocklength, the message is extended
// by n bytes that each have a binary byte value of n.  If the message is a multiple of the
// blocklength, a full block of bytes each containing the binary value of the blocklen is appended.
//
// To avoid copying the data the padding is done in place.  The data slice length should be at least
// unpaddedlen + blocklen - unpaddedlen % blocklen.  This means that if the last block in the unpadded
// data is incomplete there is space to complete it.  If the last block is complete there must be room for
// another block.
//
// I am not attempting to make this a constant time operation like its inverse.
// The timing only leaks the data (plaintext) length, which does not threaten secure encryption.
func pkcsPad(data []byte, unpaddedlen, blocklen int) error {

	if blocklen > math.MaxUint8 {
		return fmt.Errorf("Padding error: Blocklen %d exceeds maximum one byte unsigned integer",
			blocklen, math.MaxUint8)
	}

	if unpaddedlen > len(data) {
		return fmt.Errorf("Padding error: Unpadded length parameter %d exceeds data length %d",
			unpaddedlen, len(data))
	}

	padchars := blocklen - unpaddedlen%blocklen
	paddedlen := unpaddedlen + padchars

	if paddedlen > len(data) {
		return fmt.Errorf("Padding error: Padded data length %d will not fit in data length %d",
			paddedlen, len(data))
	}

	padchar := byte(padchars)
	padding := bytes.Repeat([]byte(string(padchar)), padchars)

	copy(data[unpaddedlen:], padding)

	return nil
}

// pkcsUnpad implements PKCS#7 un-padding.  If the padding is valid a valid value of 1 is returned.
// If the padding is invalid, valid is returned as 0.  Any unpaddeddata value should not be used
// if pcksUnpad determines the padding is invalid.  A logic error returns an error.  If you
// have not already authenticated the ciphertext, reporting a padding error, even through side channels
// (like timing), leaves you open to padding oracle attacks, so beware.
//
// I am implementing pkcsPad with constant time operations to forestall timing attacks that might
// be used to create a padding oracle. Since this package always authenticates first,
// timing and padding oracle attacks are ineffective because ciphertexts cannot be
// forged or manipulated with more than insignificant probability of success.
// In such a case constant time operation is unimportant, but constant timing may be important if this
// code is reused elsewhere.
func pkcsUnpad(data []byte, blocklen int) (valid int, unpaddeddata []byte, err error) {

	if blocklen > math.MaxUint8 {
		err = fmt.Errorf("Unpadding error: Blocklen %d exceeds maximum one byte unsigned integer",
			blocklen, math.MaxUint8)
		return
	}

	origlen := len(data)

	if origlen < blocklen {
		err = fmt.Errorf("Unpadding error: Data length %d is less than blocklen %d",
			origlen, blocklen)
		return
	}

	if origlen%blocklen != 0 {
		err = fmt.Errorf("Unpadding error: Data length %d is not a multiple of blocklen %d",
			origlen, blocklen)
		return
	}

	padchar := data[origlen-1]
	padcharlen := int(padchar)

	datalen := origlen - padcharlen

	valid = subtle.ConstantTimeLessOrEq(padcharlen, blocklen)

	for i := 1; i <= blocklen; i++ {
		// valid = (i > padcharlen || data[origlen-i] == padchar) && valid
		iLePadcharlen := subtle.ConstantTimeLessOrEq(i, padcharlen)
		isPadChar := subtle.ConstantTimeByteEq(data[origlen-i], padchar)
		stillvalid := subtle.ConstantTimeSelect(iLePadcharlen, isPadChar, 1)
		valid &= stillvalid
	}

	unpaddeddata = data[:datalen] // This data should not be used if invalid.
	// Returning it in any case simplifies constant timing
	return
}

// appendHMAC adds a message authentication code to end of data.
// The MAC is appended in place to make copying unnecessary.
// The data slice length must include space (32 bytes) for the MAC.
// data[:datalen] is the location of the input data to be MACed.
func appendHMAC(data []byte, datalen int, key []byte) error {
	if datalen > len(data) {
		return fmt.Errorf("HMAC error: Datalen %d exceeds length of data %d", datalen, len(data))
	}
	if datalen+32 > len(data) {
		return fmt.Errorf("HMAC error: Length of data %d is not sufficient to append MAC to datalen",
			len(data), datalen)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(data[:datalen])
	macdata := mac.Sum(nil)
	copy(data[datalen:], macdata)
	return nil
}

// checkHMAC verifies the message authentication code at the end of data
func checkHMAC(data []byte, key []byte) (unMACedData []byte, isValidMAC bool) {

	origlen := len(data)

	if origlen < sha256.Size {
		return nil, false
	}

	embeddedmac := data[origlen-sha256.Size:]
	embeddeddata := data[:origlen-sha256.Size]

	mac := hmac.New(sha256.New, key)
	mac.Write(embeddeddata)
	checkmac := mac.Sum(nil)

	// constant time compare of MAC so as not to leak position of first bad MAC byte
	if hmac.Equal(embeddedmac, checkmac) {
		return embeddeddata, true
	} else {
		return nil, false
	}
}

// deriveKey uses PBKDF2 to create a cryptographically secure master key from a user provided password
// and non-secret salt.  PBKDF2 uses many iterations that along with the random salt are designed to
// slow down password cracking attacks.
func deriveKey(password []byte, nonsecretsalt []byte, iterations int) (masterkey []byte) {
	return pbkdf2.Key(password, nonsecretsalt, iterations, 32, sha256.New)
}

// expandKey uses HKDF on SHA256 to create 256 bit random keys
// from cryptographically secure masterkey and salt.
func expandKey(masterkey []byte, nonsecretsalt []byte, count int) (keys [][]byte, err error) {

	hkdf := hkdf.New(sha256.New, masterkey, nonsecretsalt, []byte("Why not mix it up?"))

	// Generate keys
	keys = make([][]byte, count)
	for i := 0; i < count; i++ {
		keys[i] = make([]byte, 32)
		n, err := io.ReadFull(hkdf, keys[i])
		if err == nil && n != 32 {
			err = fmt.Errorf("expandKey: HKDF did not return 32 byte key. Len: %d\n", len(keys[i]))
		}
		if err != nil {
			return nil, err
		}
	}

	// Check for obvious leakage or non-randomness
	for i := 0; i < count; i++ {
		if bytes.Contains(keys[i], masterkey) {
			err = fmt.Errorf("expandKey: HKDF failed")
			return nil, err
		}
		for j := 0; j < i; j++ {
			if bytes.Equal(keys[i], keys[j]) {
				err = fmt.Errorf("expandKey: HKDF failed")
				return nil, err
			}
		}
	}

	return keys, nil
}

func IsAuthError(err error) bool {
	return err == errAuthFailure
}

// Encrypt performs authenticated encryption using master key derivation, key expansion and
// Encrypt-then-MAC.
func Encrypt(input []byte, password []byte) (output []byte, err error) {

	// Number of bytes in trailing partial block
	partialBlockLen := len(input) % aes.BlockSize

	paddedInputLen := len(input) + aes.BlockSize - partialBlockLen

	// Create output with space for iv, encrypted data the size of padded input,
	// the nonsecret salt for master key, unsigned 32 bit number of iterations,
	// the non-secret salt for key expansion and the MAC
	output = make([]byte, aes.BlockSize+paddedInputLen+32+32+4+32)

	// Place the input into the appropriate place in the output slice.
	// This allows the padding, encryption and hmac operations to take place directly in output array
	// saving additional copying and array allocations.
	paddedinput := output[aes.BlockSize : aes.BlockSize+paddedInputLen]
	copy(paddedinput, input)

	// Pad input in place
	err = pkcsPad(paddedinput, len(input), aes.BlockSize)
	if err != nil {
		return nil, err
	}

	// Make cryptographically random 256 bit nonsecret salt for master key derivation
	saltMasterKey := make([]byte, 32)
	randlen, err := io.ReadFull(rand.Reader, saltMasterKey)
	if err == nil && randlen != len(saltMasterKey) {
		err = fmt.Errorf("Master key salt read length %d is not expected length %d",
			randlen, len(saltMasterKey))
	}
	if err != nil {
		return nil, err
	}

	// Number of master key iterations is masterkeyGenBaseIterations + random integer 0-2^16-1
	// Read random bytes and convert to uint16 increment
	iterIncrementBytes := make([]byte, 2)
	randlen, err = io.ReadFull(rand.Reader, iterIncrementBytes)
	if err == nil && randlen != 2 {
		err = fmt.Errorf("Increment read length %d is not expected length %d",
			randlen, len(iterIncrementBytes))
	}
	if err != nil {
		return nil, err
	}
	var iterIncrement uint16
	buf := bytes.NewReader(iterIncrementBytes)
	err = binary.Read(buf, binary.LittleEndian, &iterIncrement)
	if err != nil {
		fmt.Errorf("Conversion of random to iteration increment failed:", err)
		return nil, err
	}
	// Calculate iterations and format as bytes
	iterations := uint32(masterkeyGenBaseIterations + int(iterIncrement))
	bufout := new(bytes.Buffer)
	err = binary.Write(bufout, binary.LittleEndian, iterations)
	if err == nil && bufout.Len() != 4 {
		err = fmt.Errorf("Iteration byte length %d is not expected length %d", bufout.Len(),
			len(iterIncrementBytes))
	}
	if err != nil {
		return nil, err
	}
	iterationsBytes := bufout.Bytes()

	// Derive cryptographically secure master key from password
	masterkey := deriveKey(password, saltMasterKey, int(iterations))

	// Make cryptographically random 256 bit nonsecret salt for key expansion
	saltExpandKey := make([]byte, 32)
	randlen, err = io.ReadFull(rand.Reader, saltExpandKey)
	if err == nil && randlen != len(saltExpandKey) {
		err = fmt.Errorf("Expand key salt read length %d is not expected length %d",
			randlen, len(saltExpandKey))
	}
	if err != nil {
		return nil, err
	}

	// Create two 256 bit random keys from masterkey
	keys, err := expandKey(masterkey, saltExpandKey, 2)
	if err != nil {
		return nil, err
	}
	key, mackey := keys[0], keys[1]

	// Ciphertext includes space for IV
	ciphertext := output[:aes.BlockSize+len(paddedinput)]

	// Perform encryption
	// Note that the ciphertext after the IV is colocated with the padded input.
	// This is allowed.
	err = aesCBCEncrypt(paddedinput, key, ciphertext)
	if err != nil {
		return nil, err
	}

	// Append salts and iteration count to ciphertext
	ciphertextAndSalts := output[:len(ciphertext)+len(saltMasterKey)+len(iterationsBytes)+len(saltExpandKey)]
	copy(ciphertextAndSalts[len(ciphertext):], saltMasterKey)
	copy(ciphertextAndSalts[len(ciphertext)+len(saltMasterKey):], iterationsBytes)
	copy(ciphertextAndSalts[len(ciphertext)+len(saltMasterKey)+len(iterationsBytes):], saltExpandKey)

	// MAC everything in place in output slice
	err = appendHMAC(output, len(ciphertextAndSalts), mackey)
	if err != nil {
		return nil, err
	}

	return output, nil
}

// Decrypt checks MAC and then decrypts authenticated ciphertext
func Decrypt(macedInput []byte, password []byte) ([]byte, error) {

	if len(macedInput) < 100 {
		err := fmt.Errorf("Input to Decrypt has length %d.  Expected length of 100 or more.",
			len(macedInput))
		return nil, err
	}

	// Extract salts and iteration count for master key derivation and key expansion
	saltMasterKey := macedInput[len(macedInput)-100 : len(macedInput)-68]
	iterationsBytes := macedInput[len(macedInput)-68 : len(macedInput)-64]
	var iterations uint32
	buf := bytes.NewReader(iterationsBytes)
	err := binary.Read(buf, binary.LittleEndian, &iterations)
	if err != nil {
		fmt.Errorf("Read of iterations failed:", err)
		return nil, err
	}
	saltExpandKey := macedInput[len(macedInput)-64 : len(macedInput)-32]

	// Derive cryptographically secure master key from password
	masterkey := deriveKey(password, saltMasterKey, int(iterations))

	// Create two 256 bit random keys from masterkey
	keys, err := expandKey(masterkey, saltExpandKey, 2)
	if err != nil {
		return nil, err
	}
	key, mackey := keys[0], keys[1]

	ciphertextAndSalts, ok := checkHMAC(macedInput, mackey)
	if !ok {
		err := errAuthFailure
		return nil, err
	}

	// Since aesCBCDecrypt operates in place and changes data, we need to allocate a
	// new buffer for ciphertext so the input slice is not changed.  We do this after
	// authentication to forestall denial of service attacks.
	paddedtext := make([]byte, len(ciphertextAndSalts)-32-4-32-aes.BlockSize)
	// copy(ciphertext, ciphertextAndSalts[:len(ciphertextAndSalts)-68])
	ciphertext := ciphertextAndSalts[:len(ciphertextAndSalts)-32-4-32]

	err = aesCBCDecrypt(ciphertext, key, paddedtext)
	if err != nil {
		return nil, err
	}

	valid, plaintext, err := pkcsUnpad(paddedtext, aes.BlockSize)

	if valid == 0 { // valid = int with 1=true 0=false, a convention that used with constant time
		// operations so that logical expressions can be evaluated with (constant time)
		// bit operations.  That aspect of pkcsUnpad is not needed here since ciphertext
		// has already been authenticated.
		return nil, fmt.Errorf("Invalid padding") // Since the ciphertext is already authenticated
		// it is ok to report a padding err.  This error should only
		// result from a program logic error.

	}
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
