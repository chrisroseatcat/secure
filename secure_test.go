package secure

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"testing"
)

func TestEncryptDecryptSimple(t *testing.T) {
	const msg1 = "The sage too is ruthless"
	const pw1 = "Low Places"

	msg := []byte(msg1)
	pw := []byte(pw1)
	msgCheck := []byte(msg1)
	pwCheck := []byte(pw1)

	ciphertext, err := Encrypt(msg, pw)

	// Verify msg, pw not changed
	if !bytes.Equal(msg, msgCheck) {
		t.Errorf("Encrypt changed input msg")
	}
	if !bytes.Equal(pw, pwCheck) {
		t.Errorf("Encrypt changed input password")
	}
	if err != nil {
		t.Fatalf("Encrypt returned error: %s", err)
	}

	ciphertextCheck := dupBytes(ciphertext)
	if !bytes.Equal(ciphertextCheck, ciphertext) {
		t.Fatalf("dupBytes failed")
	}
	decryptedMsg, err := Decrypt(ciphertext, pw)

	// Verify ciphertext, pw not changed
	if !bytes.Equal(ciphertext, ciphertextCheck) {
		t.Errorf("Decrypt changed input ciphertext")
	}
	if !bytes.Equal(pw, pwCheck) {
		t.Errorf("Decrypt changed input password")
	}
	if err != nil {
		t.Fatalf("Decrypt returned error: %s", err)
	}

	// Verify that Decrypt(Encrypt(x, pw), pw) is identity operation
	if !bytes.Equal(msg, decryptedMsg) {
		t.Fatalf("Decrypted message does not match input message")
	}

	if !t.Failed() {
		t.Logf("Simple Encrypt/Decrypt Test Passed")
	}
}

func TestAuthCheckSimple(t *testing.T) {
	const msg1 = "True wholeness is achieved by return"
	const pw1 = "Reversal"

	msg := []byte(msg1)
	pw := []byte(pw1)

	ciphertext, err := Encrypt(msg, pw)
	if err != nil {
		t.Fatalf("Encrypt returned error: %s", err)
	}

	_, err = Decrypt(ciphertext, pw)
	if IsAuthError(err) {
		t.Errorf("Unexpected Auth Error")
	} else if err != nil {
		t.Errorf("Decrypt of auth text returned error: %s", err)
	}

	// Break ciphertext
	ciphertext[23] ^= byte(128)

	_, err = Decrypt(ciphertext, pw)
	if !IsAuthError(err) {
		if err != nil {
			t.Errorf("Decrypt of broken ciphertext return non-Auth Error: %s", err)
		} else {
			t.Errorf("Decrypt of broken ciphertext did not return Auth Error as expected")
		}
	}

	if !t.Failed() {
		t.Logf("Simple Auth Test Passed")
	}
}

func TestEncrytDecryptEdgeCases(t *testing.T) {
	doEncryptDecrypt(t, "PT&PW=nil", nil, nil)
	doEncryptDecrypt(t, "PT=nil", []byte(""), []byte("weiwuwei"))
	doEncryptDecrypt(t, "PW=nil", []byte("Is not the real tao"), []byte(""))
	if !t.Failed() {
		t.Logf("Edge Cases Tests Passed")
	}
}

func TestEncryptDecryptRandomData(t *testing.T) {
	const iterations = 8

	for i := 0; i < iterations; i++ {
		pwlen, err := chooseInt(0, 100)
		if err != nil {
			panic(err)
		}
		datalen, err := chooseInt(0, 2000)
		if err != nil {
			panic(err)
		}
		tag := fmt.Sprintf("Rand%d-PWLen:%d Len:%d", i, pwlen, datalen)
		pw, err := randBytes(pwlen)
		if err != nil {
			panic(err)
		}
		data, err := randBytes(datalen)
		if err != nil {
			panic(err)
		}
		doEncryptDecrypt(t, tag, data, pw)
	}
}

func dupBytes(src []byte) (dest []byte) {
	dest = make([]byte, len(src))
	copy(dest, src)
	return dest
}

func doEncryptDecrypt(t *testing.T, tag string, msgIn, pwIn []byte) {

	msg := dupBytes(msgIn)
	pw := dupBytes(pwIn)

	ciphertext, err := Encrypt(msg, pw)

	// Verify msg, pw not changed
	if !bytes.Equal(msg, msgIn) {
		t.Errorf("%s: Encrypt changed input msg", tag)
	}
	if !bytes.Equal(pw, pwIn) {
		t.Errorf("%s: Encrypt changed input password", tag)
	}
	if err != nil {
		t.Errorf("%s: Encrypt returned error: %s", tag, err)
		return
	}

	ciphertextCheck := dupBytes(ciphertext)

	decryptedMsg, err := Decrypt(ciphertext, pw)

	// Verify ciphertext, pw not changed
	if !bytes.Equal(ciphertext, ciphertextCheck) {
		t.Errorf("%s: Decrypt changed input ciphertext", tag)
	}
	if !bytes.Equal(pw, pwIn) {
		t.Errorf("%s: Decrypt changed input password", tag)
	}
	if err != nil {
		t.Errorf("%s: Decrypt returned error: %s", tag, err)
	} else {
		// Verify that Decrypt(Encrypt(x, pw), pw) is identity operation
		if !bytes.Equal(msg, decryptedMsg) {
			t.Errorf("%s: Decrypted message does not match input message", tag)
		}
	}

	// Break ciphertext and verify auth error
	if len(ciphertext) > 0 {
		somePos, err := chooseInt(0, len(ciphertext))
		if err != nil {
			panic(err)
		}
		someByteInt, err := chooseInt(1, 256)
		if err != nil {
			panic(err)
		}
		someByte := uint8(someByteInt)

		t.Logf("%s: somePos: %d  someByte: %d", tag, somePos, someByte)

		ciphertext[somePos] ^= someByte // break ciphertext
		decryptedMsg, err = Decrypt(ciphertext, pw)

		// Verify ciphertext, pw not changed
		ciphertext[somePos] ^= someByte // revert ciphertext
		if !bytes.Equal(ciphertext, ciphertextCheck) {
			t.Errorf("%s: NonAuth Decrypt changed input ciphertext", tag)
		}
		if !bytes.Equal(pw, pwIn) {
			t.Errorf("%s: NonAuth Decrypt changed input password", tag)
		}
		if !IsAuthError(err) {
			t.Errorf("%s: NonAuth Decrypt did not return Auth Error", tag)
			if err != nil {
				t.Errorf("%s: NonAuth Decrypt returned error: %s", tag, err)
			}
		}
	}
}

// randBytes returns a byte slice of a certain length of random data
func randBytes(length int) (bytes []byte, err error) {
	bytes = make([]byte, length)
	byteslen, err := io.ReadFull(rand.Reader, bytes)
	if err == nil && byteslen != length {
		err = fmt.Errorf("randBytes read length %d is not expected length %d", byteslen, len(bytes))
	}
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// chooseInt is a near random selector of an int in a range.  The smaller the range,
// the more random the choice.
func chooseInt(minInclusive, maxExclusive int) (randint int, err error) {
	span := maxExclusive - minInclusive
	if span == 0 {
		return minInclusive, nil // No choice
	}
	if span < 0 {
		err = fmt.Errorf("chooseInt max less than min")
		return -1, err
	}
	if span > math.MaxInt32 {
		err = fmt.Errorf("chooseInt span greater than MaxInt32")
		return -1, err
	}
	chooseIntBytes := make([]byte, 4)
	chooselen, err := io.ReadFull(rand.Reader, chooseIntBytes)
	if err == nil && chooselen != 4 {
		err = fmt.Errorf("chooseInt read length %d is not expected length %d", chooselen, len(chooseIntBytes))
	}
	if err != nil {
		return -1, err
	}

	var chooseint32 uint32
	buf := bytes.NewReader(chooseIntBytes)
	err = binary.Read(buf, binary.LittleEndian, &chooseint32)
	if err != nil {
		fmt.Errorf("Conversion of chooseIntBytes to chooseint32 failed:", err)
		return -1, err
	}
	chooseint := int(chooseint32)
	if chooseint < 0 {
		chooseint *= -1
	}

	return minInclusive + chooseint%span, nil
}
