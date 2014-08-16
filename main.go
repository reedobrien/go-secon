/* secon secures values in a yaml config file.
It

Encrypts:
 - reads the yaml file
 - gob encodes the value of each key
 - encrypts the value of each gob
 - b64 encodes the ciphertext
 - signs each b64 encoded ciphertext (prepending sentinal and appending MAC)
 - base64 encodes the signed text
 - saves it back as the value for the key

Decrypts:
 - reads the sentinel prepended value and removes the sentinal
 - b64 decodes the value
 - splits off the MAC and verifies it and sentinel
 - b64 decodes the value to get the ciphertext
 - decrypts the ciphertext
 - gob decodes the value
 - saves it back to the yaml key

 Verifies:
  - checks each value to see if it is prepended with the sentinal value
  - exits non zero if any are not.

Verifies may be misleading. However the primary purpose of verify is to use in a pre-commit hook.
*/
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"strconv"

	"gopkg.in/yaml.v1"
)

var sentinel = "$$$secon$$$:::"

var (
	path   = flag.String("path", "", "Path to the config file")
	marker = flag.String("marker", sentinel, "The marker to indicate a file is encrypted.")
	action = flag.String("action", "verify", "One of encrypt, decrypt, or the default verify")

	actions = map[string]bool{"encrypt": true, "decrypt": true, "verify": true}

	c   map[string]interface{}
	b   []byte
	err error
)

func main() {
	flag.Parse()
	// Verify args
	if *path == "" {
		log.Fatalln("-path is a required arg.")
	}
	if _, ok := actions[*action]; !ok {
		log.Fatal("-action must be one of 'encrypt', 'decrypt', or 'verify' but got: ", *action)
	}

	b, err = ioutil.ReadFile(*path)
	if err != nil {
		log.Fatal("Can't load config: ", err)
	}
	err := yaml.Unmarshal(b, &c)
	if err != nil {
		log.Fatal("Can't unmarshal config YAML", err)
	}
	switch *action {
	case "verify":
		log.Println("verifying")
	case "encrypt":
		log.Println("encrypting")
	case "decrypt":
		log.Println("decrypting")
	}
	key := []byte("A 32 byte key to select AES 256.") // 32 bytes
	plaintext := []byte("Only dull people are brilliant at breakfast. O. Wilde")
	fmt.Printf("%s\n", string(plaintext))
	ciphertext := encrypt(key, plaintext)
	fmt.Printf("%x\n", ciphertext)
	result := decrypt(key, ciphertext)
	fmt.Printf("%s\n", string(result))

	for k, v := range c {
		log.Printf("key: %s\tvalue: %v\t type: %T\n", k, v, v)
	}
	log.Printf("%+v\n", c)
}

func encodeBase64(b []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(b))
}

func decodeBase64(b []byte) []byte {
	data, err := base64.StdEncoding.DecodeString(string(b))
	if err != nil {
		log.Fatalf("decodeBase64: %s", err)
	}
	return data
}

func encrypt(key, txt []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("encrypt: Error generating cipher.Block: %s", err)
	}
	b := encodeBase64(txt)
	ctxt := make([]byte, aes.BlockSize+len(b))
	iv := ctxt[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		log.Fatalf("encrypt: %s", err)
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ctxt[aes.BlockSize:], b)
	return ctxt
}

func decrypt(key, txt []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal("decrypt: Error generating cipher.Block: ", err)
	}
	if len(txt) < aes.BlockSize {
		log.Fatal("decrypt: The ciphertext is too short.")
	}
	iv := txt[:aes.BlockSize]
	txt = txt[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(txt, txt)
	return decodeBase64(txt)
}

func gobEncode(src interface{}) ([]byte, error) {
	b := new(bytes.Buffer)
	e := gob.NewEncoder(b)
	if err := e.Encode(src); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func gobDecode(src []byte, dest interface{}) error {
	d := gob.NewDecoder(bytes.NewBuffer(src))
	if err := d.Decode(dest); err != nil {
		return err
	}
	return nil
}

func sign(msg, secret []byte) []byte {
	key := secret
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return h.Sum(nil)
}

func verify(msg, mac, secret []byte) bool {
	m := hmac.New(sha256.New, secret)
	m.Write(msg)
	expected := m.Sum(nil)
	return hmac.Equal(mac, expected)
}

// floatToString converts a float to a String
func floatToString(f float64) string {
	return strconv.FormatFloat(f, 'f', -1, 64)
}

func stringToFloat(s string) (float64, error) {
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return f, err
	}
	return f, nil
}
