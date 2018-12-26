package main

import(
    "flag"
    "fmt"
    "errors"
    "io/ioutil"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/hmac"
    "crypto/sha256"
    "golang.org/x/crypto/pbkdf2"
)

const(
    AES_KEYSIZE int = 32
    HMAC_KEYSIZE int = 32
    MAC_TAGSIZE int = 32
    KDF_ITERS int = 4096
)

func main() {
    var(
        decryptFlag bool
        pass string
        file string
    )

    flag.BoolVar(&decryptFlag, "d", false, "Use this flag to decrypt instead of encrypting")
    flag.StringVar(&pass, "p", "", "The password to encrypt the file with")
    flag.StringVar(&file, "f", "", "The file to encrypt or decrypt")
    flag.Parse()

    if pass == "" {
        fmt.Println("No password specified. Aborting.")
        return
    }

    if file == "" {
        fmt.Println("No file specified. Aborting.")
        return
    }

    var err error

    if decryptFlag {
        err = decrypt(file, pass)
    } else {
        err = encrypt(file, pass)
    }

    if err != nil {
        fmt.Println(err)
    }
}

func encrypt(infile, password string) error {
    clearText, err := ioutil.ReadFile(infile)
    if err != nil {
        return err
    }

    padded, err := PKCS7Pad(clearText, aes.BlockSize)
    if err != nil {
        return err
    }

    buf := make([]byte,
        aes.BlockSize + // IV
        HMAC_KEYSIZE  + // HMAC key
        MAC_TAGSIZE   + // MAC tag
        len(padded))    // Ciphertext

    iv := buf[:aes.BlockSize]
    hmacKey := buf[aes.BlockSize:aes.BlockSize + HMAC_KEYSIZE]
    macTag := buf[aes.BlockSize + HMAC_KEYSIZE:aes.BlockSize + HMAC_KEYSIZE + MAC_TAGSIZE]
    cipherText := buf[aes.BlockSize + HMAC_KEYSIZE + MAC_TAGSIZE:]
    
    _, err = rand.Read(iv)
    if err != nil {
        return err
    }

    _, err = rand.Read(hmacKey)
    if err != nil {
        return err
    }

    aesKey := pbkdf2.Key([]byte(password), nil, KDF_ITERS, AES_KEYSIZE, sha256.New)
    block, err := aes.NewCipher(aesKey)
    if err != nil {
        return err
    }

    cbc := cipher.NewCBCEncrypter(block, iv)
    cbc.CryptBlocks(cipherText, padded)

    mac := hmac.New(sha256.New, hmacKey)
    mac.Write(iv)
    mac.Write(cipherText)
    tag := mac.Sum(nil)
    copy(macTag, tag)

    cbc = cipher.NewCBCEncrypter(block, iv)
    cbc.CryptBlocks(hmacKey, hmacKey)

    return ioutil.WriteFile(infile + ".gobbledygook", buf, 0666)
}

func decrypt(infile, password string) error {
    buf, err := ioutil.ReadFile(infile)
    if err != nil {
        return err
    }

    iv := buf[:aes.BlockSize]
    hmacKey := buf[aes.BlockSize:aes.BlockSize + HMAC_KEYSIZE]
    macTag := buf[aes.BlockSize + HMAC_KEYSIZE:aes.BlockSize + HMAC_KEYSIZE + MAC_TAGSIZE]
    cipherText := buf[aes.BlockSize + HMAC_KEYSIZE + MAC_TAGSIZE:]

    aesKey := pbkdf2.Key([]byte(password), nil, KDF_ITERS, AES_KEYSIZE, sha256.New)
    block, err := aes.NewCipher(aesKey)
    if err != nil {
        return err
    }

    cbc := cipher.NewCBCDecrypter(block, iv)
    cbc.CryptBlocks(hmacKey, hmacKey)

    mac := hmac.New(sha256.New, hmacKey)
    mac.Write(iv)
    mac.Write(cipherText)
    expectedMac := mac.Sum(nil)
    if !hmac.Equal(macTag, expectedMac) {
        return errors.New("Expected MAC did not match supplied MAC.")
    }

    cbc = cipher.NewCBCDecrypter(block, iv)
    cbc.CryptBlocks(cipherText, cipherText)

    clearText, err := PKCS7Unpad(cipherText, aes.BlockSize)
    if err != nil {
        return err
    }

    return ioutil.WriteFile(infile + ".txt", clearText, 0666)
}

