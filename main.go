package main

import(
    "flag"
    "fmt"
    "os"
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
        noPreserveFlag bool
        pass string
        infile string
        outfile string
    )

    flag.StringVar(&pass, "p", "", "The password to encrypt the file with")
    flag.StringVar(&infile, "f", "", "The file to encrypt or decrypt")
    flag.BoolVar(&decryptFlag, "d", false, "Decrypt instead of encrypting (Optional)")
    flag.BoolVar(&noPreserveFlag, "no-preserve", false, "Delete the cleartext file after it is decrypted (Optional)")
    flag.StringVar(&outfile, "o", "", "The file to produce (Optional)")
    flag.Parse()

    if pass == "" {
        fmt.Println("No password specified. Aborting.")
        return
    }

    if infile == "" {
        fmt.Println("No file specified. Aborting.")
        return
    }

    var operation func(string, string) ([]byte, error)
    if decryptFlag {
        operation = decrypt
    } else {
        operation = encrypt
    }

    output, err := operation(infile, pass)
    if err != nil {
        fmt.Println(err)
        return
    }

    if outfile == "" {
        outfile = infile
        if decryptFlag {
            outfile = outfile + ".txt"
        } else {
            outfile = outfile + ".gobbledygook"
        }
    }

    err = ioutil.WriteFile(outfile, output, 0666)
    if err != nil {
        fmt.Println(err)
        return
    }

    if noPreserveFlag {
        os.Remove(infile)
    }
}

func encrypt(infile, password string) ([]byte, error) {
    clearText, err := ioutil.ReadFile(infile)
    if err != nil {
        return nil, err
    }

    padded, err := PKCS7Pad(clearText, aes.BlockSize)
    if err != nil {
        return nil, err
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
        return nil, err
    }

    _, err = rand.Read(hmacKey)
    if err != nil {
        return nil, err
    }

    aesKey := pbkdf2.Key([]byte(password), nil, KDF_ITERS, AES_KEYSIZE, sha256.New)
    block, err := aes.NewCipher(aesKey)
    if err != nil {
        return nil, err
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

    return buf, nil
}

func decrypt(infile, password string) ([]byte, error) {
    buf, err := ioutil.ReadFile(infile)
    if err != nil {
        return nil, err
    }

    iv := buf[:aes.BlockSize]
    hmacKey := buf[aes.BlockSize:aes.BlockSize + HMAC_KEYSIZE]
    macTag := buf[aes.BlockSize + HMAC_KEYSIZE:aes.BlockSize + HMAC_KEYSIZE + MAC_TAGSIZE]
    cipherText := buf[aes.BlockSize + HMAC_KEYSIZE + MAC_TAGSIZE:]

    aesKey := pbkdf2.Key([]byte(password), nil, KDF_ITERS, AES_KEYSIZE, sha256.New)
    block, err := aes.NewCipher(aesKey)
    if err != nil {
        return nil, err
    }

    cbc := cipher.NewCBCDecrypter(block, iv)
    cbc.CryptBlocks(hmacKey, hmacKey)

    mac := hmac.New(sha256.New, hmacKey)
    mac.Write(iv)
    mac.Write(cipherText)
    expectedMac := mac.Sum(nil)
    if !hmac.Equal(macTag, expectedMac) {
        return nil, errors.New("Expected MAC did not match supplied MAC.")
    }

    cbc = cipher.NewCBCDecrypter(block, iv)
    cbc.CryptBlocks(cipherText, cipherText)

    clearText, err := PKCS7Unpad(cipherText, aes.BlockSize)
    if err != nil {
        return nil, err
    }

    return clearText, nil
}

