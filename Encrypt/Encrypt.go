package Encrypt

import (
	"MyPacker/Others"
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Generate random keys
const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func init() {
	rand.Seed(time.Now().UnixNano())
}

// random string
func GenerateRandomString(length int) string {
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[rand.Intn(len(charset))]
	}
	return string(result)
}

// BytesToUUIDs_C splits the byte slice into multiple 16-byte groups and converts it into a string slice in UUID format
func BytesToUUIDs_C(b []byte) ([]string, error) {
	var uuids []string
	chunkSize := 16

	for len(b) > 0 {
		// If the remaining bytes are less than 16 bytes, pad them with 0
		if len(b) < chunkSize {
			padding := make([]byte, chunkSize-len(b))
			b = append(b, padding...)
		}

		// Intercept 16-byte group
		chunk := b[:chunkSize]
		b = b[chunkSize:]

		// Convert bytes to hexadecimal string
		hexString := hex.EncodeToString(chunk)

		// Format UUID string
		uuid := fmt.Sprintf("%s%s%s%s-%s%s-%s%s-%s-%s",
			hexString[6:8],
			hexString[4:6],
			hexString[2:4],
			hexString[0:2],
			hexString[10:12],
			hexString[8:10],
			hexString[14:16],
			hexString[12:14],
			hexString[16:20],
			hexString[20:32])

		uuids = append(uuids, uuid)
	}

	return uuids, nil
}

// BytesToUUIDs_RUST splits the byte slice into multiple 16-byte groups and converts it into a string slice in UUID format
// Now the first half is UUID and the second half is words, in order to speed up compilation
func BytesToUUIDs_RUST(b []byte) ([]string, string, string, error) {
	// Make sure the length of the first half is an integral multiple of 16
	totalLength := len(b)
	portionLen := totalLength / 10
	uuidLen := totalLength - portionLen

	// Adjust uuidLen to be a multiple of 16
	if remainder := uuidLen % 16; remainder != 0 {
		uuidLen += 16 - remainder
	}

	uuidPart := b[:uuidLen]
	wordsPart := b[uuidLen:]

	var uuids []string
	chunkSize := 16

	for len(uuidPart) > 0 {
		// If the remaining bytes are less than 16 bytes, pad them with 0
		if len(uuidPart) < chunkSize {
			padding := make([]byte, chunkSize-len(uuidPart))
			uuidPart = append(uuidPart, padding...)
		}

		// Intercept 16-byte group
		chunk := uuidPart[:chunkSize]
		uuidPart = uuidPart[chunkSize:]

		// Convert bytes to hexadecimal string
		hexString := hex.EncodeToString(chunk)

		// Format UUID string
		uuid := fmt.Sprintf("%s-%s-%s-%s-%s",
			hexString[0:8],
			hexString[8:12],
			hexString[12:16],
			hexString[16:20],
			hexString[20:32])

		uuids = append(uuids, uuid)
	}
	//Call the python script to get dataset and words

	err := ioutil.WriteFile("T00ls\\enc.bin", wordsPart, 0644)
	if err != nil {
		panic(err)
	}
	dir, err := os.Getwd()
	dir1 := filepath.Join(dir, "T00ls", "Shellcode-to-English.py")
	dir2 := filepath.Join(dir, "T00ls", "enc.bin")
	words_path := filepath.Join(dir, "T00ls", "words.txt")
	dataset_path := filepath.Join(dir, "T00ls", "dataset.txt")
	cmd := exec.Command("python", dir1, dir2)
	// Capture standard output and standard error
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		fmt.Println("\033[31m[+]\033[0m Compilation failed:", err)
		// Get the contents of standard error
		stderrString := stderr.String()
		if stderrString != "" {
			fmt.Println("\033[31m[+]\033[0m standard error:", stderrString)
		}
	}
	words, err := ioutil.ReadFile(words_path)
	if err != nil {
		log.Fatal(err)
	}
	dataset, err := ioutil.ReadFile(dataset_path)
	if err != nil {
		log.Fatal(err)
	}
	return uuids, string(words), string(dataset), nil
}

func HexStringToBytes(hexStr string) ([]byte, error) {
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// obfuscation
func Obfuscation(options *Others.FlagOptions, shellcodeString string) (string, string, string) {
	switch strings.ToLower(options.Obfuscation) {

	case "uuid":
		var uuids []string
		var words string
		var dataset string
		bytes, _ := HexStringToBytes(shellcodeString)
		var err error
		switch strings.ToLower(options.Language) {
		case "c":
			uuids, err = BytesToUUIDs_C([]byte(bytes))
			if err != nil {
				fmt.Println("\033[31m[+]\033[0m Error:", err)
			}
		case "rust":
			uuids, words, dataset, err = BytesToUUIDs_RUST([]byte(bytes))
			if err != nil {
				fmt.Println("\033[31m[+]\033[0m Error:", err)
			}
		}
		var uuidsString string
		for _, uuid := range uuids {
			uuidsString += "\"" + uuid + "\","
		}
		return uuidsString, words, dataset
	case "words":
		switch strings.ToLower(options.Language) {

		case "c":
			//Call the python script to get dataset and words
			decoded, err := hex.DecodeString(shellcodeString)
			if err != nil {
				panic(err)
			}

			err = ioutil.WriteFile("T00ls\\enc.bin", decoded, 0644)
			if err != nil {
				panic(err)
			}
			dir, err := os.Getwd()
			dir1 := filepath.Join(dir, "T00ls", "Shellcode-to-English.py")
			dir2 := filepath.Join(dir, "T00ls", "enc.bin")
			words_path := filepath.Join(dir, "T00ls", "words.txt")
			dataset_path := filepath.Join(dir, "T00ls", "dataset.txt")
			cmd := exec.Command("python", dir1, dir2)
			// Capture standard output and standard error
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			err = cmd.Run()
			if err != nil {
				fmt.Println("\033[31m[+]\033[0m Compilation failed:", err)
				// Get the contents of standard error
				stderrString := stderr.String()
				if stderrString != "" {
					fmt.Println("\033[31m[+]\033[0m standard error:", stderrString)
				}
				return "", "", ""
			}
			words, err := ioutil.ReadFile(words_path)
			if err != nil {
				log.Fatal(err)
			}
			dataset, err := ioutil.ReadFile(dataset_path)
			if err != nil {
				log.Fatal(err)
			}

			//fmt.Println("[+] Generated dataset" + string(dataset) + "\n")
			//fmt.Println("[+] Generated words:" + string(words) + "\n")
			return "", string(words), string(dataset)
		case "rust":
			var uuids []string
			var words string
			var dataset string
			bytes, _ := HexStringToBytes(shellcodeString)
			var err error
			uuids, words, dataset, err = BytesToUUIDs_RUST([]byte(bytes))
			if err != nil {
				fmt.Println("\033[31m[+]\033[0m Error:", err)
			}

			var uuidsString string
			for _, uuid := range uuids {
				uuidsString += "\"" + uuid + "\","
			}
			return uuidsString, words, dataset
		}

	}
	return "", "", ""
}
