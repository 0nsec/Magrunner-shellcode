package Converters

import (
	"MyPacker/Others"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

func OriginalShellcode(options *Others.FlagOptions) []byte {
	fmt.Println("[+] Encoding using sgn tool\n")
	switch runtime.GOOS {
	case "windows":
		//windows下
		dir, err := os.Getwd()
		if err != nil {
			log.Fatalf("\033[31m[+]\033[0m Failed to get the current working directory: %v", err)
		}
		dir1 := filepath.Join(dir, "T00ls", "sgn.exe")
		cmd := exec.Command(dir1, "-a", strconv.Itoa(options.Framework), "-i", options.InputFile)

		// Run the command and wait for it to complete
		err = cmd.Run()
		if err != nil {
			log.Fatalf("\033[31m[+]\033[0m Failed to execute command: %v", err)
		}
	case "darwin": //The GOOS identifier for macOS is darwin
		// macOS Commands executed by the system
		dir, err := os.Getwd()
		if err != nil {
			log.Fatalf("\033[31m[+]\033[0m Failed to get the current working directory: %v", err)
		}
		dir1 := filepath.Join(dir, "T00ls", "sgn")
		cmd := exec.Command(dir1, "-a", strconv.Itoa(options.Framework), "-i", options.InputFile)

		// Run the command and wait for it to complete
		err = cmd.Run()
		if err != nil {
			log.Fatalf("\033[31m[+]\033[0m Failed to execute command: %v", err)
		}
	}
	var file = options.InputFile + ".sgn"
	fileContent, err := ioutil.ReadFile(file)
	if err != nil {
		fmt.Println("\033[31m[+]\033[0m Filed to open inputFile", err)
		os.Exit(-1)
	}

	return []byte(fileContent)

}

func ShellcodeToHex(shellcode string) string {

	StringShellcode := strings.TrimSpace(string(shellcode))
	//Convert shellcode to hex format
	hexShellcode := hex.EncodeToString([]byte(StringShellcode))
	return hexShellcode
}

// Format shellcode
func FormattedHexShellcode(hexShellcode string) string {
	var builder strings.Builder
	for i := 0; i < len(hexShellcode); i += 2 {
		// Add "0x" prefix and then two hex digits.
		builder.WriteString("0x")
		builder.WriteString(hexShellcode[i : i+2])
		// If not the last pair, add comma and space.
		if i < len(hexShellcode)-2 {
			builder.WriteString(", ")
		}
	}
	return builder.String()
}

// Change dataset from []string to string
func FormattedDataset(dataset []string) string {
	var trimmedDataset []string
	for _, s := range dataset {
		trimmed := strings.TrimRight(s, "\r")
		trimmedDataset = append(trimmedDataset, trimmed)
	}
	datasetString := "\"" + strings.Join(trimmedDataset, "\", \"") + "\""
	return datasetString
}
