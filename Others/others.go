package Others

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type FlagOptions struct {
	Help        bool
	OutFile     string
	InputFile   string
	Language    string
	Encryption  string
	KeyLength   int
	Obfuscation string
	Framework   int
	Sandbox     bool
	Unhook      bool
	Loading     string
	Debug       bool
}


func PrintVersion() {
    fmt.Println("  ")
    fmt.Println("░█▄█░█▀█░█▀▀░█▀▄░█░█░█▀█░█▀█░█▀▀░█▀▄░░░░░█▀▀░█░█░█▀▀░█░░░█░░░█▀▀░█▀█░█▀▄░█▀▀")
    fmt.Println("░█░█░█▀█░█░█░█▀▄░█░█░█░█░█░█░█▀▀░█▀▄░▄▄▄░▀▀█░█▀█░█▀▀░█░░░█░░░█░░░█░█░█░█░█▀▀")
    fmt.Println("░▀░▀░▀░▀░▀▀▀░▀░▀░▀▀▀░▀░▀░▀░▀░▀▀▀░▀░▀░░░░░▀▀▀░▀░▀░▀▀▀░▀▀▀░▀▀▀░▀▀▀░▀▀░░▀▀▀░▀▀▀")
	fmt.Println("                                               ")
	fmt.Println("                    author 0nsec               ")
	fmt.Println("                    version 1.0.0              ")
	fmt.Println("                    2024.09                    ")
}

func PrintUsage() {
	fmt.Println("Usage:")
	fmt.Println("[+]  -h <help>: Show help information")
	fmt.Println("[+]  -i <path>: Path to raw format shellcode")
	fmt.Println("[+]  -enc <encryption>: Shellcode encryption method (default: aes)")
	fmt.Println("[+]  -lang <language>: Select the language of the loader (default 'c', possible values: c,rust)")
	fmt.Println("[+]  -o <output>: Output file (default: Program)")
	fmt.Println("[+]  -k <keyLength>:  Encryption key length (default: 16)")
	fmt.Println("[+]  -obf <obfuscation>: Obfuscate shellcode to reduce entropy (default: uuid)")
	fmt.Println("[+]  -f <framework>:  Is the target architecture 32-bit or 64-bit?")
	fmt.Println("[+]  -sandbox <true/false>: Whether to enable anti-sandbox mode (default: true)")
	fmt.Println("[+]  -unhook <true/false>: Whether to enable unhook mode (default: false, use indirect syscall to load)")
	fmt.Println("[+]  -loading <loadingTechnique>: Please select the loading method, support callback, fiber, earlybird (default: callback)")
	fmt.Println("[+]  -debug  <true/false>: Whether to print the shellcode intermediate encryption/obfuscation process (default is 'false', that is, do not print)")
}

func PrintKeyDetails(key string) {
	for i, b := range key {
		// decimalValue := int(b)
		hexValue := fmt.Sprintf("%02x", b)
		fmt.Printf("0x%s", hexValue)
		if i < len(key)-1 {
			fmt.Printf(", ")
		}
	}

	fmt.Printf("\n\n")
}

// Check AES encryption format
//func DetectNotification(key int) int {
//	logger := log.New(os.Stderr, "[!] ", 0)
//	keyNotification := 0
//	switch key {
//	case 16:
//		keyNotification = 128
//	case 24:
//		keyNotification = 192
//	case 32:
//		keyNotification = 256
//	default:
//		logger.Fatal("Initial Error, valid AES key not found\n")
//	}
//
//	return keyNotification
//}

func SaveTemplateToFile(filename string, template string) {
	// Make sure the directory exists
	dir := filepath.Dir(filename)
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		fmt.Println("\033[31m[+]\033[0m Error while creating directory:", err)
		return
	}

	// Open a file for writing. If the file does not exist, it will be created.
	file, err := os.Create(filename)
	if err != nil {
		fmt.Println("\033[31m[+]\033[0m Error creating file:", err)
		return
	}
	defer file.Close() // Close file on function exit

	// Write variable value to file
	_, err = fmt.Fprintln(file, template)
	if err != nil {
		fmt.Println("\033[31m[+]\033[0m Error writing file:", err)
		return
	}
}

// MoveAndRenameFile Move and rename files
func MoveAndRenameFile(srcPath, dstPath string) error {
	err := os.Rename(srcPath, dstPath)
	if err != nil {
		return fmt.Errorf("\033[31m[+]\033[0m Error while moving and renaming file: %w", err)
	}
	return nil
}

func Build(options *FlagOptions, outfile string, framework int) {
	outexe := getOutfileName(outfile)
	// Execute compilation command
	switch strings.ToLower(options.Language) {
	case "c":
		switch framework {
		case 32:
			dir, _ := os.Getwd()
			outfile = outfile
			srcdir := filepath.Join(dir, "C_Template", outfile)
			sysdir := filepath.Join(dir, "C_Template", "sys_32.c")
			cmd := exec.Command("gcc", "-mwindows", "-m32", "-o", outexe, srcdir, sysdir, "-s", "-masm=intel", "-lrpcrt4")
			// Execute the command and wait for it to complete
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			err := cmd.Run()
			if err != nil {
				fmt.Println("\033[31m[+]\033[0m Compilation failed:", err)
				// Get the contents of standard error
				stderrString := stderr.String()
				if stderrString != "" {
					fmt.Println("\033[31m[+]\033[0m standard error:", stderrString)
				}
				return
			}
			fmt.Printf("\033[32m[+]\033[0m Compiled successfully: " + outexe)
		case 64:
			dir, _ := os.Getwd()
			srcdir := filepath.Join(dir, "C_Template", outfile)
			sysdir := filepath.Join(dir, "C_Template", "sys_64.c")
			cmd := exec.Command("gcc", "-mwindows", "-m64", "-o", outexe, srcdir, sysdir, "-s", "-masm=intel", "-lrpcrt4")
			// Execute the command and wait for it to complete
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			err := cmd.Run()
			if err != nil {
				fmt.Println("Compilation failed:", err)
				// Get the contents of standard error
				stderrString := stderr.String()
				if stderrString != "" {
					fmt.Println("standard error:", stderrString)
				}
				return
			}
			fmt.Printf("\033[32m[+]\033[0m Compiled successfully: " + outexe)
		default:
			fmt.Printf("Please choose 32-bit or 64-bit operating system")
		}
	case "rust":
		os.Setenv("RUSTFLAGS", "-Z threads=18")
		dir, _ := os.Getwd()
		dir1 := filepath.Join(dir, "Rust_Template", "Cargo.toml")
		switch options.Framework {
		case 64:
			cmd := exec.Command("cargo", "build", "--manifest-path", dir1, "--release")
			// Execute the command and wait for it to complete
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			err := cmd.Run()
			if err != nil {
				fmt.Println("\033[31m[+]\033[0m Compilation failed:", err)
				// Get the contents of standard error
				stderrString := stderr.String()
				if stderrString != "" {
					fmt.Println("\033[31m[+]\033[0m standard error:", stderrString)
				}
				return
			}
			fmt.Println("[+] Executable files are being moved for you\n")
			dir, _ := os.Getwd()
			dir1 := filepath.Join(dir, "Rust_Template", "target", "release", "Unhook.exe")
			dstPath := filepath.Join(dir, outexe)
			err = MoveAndRenameFile(dir1, dstPath)
			if err != nil {
				fmt.Println("\033[31m[+]\033[0m Error moving and renaming file:", err)
			} else {
				fmt.Printf("\033[32m[+]\033[0m Compiled successfully: " + outexe)
			}
		case 32:
			cmd := exec.Command("cargo", "build", "--manifest-path", dir1, "--release", "--target=i686-pc-windows-gnu")
			// Execute the command and wait for it to complete
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			err := cmd.Run()
			if err != nil {
				fmt.Println("\033[31m[+]\033[0m Compilation failed:", err)
				// Get the contents of standard error
				stderrString := stderr.String()
				if stderrString != "" {
					fmt.Println("\033[31m[+]\033[0m standard error:", stderrString)
				}
				return
			}
			fmt.Println("[+] Executable files are being moved for you\n")
			dir, _ := os.Getwd()
			dir1 := filepath.Join(dir, "Rust_Template", "target", "i686-pc-windows-gnu", "release", "Unhook.exe")
			dstPath := filepath.Join(dir, outexe)
			err = MoveAndRenameFile(dir1, dstPath)
			if err != nil {
				fmt.Println("\033[31m[+]\033[0m Error while moving and renaming file:", err)
			} else {
				fmt.Printf("\033[32m[+]\033[0m Compiled successfully: " + outexe)
			}

		}
	default:
		println("\033[31m[+]\033[0m Error in specified language")
		os.Exit(-1)

	}

}

// 输Out file name
func getOutfileName(filename string) string {
	base := filepath.Base(filename)
	ext := filepath.Ext(base)
	name := base[0 : len(base)-len(ext)]
	return name + ".exe"
}
