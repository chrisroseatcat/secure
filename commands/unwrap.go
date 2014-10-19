// unwrap decrypts data that has been encrypted with wrap secure encryption.
// It reads from stdin or an input file and writes to stdout or an output file.
package main

import (
	"bufio"
	"code.google.com/p/gopass"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"secure"
	"strings"
)

const APP_VERSION = "1.0"

const (
	fileModeNoOverwrite = os.O_WRONLY | os.O_CREATE | os.O_EXCL
	fileModeOverwrite   = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
)

var (
	blkOutFlag    *bool   = flag.Bool("blk", false, "Autoname output file by removing .blk extension")
	helpFlag      *bool   = flag.Bool("h", false, "Print this help text and exit")
	overwriteFlag *bool   = flag.Bool("o", false, "Allow overwrite of output file")
	pwStringFlag  *string = flag.String("pw", "", "Password")
	stdinFlag     *bool   = flag.Bool("stdin", false, "Get input from stdin")
	versionFlag   *bool   = flag.Bool("v", false, "Print version")
	visEntryFlag  *bool   = flag.Bool("vis", false, "Visible password entry")
)

func usage() {
	fmt.Fprintln(os.Stderr, "Usage: unwrap [OPTIONS] [<input-file>] [<output-file>]\n"+
		"unwrap decrypts data encrypted by wrap secure encryption.\n"+
		"  -blk\t\tAutoname output file by removing .blk extension\n"+
		"  -h\t\tPrint this help text and exit\n"+
		"  -o\t\tAllow overwrite of output file\n"+
		"  -pw <password>\tPassword\n"+
		"  -stdin\t\tUse stdin for input\n"+
		"  -v\t\tPrint version\n"+
		"  -vis\t\tVisible password entry\n")
}

// unwrap decrypts data that has been encrypted with wrap secure encryption.
// It reads from stdin or an input file and writes to stdout or an output file.
func main() {

	// Catch any panics.  The secure package itself does not explicitly panic.
	defer func() {
		if err := recover(); err != nil {
			fmt.Fprintf(os.Stderr, "unwrap error: %s\n", err)
			os.Exit(1)
		}
	}()

	err := run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "unwrap error: %s\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}

func run() error {

	flag.Usage = usage

	flag.Parse() // Scan the arguments list

	args := flag.Args()

	if *versionFlag {
		fmt.Fprintf(os.Stderr, "unwrap version: %s\n", APP_VERSION)
	}

	if *helpFlag {
		usage()
		err := fmt.Errorf("Processing does not continue when help requested.")
		return err
	}

	// Input & Output File Processing
	var (
		infilename  string
		infile      *os.File
		outfilename string
		outfile     *os.File
		pw          []byte
		outmode     int
		err         error
	)

	if *overwriteFlag {
		outmode = fileModeOverwrite
	} else {
		outmode = fileModeNoOverwrite
	}

	if *pwStringFlag != "" && *visEntryFlag {
		return fmt.Errorf("Option -pw (to specify password in command) and " +
			"option -vis (for visible password entry) are mutually exclusive")
	}

	if *blkOutFlag && *stdinFlag {
		return fmt.Errorf("Option -stdin is not allowed with option -blk")
	}

	if *pwStringFlag == "" && *stdinFlag {
		return fmt.Errorf("Option -stdin requires including password in command using option -pw")
	}

	if len(args) == 2 {
		if *blkOutFlag {
			return fmt.Errorf("Specifying output file %s is not allowed with option -blk",
				args[1])
		}

		if *stdinFlag {
			return fmt.Errorf("Specifying input file %s is not allowed with option -stdin",
				args[0])
		}
	}

	expectedNbrArgs := 2
	if *stdinFlag {
		expectedNbrArgs--
	}
	if *blkOutFlag {
		expectedNbrArgs--
	}

	// Catch all
	if len(args) > expectedNbrArgs {
		return fmt.Errorf("Extra file parameter(s): %s", strings.Join(args[expectedNbrArgs:], " "))
	}

	switch len(args) {
	case 2:
		infilename = args[0]
		outfilename = args[1]

	case 1:
		if *stdinFlag {
			outfilename = args[0]
		} else {
			infilename = args[0]
		}

	case 0:
		if !*stdinFlag {
			return fmt.Errorf("Input file not specified")
		}

	default:
		return fmt.Errorf("File arg parameter checking failed")
	}

	if *blkOutFlag {
		if !strings.HasSuffix(infilename, ".blk") {
			return fmt.Errorf("Option -blk requires that the input file name %s ends in '.blk'", infilename)
		}
		outfilename = infilename[:len(infilename)-4]
		if len(outfilename) < 1 {
			return fmt.Errorf("Option -blk applied to input file name %s yields a null string for output file name",
				infilename)
		}
	}

	if !*stdinFlag {
		if infile, err = os.Open(infilename); err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("Input file %s does not exist", infilename)
			}
			return err
		}
		defer infile.Close()
	} else {
		infile = os.Stdin
	}

	if outfilename != "" {
		if outfile, err = os.OpenFile(outfilename, outmode, 0644); err != nil {
			if os.IsExist(err) {
				return fmt.Errorf("Output file %s already exists", outfilename)
			}
			if os.IsPermission(err) {
				return fmt.Errorf("Output file %s permission denied", outfilename)
			}
			return err
		}
		defer outfile.Close()
	} else {
		outfile = os.Stdout
	}

	if *pwStringFlag == "" {
		if *visEntryFlag {
			pwReader := bufio.NewReader(os.Stdin)
			fmt.Fprintln(os.Stderr, "Enter Password:")
			pwstring, err := pwReader.ReadString('\n')
			if err != nil {
				return fmt.Errorf("Accepting password: %s\n", err)
			}
			pw = []byte(pwstring[:len(pwstring)-1]) // Drop ending \n
		} else {
			pwString, err := gopass.GetPass("Enter Password: ")
			if err != nil {
				return fmt.Errorf("Reading password: %s", err)
			}
			pw = []byte(pwString)
		}
	} else {
		pw = []byte(*pwStringFlag)
	}

	if *stdinFlag {
		fmt.Fprintf(os.Stderr, "Receiving input on Stdin: Use Ctrl+D on new line to end input manually.\n")
	}

	input, err := ioutil.ReadAll(infile)
	if err != nil {
		return fmt.Errorf("Reading input: %s", err)
	}

	output, err := secure.Decrypt(input, pw)
	if err != nil {
		return err
	}

	writer := bufio.NewWriter(outfile)
	numbytes, err := writer.Write(output)
	if err != nil || numbytes != len(output) {
		return fmt.Errorf("%d bytes written of %d: %s\n",
			numbytes, len(output), err)
	}
	writer.Flush()

	fmt.Fprintf(os.Stderr, "unwrap success: %d bytes output.\n", numbytes)
	return nil
}
