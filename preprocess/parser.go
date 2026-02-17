package preprocess

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"watchd/bpfloader"
)

type token struct {
	lineNum  int
	command  string
	argument string
}

type excludePolicy struct {
	excludeDirs  map[bpfloader.TrackedFileKey]uint8
	excludeFiles map[bpfloader.TrackedFileKey]uint8
	excludeExts  map[string]uint8
	excludeSuffs []string
}

// ----------------------------------------------------------------------------------------------------------------
/* Read and Tokenize*/
func ReadConfig(configPath string) ([]token, error) {

	f, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var tokens []token
	scanner := bufio.NewScanner(f)
	var lineNum int
	lineNum = 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.SplitN(line, ":", 2)
		if len(fields) < 2 {
			return nil, fmt.Errorf("ERROR [Line %d]: colon missing\n  %s\n  ^\nuse 'Command: Argument' format", lineNum, line)
		} else if len(fields) > 2 {
			return nil, fmt.Errorf("ERROR [Line %d]: extra colon\n  %s\n  ^\nuse 'Command: Argument' format", lineNum, line)
		}

		tokens = append(tokens, token{
			lineNum:  lineNum,
			command:  strings.TrimSpace(fields[0]),
			argument: strings.TrimSpace(fields[1]),
		})
	}
	return tokens, scanner.Err()
}

// Validate Syntax
func SyntaxValidation(tokens []token) error {
	for _, token := range tokens {
		if token.command != "D" && token.command != "E" && token.command != "IF" && token.command != "EE" && token.command != "ES" {
			return fmt.Errorf("ERROR [Line %d]: invalid command: %s\n  %s: %s\n  ^\nvalid commands: D, E, IF, EF, EE, ES", token.lineNum, token.command, token.command, token.argument)
		}
		if token.argument == "" {
			return fmt.Errorf("ERROR [Line %d]: empty argument\n  %s: %s\n  ^\nprovide argument for command", token.lineNum, token.command, token.argument)
		}
		if !strings.HasPrefix(token.argument, "/") && (token.command == "D" || token.command == "IF" || token.command == "E") {
			return fmt.Errorf("ERROR [Line %d]: argument must start with /\n  %s: %s\n  ^\nprovide absolute path", token.lineNum, token.command, token.argument)
		}
	}
	return nil

}

// Construct PolicyMap <PolicyKey, PolicyValue>
func constructPolicyMap(tokens []token, exlPol excludePolicy) (bpfloader.TrackedFileMap, error) {

	policyMap := make(bpfloader.TrackedFileMap)

	for _, token := range tokens {

		switch token.command {
		case "D":
			walkDir(token.argument, &policyMap, &exlPol)
		case "IF":
			addFile(token.argument, &policyMap)
		default:
			continue
		}
	}

	return policyMap, nil
}

func walkDir(dir string, policyMap *bpfloader.TrackedFileMap, exlPol *excludePolicy) {

	info, err := os.Stat(dir)
	if err != nil {
		fmt.Printf("WARN: %s not found %s\n", dir, err)
		return
	}
	stat := info.Sys().(*syscall.Stat_t)

	key := bpfloader.TrackedFileKey{
		Inode_number: uint64(stat.Ino),
		Dev:          rawDev(stat),
	}
	value := bpfloader.TrackedFileValue{
		Val: 1,
	}

	if _, ok := (*policyMap)[key]; ok {
		return
	}

	//check if it is excluded
	if exlPol.excludeDirs[key] == 1 {
		return
	}

	filename := info.Name()
	ext := filepath.Ext(filename)

	// check if it is excluded by suffix
	for _, suff := range exlPol.excludeSuffs {
		if strings.HasSuffix(filename, suff) {
			return
		}
	}

	// check if it is excluded by extension
	_, ok := exlPol.excludeExts[ext]
	if ok {
		return
	}

	(*policyMap)[key] = value
	//fmt.Printf("key (%d, %d)  : Value %d \n", key.Inode_number, key.Dev, value.Val)

	if info.IsDir() {
		entries, err := os.ReadDir(dir)
		if err != nil {
			fmt.Printf("WARN: %s not found %s\n", dir, err)
			return
		}
		for _, entry := range entries {
			walkDir(dir+"/"+entry.Name(), policyMap, exlPol)
		}
	}

	return
}

func addFile(file string, policyMap *bpfloader.TrackedFileMap) {

	info, err := os.Stat(file)
	if err != nil {
		fmt.Printf("WARN: %s not found %s\n", file, err)
		return
	}
	stat := info.Sys().(*syscall.Stat_t)

	key := bpfloader.TrackedFileKey{
		Inode_number: uint64(stat.Ino),
		Dev:          rawDev(stat),
	}
	value := bpfloader.TrackedFileValue{
		Val: 1,
	}

	if _, ok := (*policyMap)[key]; ok {
		return
	}
	(*policyMap)[key] = value
	//fmt.Printf("key (%d, %d)  : Value %d \n", key.Inode_number, key.Dev, value.Val)

	return
}

func parseExcludePolicy(tokens []token) excludePolicy {

	exlPol := excludePolicy{
		excludeDirs:  make(map[bpfloader.TrackedFileKey]uint8),
		excludeFiles: make(map[bpfloader.TrackedFileKey]uint8),
		excludeExts:  make(map[string]uint8),
		excludeSuffs: make([]string, 0),
	}

	for _, token := range tokens {
		switch token.command {
		case "E":
			policy, err := generatePolicyFrompath(token.argument)
			if err != nil {
				fmt.Printf("WARN: %s not found %s\n", token.argument, err)
				continue
			}
			exlPol.excludeDirs[policy.Key] = 1

		case "EE":
			ext := token.argument
			exlPol.excludeExts[ext] = 1

		case "ES":
			suff := token.argument
			exlPol.excludeSuffs = append(exlPol.excludeSuffs, suff)
		default:
			continue
		}
	}

	return exlPol
}

func generatePolicyFrompath(filepath string) (bpfloader.TrackedFile, error) {
	var policy bpfloader.TrackedFile

	info, err := os.Stat(filepath)
	if err != nil {
		return policy, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return policy, fmt.Errorf("failed to get Stat_t")
	}

	policy.Key.Inode_number = uint64(stat.Ino)
	policy.Key.Dev = rawDev(stat)
	policy.Value.Val = 1

	return policy, nil
}
