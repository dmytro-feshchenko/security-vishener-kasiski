package helpers

import (
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// ReadFileLines - read file line by line
func ReadFileLines(filename string) ([]string, error) {
	content, err := ReadFile(filename)
	if err != nil {
		return []string{}, err
	}
	lines := strings.Split(string(content), "\n")
	return lines, nil
}

// ReadFile - read the whole file and returns bytes
func ReadFile(filename string) ([]byte, error) {
	absPath, errBuildPath := filepath.Abs(filename)
	if errBuildPath != nil {
		log.Fatal(errBuildPath)
	}
	file, err := os.Open(absPath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	content, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}
	return content, nil
}
