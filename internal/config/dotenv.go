package config

import (
	"bufio"
	"errors"
	"io/fs"
	"os"
	"strings"
)

// LoadDotEnv reads KEY=VALUE lines from the file at path and sets them in the
// process environment, without overwriting variables that are already set (so
// real environment variables always win over the file). A missing file is not
// an error — .env is optional.
//
// Supported syntax, deliberately minimal:
//   - blank lines and lines beginning with '#' are ignored
//   - KEY=VALUE, with surrounding whitespace on the key trimmed
//   - an optional leading "export " prefix is stripped
//   - values wrapped in matching single or double quotes are unquoted
//   - no variable interpolation or multi-line values
func LoadDotEnv(path string) error {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		key, value, ok := parseDotEnvLine(scanner.Text())
		if !ok {
			continue
		}
		if _, exists := os.LookupEnv(key); exists {
			continue // real environment takes precedence
		}
		if err := os.Setenv(key, value); err != nil {
			return err
		}
	}
	return scanner.Err()
}

// parseDotEnvLine parses one line; ok is false for blanks, comments, and
// malformed lines.
func parseDotEnvLine(line string) (key, value string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false
	}
	line = strings.TrimPrefix(line, "export ")

	eq := strings.IndexByte(line, '=')
	if eq <= 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:eq])
	value = strings.TrimSpace(line[eq+1:])
	value = unquote(value)
	return key, value, key != ""
}

// unquote strips a matching pair of surrounding single or double quotes.
func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}
