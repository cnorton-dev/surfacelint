// Package history provides opt-in local scan history using a portable JSON Lines format.
// It deliberately has no network or database-server dependency.
package history

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cnorton-dev/surfacelint/internal/model"
)

const maxEntryBytes = 4 * 1024 * 1024

// Store writes results in files owned by the local user, one file per hostname.
type Store struct{ Dir string }

func DefaultDir() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "surfacelint", "history"), nil
}

func (s Store) filename(domain string) (string, error) {
	if domain == "" || strings.ContainsAny(domain, `/\\`) || domain == "." || domain == ".." || strings.HasPrefix(domain, ".") {
		return "", fmt.Errorf("unsafe history hostname %q", domain)
	}
	for _, r := range domain {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.') {
			return "", fmt.Errorf("unsafe history hostname %q", domain)
		}
	}
	if s.Dir == "" {
		return "", errors.New("history directory not configured")
	}
	return filepath.Join(s.Dir, domain+".jsonl"), nil
}

func (s Store) Append(result model.Result) error {
	path, err := s.filename(result.Target)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.Dir, 0700); err != nil {
		return fmt.Errorf("create history directory: %w", err)
	}
	payload, err := json.Marshal(result)
	if err != nil {
		return err
	}
	if len(payload) > maxEntryBytes {
		return fmt.Errorf("scan result exceeds %d-byte history entry limit", maxEntryBytes)
	}
	payload = append(payload, '\n')
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Chmod(0600); err != nil {
		return err
	}
	n, err := f.Write(payload)
	if err != nil {
		return err
	}
	if n != len(payload) {
		return fmt.Errorf("incomplete history write")
	}
	return f.Sync()
}

// List returns oldest-to-newest results. Missing history is an empty list.
func (s Store) List(domain string) ([]model.Result, error) {
	path, err := s.filename(domain)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return []model.Result{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), maxEntryBytes+1)
	var results []model.Result
	line := 0
	for scanner.Scan() {
		line++
		var result model.Result
		if err := json.Unmarshal(scanner.Bytes(), &result); err != nil {
			return nil, fmt.Errorf("invalid history entry at line %d: %w", line, err)
		}
		if result.Target != domain {
			return nil, fmt.Errorf("unexpected target at history line %d", line)
		}
		results = append(results, result)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read history: %w", err)
	}
	sort.SliceStable(results, func(i, j int) bool { return results[i].ScannedAt.Before(results[j].ScannedAt) })
	return results, nil
}
