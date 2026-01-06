package main

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func resolveImageVersion() string {
	if v := strings.TrimSpace(os.Getenv("IMAGE_VERSION")); v != "" {
		return v
	}

	wd, err := os.Getwd()
	if err != nil {
		return "unknown"
	}

	gitDir, err := findGitDir(wd)
	if err != nil {
		return "unknown"
	}

	sha, err := gitHeadSHA(gitDir)
	if err != nil {
		return "unknown"
	}
	sha = strings.TrimSpace(sha)
	if sha == "" {
		return "unknown"
	}
	if len(sha) > 12 {
		sha = sha[:12]
	}
	return sha
}

func resolveImageBuildDate() string {
	if v := strings.TrimSpace(os.Getenv("IMAGE_DATE")); v != "" {
		return v
	}
	return time.Now().UTC().Format(time.RFC3339)
}

func findGitDir(start string) (string, error) {
	dir := start
	for {
		candidate := filepath.Join(dir, ".git")
		info, err := os.Stat(candidate)
		if err == nil {
			if info.IsDir() {
				return candidate, nil
			}

			// Worktree/submodule checkout: .git is a file with "gitdir: <path>".
			if b, err := os.ReadFile(candidate); err == nil {
				line := strings.TrimSpace(string(b))
				if i := strings.IndexByte(line, '\n'); i >= 0 {
					line = line[:i]
				}
				if after, ok := strings.CutPrefix(line, "gitdir:"); ok {
					gitDir := strings.TrimSpace(after)
					if gitDir != "" {
						if !filepath.IsAbs(gitDir) {
							gitDir = filepath.Join(dir, gitDir)
						}
						return gitDir, nil
					}
				}
			}
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", errors.New("git directory not found")
}

func gitHeadSHA(gitDir string) (string, error) {
	b, err := os.ReadFile(filepath.Join(gitDir, "HEAD"))
	if err != nil {
		return "", err
	}
	head := strings.TrimSpace(string(b))
	if head == "" {
		return "", errors.New("empty HEAD")
	}

	if after, ok := strings.CutPrefix(head, "ref:"); ok {
		ref := strings.TrimSpace(after)
		if ref == "" {
			return "", errors.New("empty HEAD ref")
		}

		refPath := filepath.Join(gitDir, filepath.FromSlash(ref))
		if rb, err := os.ReadFile(refPath); err == nil {
			sha := strings.TrimSpace(string(rb))
			if sha != "" {
				return sha, nil
			}
		}

		sha, err := readPackedRef(gitDir, ref)
		if err != nil {
			return "", err
		}
		if sha != "" {
			return sha, nil
		}
		return "", errors.New("ref not found")
	}

	// Detached HEAD (commit SHA directly in HEAD).
	return head, nil
}

func readPackedRef(gitDir, ref string) (string, error) {
	f, err := os.Open(filepath.Join(gitDir, "packed-refs"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "^") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		if fields[1] == ref {
			return fields[0], nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", nil
}
