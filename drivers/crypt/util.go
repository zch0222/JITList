package crypt

import (
	stdpath "path"
	"slices"
	"strings"
)

// will give the best guessing based on the path
func guessPath(path string) (isFolder, secondTry bool) {
	if strings.HasSuffix(path, "/") {
		//confirmed a folder
		return true, false
	}
	lastSlash := strings.LastIndex(path, "/")
	if !strings.Contains(path[lastSlash:], ".") {
		//no dot, try folder then try file
		return true, true
	}
	return false, true
}

func (d *Crypt) encryptPath(path string, isFolder bool) string {
	if isFolder {
		return d.shortenDirPathSegments(d.cipher.EncryptDirName(path))
	}
	dir, fileName := stdpath.Split(path)
	return stdpath.Join(d.shortenDirPathSegments(d.cipher.EncryptDirName(dir)), d.shortenFileName(d.cipher.EncryptFileName(fileName)))
}

// encryptFullPath is encryptPath without shortening: the layout of entries
// written while the shortening switch was off
func (d *Crypt) encryptFullPath(path string, isFolder bool) string {
	if isFolder {
		return d.cipher.EncryptDirName(path)
	}
	dir, fileName := stdpath.Split(path)
	return stdpath.Join(d.cipher.EncryptDirName(dir), d.cipher.EncryptFileName(fileName))
}

// remotePathCandidates lists the paths, relative to RemotePath, that the entry
// at path may be stored under, in lookup order: the kind guessed from the path
// before the opposite one when the guess is uncertain, each under its
// shortened name before the full encrypted name it has when written while the
// switch was off
func (d *Crypt) remotePathCandidates(path string) []string {
	isFolder, secondTry := guessPath(path)
	kinds := []bool{isFolder}
	if secondTry {
		kinds = append(kinds, !isFolder)
	}
	var candidates []string
	for _, asFolder := range kinds {
		for _, p := range []string{d.encryptPath(path, asFolder), d.encryptFullPath(path, asFolder)} {
			if !slices.Contains(candidates, p) {
				candidates = append(candidates, p)
			}
		}
	}
	return candidates
}
