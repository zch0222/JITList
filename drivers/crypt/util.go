package crypt

import (
	stdpath "path"
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
