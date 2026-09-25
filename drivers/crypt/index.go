package crypt

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	stdpath "path"
	"regexp"
	"strings"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/errs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/OpenListTeam/OpenList/v4/internal/stream"
	"github.com/OpenListTeam/OpenList/v4/pkg/http_range"
	log "github.com/sirupsen/logrus"
)

const nameEncOff = "off"

// When name shortening is enabled, every encrypted name is stored under a
// short name: "!" + 24 hex chars derived from the SHA-256 of the full
// encrypted name. The mapping back to the encrypted name is kept in a
// per-directory index file, so it survives OpenList reinstalls. The index
// file has a plain name and is listed like any other entry.
const (
	indexFileName     = "opcrypt.idx"
	shortNamePrefix   = "!"
	shortNameHexChars = 24
	shortNameTotalLen = 1 + shortNameHexChars
	indexVersion      = 1
)

var shortNameRe = regexp.MustCompile(`^![0-9a-f]{` + fmt.Sprint(shortNameHexChars) + `}$`)

func shortName(encName string) string {
	sum := sha256.Sum256([]byte(encName))
	return shortNamePrefix + hex.EncodeToString(sum[:shortNameHexChars/2])
}

func isShortName(name string) bool {
	return shortNameRe.MatchString(name)
}

// fileIO abstracts remote file access so the name index logic stays testable
type fileIO interface {
	ReadFile(ctx context.Context, path string) ([]byte, error)
	WriteFile(ctx context.Context, dir, name string, data []byte) error
	Remove(ctx context.Context, path string) error
}

// fsIO is the fileIO implementation backed by the mounted remote storage.
// Paths go through the fs layer, so callers must pass the same object paths
// the driver uses for fs.List/fs.Move, with the mount path included, not the
// paths the op layer returns once the mount path has been stripped
type fsIO struct{}

func (fsIO) ReadFile(ctx context.Context, path string) ([]byte, error) {
	remoteStorage, actualPath, err := op.GetStorageAndActualPath(path)
	if err != nil {
		return nil, err
	}
	remoteLink, remoteFile, err := op.Link(ctx, remoteStorage, actualPath, model.LinkArgs{})
	if err != nil {
		return nil, err
	}
	defer remoteLink.Close()
	remoteSize := remoteLink.ContentLength
	if remoteSize <= 0 {
		remoteSize = remoteFile.GetSize()
	}
	if remoteSize <= 0 {
		return nil, fmt.Errorf("file %s is empty", path)
	}
	rrf, err := stream.GetRangeReaderFromLink(remoteSize, remoteLink)
	if err != nil {
		return nil, err
	}
	rc, err := rrf.RangeRead(ctx, http_range.Range{Start: 0, Length: remoteSize})
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

func (fsIO) WriteFile(ctx context.Context, dir, name string, data []byte) error {
	remoteStorage, actualPath, err := op.GetStorageAndActualPath(dir)
	if err != nil {
		return err
	}
	fileStream := &stream.FileStream{
		Obj: &model.Object{
			Name:     name,
			Size:     int64(len(data)),
			Modified: time.Now(),
		},
		Reader:            bytes.NewReader(data),
		Mimetype:          "application/octet-stream",
		ForceStreamUpload: true,
	}
	return op.Put(ctx, remoteStorage, actualPath, fileStream, nil)
}

func (fsIO) Remove(ctx context.Context, path string) error {
	remoteStorage, actualPath, err := op.GetStorageAndActualPath(path)
	if err != nil {
		return err
	}
	return op.Remove(ctx, remoteStorage, actualPath)
}

type indexFile struct {
	Version int               `json:"version"`
	Names   map[string]string `json:"names"`
}

func (d *Crypt) loadIndex(ctx context.Context, remoteDir string) (map[string]string, error) {
	data, err := d.fileIO.ReadFile(ctx, stdpath.Join(remoteDir, indexFileName))
	if err != nil {
		if errs.IsObjectNotFound(err) {
			return map[string]string{}, nil
		}
		return nil, err
	}
	dec, err := d.cipher.DecryptData(io.NopCloser(bytes.NewReader(data)))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt name index: %w", err)
	}
	defer dec.Close()
	plain, err := io.ReadAll(dec)
	if err != nil {
		return nil, fmt.Errorf("failed to read name index: %w", err)
	}
	var idx indexFile
	if err := json.Unmarshal(plain, &idx); err != nil {
		return nil, fmt.Errorf("failed to parse name index: %w", err)
	}
	if idx.Version != indexVersion {
		return nil, fmt.Errorf("unsupported name index version %d", idx.Version)
	}
	if idx.Names == nil {
		return map[string]string{}, nil
	}
	return idx.Names, nil
}

func (d *Crypt) saveIndex(ctx context.Context, remoteDir string, m map[string]string) error {
	indexPath := stdpath.Join(remoteDir, indexFileName)
	if len(m) == 0 {
		if err := d.fileIO.Remove(ctx, indexPath); err != nil && !errs.IsObjectNotFound(err) {
			return err
		}
		return nil
	}
	plain, err := json.Marshal(indexFile{Version: indexVersion, Names: m})
	if err != nil {
		return err
	}
	encReader, err := d.cipher.EncryptData(bytes.NewReader(plain))
	if err != nil {
		return err
	}
	data, err := io.ReadAll(encReader)
	if err != nil {
		return err
	}
	return d.fileIO.WriteFile(ctx, remoteDir, indexFileName, data)
}

// updateIndex re-reads the index and applies mutate before writing it back,
// so concurrent writes from other instances are merged instead of overwritten
func (d *Crypt) updateIndex(ctx context.Context, remoteDir string, mutate func(m map[string]string) error) error {
	d.idxMu.Lock()
	defer d.idxMu.Unlock()
	m, err := d.loadIndex(ctx, remoteDir)
	if err != nil {
		return err
	}
	if err := mutate(m); err != nil {
		return err
	}
	return d.saveIndex(ctx, remoteDir, m)
}

func (d *Crypt) addIndexEntry(ctx context.Context, remoteDir, shortKey, encName string) error {
	return d.updateIndex(ctx, remoteDir, func(m map[string]string) error {
		if old, ok := m[shortKey]; ok && old != encName {
			return fmt.Errorf("short name collision in %s: %s", remoteDir, shortKey)
		}
		m[shortKey] = encName
		return nil
	})
}

func (d *Crypt) removeIndexEntry(ctx context.Context, remoteDir, shortKey string) error {
	return d.updateIndex(ctx, remoteDir, func(m map[string]string) error {
		delete(m, shortKey)
		return nil
	})
}

func (d *Crypt) lookupIndexEntry(ctx context.Context, remoteDir, shortKey string) (string, error) {
	m, err := d.loadIndex(ctx, remoteDir)
	if err != nil {
		return "", err
	}
	return m[shortKey], nil
}

// shortening only applies to names that are actually encrypted: with
// filename encryption off the plain name is stored, and a short name would
// never be attempted on decryption
func (d *Crypt) fileShorteningActive() bool {
	return d.FileNameShorten && d.FileNameEnc != nameEncOff
}

func (d *Crypt) dirShorteningActive() bool {
	return d.fileShorteningActive() && d.DirNameEnc == "true"
}

// shortenFileName maps an encrypted file name to its short name when the
// shortening switch is on
func (d *Crypt) shortenFileName(encName string) string {
	if !d.fileShorteningActive() {
		return encName
	}
	return shortName(encName)
}

// shortenDirName maps an encrypted directory name to its short name when the
// shortening switch is on
func (d *Crypt) shortenDirName(encName string) string {
	if !d.dirShorteningActive() {
		return encName
	}
	return shortName(encName)
}

// shortenDirPathSegments shortens each encrypted directory segment of a path
func (d *Crypt) shortenDirPathSegments(encPath string) string {
	if !d.dirShorteningActive() {
		return encPath
	}
	segments := strings.Split(encPath, "/")
	for i, seg := range segments {
		if seg != "" {
			segments[i] = shortName(seg)
		}
	}
	return strings.Join(segments, "/")
}

// decryptRemoteName decrypts a raw remote name, falling back to the
// directory index for short names. The index is only a secondary source: a
// name it cannot resolve is reported as undecryptable, exactly as when the
// shortening switch is off
func (d *Crypt) decryptRemoteName(ctx context.Context, remoteFullPath, rawName string, isDir bool) (string, error) {
	// the index file is stored unencrypted and is shown as a normal entry
	if rawName == indexFileName {
		return rawName, nil
	}
	if isDir {
		if name, err := d.cipher.DecryptDirName(rawName); err == nil {
			return name, nil
		}
	} else if name, err := d.cipher.DecryptFileName(rawName); err == nil {
		return name, nil
	}
	if d.fileShorteningActive() && isShortName(rawName) {
		dir := stdpath.Dir(remoteFullPath)
		m, err := d.loadIndex(ctx, dir)
		if err != nil {
			return "", fmt.Errorf("failed to load name index of %s: %w", dir, err)
		}
		if encName, ok := m[rawName]; ok {
			if isDir {
				return d.cipher.DecryptDirName(encName)
			}
			return d.cipher.DecryptFileName(encName)
		}
	}
	return "", fmt.Errorf("failed to decrypt name %q", rawName)
}

// listedObj is one entry of a resolved directory listing
type listedObj struct {
	remote model.Obj
	name   string // decrypted display name
	size   int64  // decrypted size for files, raw size for others
}

// resolveListing maps raw remote objects to decrypted names, resolving
// short names through the directory index. Entries whose names cannot be
// decrypted are dropped, and a short name without an index entry falls back
// to that default path, so a missing or unreadable index never breaks a
// listing: it only leaves the shortened entries unresolvable
func (d *Crypt) resolveListing(ctx context.Context, remoteDirPath string, objs []model.Obj) []listedObj {
	out := make([]listedObj, 0, len(objs))
	type pendingShort struct {
		remote model.Obj
		size   int64
	}
	var shorts []pendingShort
	for _, obj := range objs {
		rawName := model.UnwrapObjName(obj).GetName()
		mask := model.GetObjMask(obj)
		if mask&model.Virtual != 0 {
			out = append(out, listedObj{remote: obj, name: rawName, size: obj.GetSize()})
			continue
		}
		// the index file is stored unencrypted and is shown as a normal entry
		if rawName == indexFileName {
			size := obj.GetSize()
			if decryptedSize, err := d.cipher.DecryptedSize(size); err == nil {
				size = decryptedSize
			}
			out = append(out, listedObj{remote: obj, name: rawName, size: size})
			continue
		}
		if obj.IsDir() {
			name, err := d.cipher.DecryptDirName(rawName)
			if err != nil {
				if isShortName(rawName) {
					shorts = append(shorts, pendingShort{remote: obj})
				}
				continue
			}
			out = append(out, listedObj{remote: obj, name: name, size: obj.GetSize()})
			continue
		}
		size, err := d.cipher.DecryptedSize(obj.GetSize())
		if err != nil {
			continue
		}
		name, err := d.cipher.DecryptFileName(rawName)
		if err != nil {
			if isShortName(rawName) {
				shorts = append(shorts, pendingShort{remote: obj, size: size})
			}
			continue
		}
		out = append(out, listedObj{remote: obj, name: name, size: size})
	}
	if len(shorts) > 0 {
		m, err := d.loadIndex(ctx, remoteDirPath)
		if err != nil {
			log.Warnf("crypt: failed to load name index of %s: %v", remoteDirPath, err)
			return out
		}
		for _, p := range shorts {
			rawName := model.UnwrapObjName(p.remote).GetName()
			encName, ok := m[rawName]
			if !ok {
				// no mapping for this short name: fall back to the default
				// handling of an undecryptable name and leave the entry out
				log.Debugf("crypt: short name %s has no index entry in %s", rawName, remoteDirPath)
				continue
			}
			var name string
			if p.remote.IsDir() {
				name, err = d.cipher.DecryptDirName(encName)
			} else {
				name, err = d.cipher.DecryptFileName(encName)
			}
			if err != nil {
				log.Debugf("crypt: failed to decrypt index entry %s in %s: %v", rawName, remoteDirPath, err)
				continue
			}
			out = append(out, listedObj{remote: p.remote, name: name, size: p.size})
		}
	}
	return out
}
