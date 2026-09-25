package crypt

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	stdpath "path"
	"regexp"
	"strings"
	"sync"

	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/errs"
	"github.com/OpenListTeam/OpenList/v4/internal/fs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/OpenListTeam/OpenList/v4/internal/sign"
	"github.com/OpenListTeam/OpenList/v4/internal/stream"
	"github.com/OpenListTeam/OpenList/v4/pkg/http_range"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	"github.com/OpenListTeam/OpenList/v4/server/common"
	rcCrypt "github.com/rclone/rclone/backend/crypt"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/obscure"
	log "github.com/sirupsen/logrus"
)

type Crypt struct {
	model.Storage
	Addition
	cipher *rcCrypt.Cipher
	fileIO fileIO
	idxMu  sync.Mutex
}

const obfuscatedPrefix = "___Obfuscated___"

func (d *Crypt) Config() driver.Config {
	return config
}

func (d *Crypt) GetAddition() driver.Additional {
	return &d.Addition
}

func (d *Crypt) Init(ctx context.Context) error {
	// obfuscate credentials if it's updated or just created
	err := d.updateObfusParm(&d.Password)
	if err != nil {
		return fmt.Errorf("failed to obfuscate password: %w", err)
	}
	err = d.updateObfusParm(&d.Salt)
	if err != nil {
		return fmt.Errorf("failed to obfuscate salt: %w", err)
	}

	isCryptExt := regexp.MustCompile(`^[.][A-Za-z0-9-_]{2,}$`).MatchString
	if !isCryptExt(d.EncryptedSuffix) {
		return fmt.Errorf("EncryptedSuffix is Illegal")
	}
	d.FileNameEncoding = utils.GetNoneEmpty(d.FileNameEncoding, "base64")
	d.EncryptedSuffix = utils.GetNoneEmpty(d.EncryptedSuffix, ".bin")
	d.RemotePath = utils.FixAndCleanPath(d.RemotePath)
	if d.FileNameLengthLimit < 0 {
		return fmt.Errorf("filename_length_limit must be >= 0")
	}
	if d.FileNameLengthLimit > 0 && d.FileNameLengthLimit < minFileNameLengthLimit {
		return fmt.Errorf("filename_length_limit must be 0 (disabled) or at least %d", minFileNameLengthLimit)
	}

	p, _ := strings.CutPrefix(d.Password, obfuscatedPrefix)
	p2, _ := strings.CutPrefix(d.Salt, obfuscatedPrefix)
	config := configmap.Simple{
		"password":                  p,
		"password2":                 p2,
		"filename_encryption":       d.FileNameEnc,
		"directory_name_encryption": d.DirNameEnc,
		"filename_encoding":         d.FileNameEncoding,
		"suffix":                    d.EncryptedSuffix,
		"pass_bad_blocks":           "",
	}
	c, err := rcCrypt.NewCipher(config)
	if err != nil {
		return fmt.Errorf("failed to create Cipher: %w", err)
	}
	d.cipher = c
	d.fileIO = fsIO{}

	return nil
}

func (d *Crypt) updateObfusParm(str *string) error {
	temp := *str
	if !strings.HasPrefix(temp, obfuscatedPrefix) {
		temp, err := obscure.Obscure(temp)
		if err != nil {
			return err
		}
		temp = obfuscatedPrefix + temp
		*str = temp
	}
	return nil
}

func (d *Crypt) Drop(ctx context.Context) error {
	return nil
}

func (d *Crypt) List(ctx context.Context, dir model.Obj, args model.ListArgs) ([]model.Obj, error) {
	remoteFullPath := dir.GetPath()
	objs, err := fs.List(ctx, remoteFullPath, &fs.ListArgs{NoLog: true, Refresh: args.Refresh})
	// the obj must implement the model.SetPath interface
	// return objs, err
	if err != nil {
		return nil, err
	}

	resolved := d.resolveListing(ctx, remoteFullPath, objs)
	result := make([]model.Obj, 0, len(resolved))
	for _, r := range resolved {
		if !d.ShowHidden && strings.HasPrefix(r.name, ".") {
			continue
		}
		objRes := &model.Object{
			Path:     stdpath.Join(remoteFullPath, r.remote.GetName()),
			Name:     r.name,
			Size:     r.size,
			Modified: r.remote.ModTime(),
			IsFolder: r.remote.IsDir(),
			Ctime:    r.remote.CreateTime(),
			Mask:     model.GetObjMask(r.remote) &^ model.Temp,
			// discarding hash as it's encrypted
		}
		if !d.Thumbnail || !strings.HasPrefix(args.ReqPath, "/") {
			result = append(result, objRes)
			continue
		}
		thumbPath := stdpath.Join(args.ReqPath, ".thumbnails", r.name+".webp")
		thumb := fmt.Sprintf("%s/d%s?sign=%s",
			common.GetApiUrl(ctx),
			utils.EncodePath(thumbPath, true),
			sign.Sign(thumbPath))
		result = append(result, &model.ObjThumb{
			Object: *objRes,
			Thumbnail: model.Thumbnail{
				Thumbnail: thumb,
			},
		})
	}

	return result, nil
}

func (a Addition) GetRootPath() string {
	return a.RemotePath
}

func (d *Crypt) Get(ctx context.Context, path string) (model.Obj, error) {
	firstTryIsFolder, secondTry := guessPath(path)
	remoteFullPath := stdpath.Join(d.RemotePath, d.encryptPath(path, firstTryIsFolder))
	remoteObj, err := fs.Get(ctx, remoteFullPath, &fs.GetArgs{NoLog: true})
	if err != nil {
		if errors.Is(err, errs.StorageNotFound) {
			remoteFullPath = stdpath.Join(d.RemotePath, path)
			remoteObj, err = fs.Get(ctx, remoteFullPath, &fs.GetArgs{NoLog: true})
			if err != nil {
				// 可能是 虚拟路径+开启文件夹加密：返回NotSupport让op.Get去尝试op.List查找
				return nil, errs.NotSupport
			}
		} else if secondTry && errs.IsObjectNotFound(err) {
			// try the opposite
			remoteFullPath = stdpath.Join(d.RemotePath, d.encryptPath(path, !firstTryIsFolder))
			remoteObj, err = fs.Get(ctx, remoteFullPath, &fs.GetArgs{NoLog: true})
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	size := remoteObj.GetSize()
	name := remoteObj.GetName()
	mask := model.GetObjMask(remoteObj) &^ model.Temp
	if mask&model.Virtual == 0 {
		if !remoteObj.IsDir() {
			decryptedSize, err := d.cipher.DecryptedSize(size)
			if err != nil {
				log.Warnf("DecryptedSize failed for %s ,will use original size, err:%s", path, err)
			} else {
				size = decryptedSize
			}
		}
		if decryptedName, err := d.decryptRemoteName(ctx, remoteFullPath, model.UnwrapObjName(remoteObj).GetName(), remoteObj.IsDir()); err == nil {
			name = decryptedName
		} else {
			log.Warnf("DecryptName failed for %s ,will use original name, err:%s", path, err)
		}
	}
	return &model.Object{
		Path:     remoteFullPath,
		Name:     name,
		Size:     size,
		Modified: remoteObj.ModTime(),
		IsFolder: remoteObj.IsDir(),
		Ctime:    remoteObj.CreateTime(),
		Mask:     mask,
	}, nil
}

// https://github.com/rclone/rclone/blob/v1.67.0/backend/crypt/cipher.go#L37
const fileHeaderSize = 32

func (d *Crypt) Link(ctx context.Context, file model.Obj, _ model.LinkArgs) (*model.Link, error) {
	remoteStorage, remoteActualPath, err := op.GetStorageAndActualPath(file.GetPath())
	if err != nil {
		return nil, err
	}
	remoteLink, remoteFile, err := op.Link(ctx, remoteStorage, remoteActualPath, model.LinkArgs{})
	if err != nil {
		return nil, err
	}

	remoteSize := remoteLink.ContentLength
	if remoteSize <= 0 {
		remoteSize = remoteFile.GetSize()
	}
	rrf, err := stream.GetRangeReaderFromLink(remoteSize, remoteLink)
	if err != nil {
		_ = remoteLink.Close()
		return nil, fmt.Errorf("the remote storage driver need to be enhanced to support encryption")
	}

	mu := &sync.Mutex{}
	var fileHeader []byte
	rangeReaderFunc := func(ctx context.Context, offset, limit int64) (io.ReadCloser, error) {
		length := limit
		if offset == 0 && limit > 0 {
			mu.Lock()
			if limit <= fileHeaderSize {
				defer mu.Unlock()
				if fileHeader != nil {
					return io.NopCloser(bytes.NewReader(fileHeader[:limit])), nil
				}
				length = fileHeaderSize
			} else if fileHeader == nil {
				defer mu.Unlock()
			} else {
				mu.Unlock()
			}
		}

		remoteReader, err := rrf.RangeRead(ctx, http_range.Range{Start: offset, Length: length})
		if err != nil {
			return nil, err
		}

		if offset == 0 && limit > 0 {
			fileHeader = make([]byte, fileHeaderSize)
			n, err := io.ReadFull(remoteReader, fileHeader)
			if n != fileHeaderSize {
				fileHeader = nil
				return nil, fmt.Errorf("failed to read all data: (expect =%d, actual =%d) %w", fileHeaderSize, n, err)
			}
			if limit <= fileHeaderSize {
				remoteReader.Close()
				return io.NopCloser(bytes.NewReader(fileHeader[:limit])), nil
			} else {
				remoteReader = utils.ReadCloser{
					Reader: io.MultiReader(bytes.NewReader(fileHeader), remoteReader),
					Closer: remoteReader,
				}
			}
		}
		return remoteReader, nil
	}
	return &model.Link{
		RangeReader: stream.RangeReaderFunc(func(ctx context.Context, httpRange http_range.Range) (io.ReadCloser, error) {
			readSeeker, err := d.cipher.DecryptDataSeek(ctx, rangeReaderFunc, httpRange.Start, httpRange.Length)
			if err != nil {
				return nil, err
			}
			return readSeeker, nil
		}),
		SyncClosers:      utils.NewSyncClosers(remoteLink),
		RequireReference: remoteLink.RequireReference,
	}, nil
}

func (d *Crypt) MakeDir(ctx context.Context, parentDir model.Obj, dirName string) error {
	remoteStorage, remoteActualPath, err := op.GetStorageAndActualPath(parentDir.GetPath())
	if err != nil {
		return err
	}
	encName := d.cipher.EncryptDirName(dirName)
	finalName := d.shortenDirName(encName)
	if finalName != encName {
		// register before creating: a stale entry is harmless, while an
		// unindexed short name would make the directory invisible
		if err := d.addIndexEntry(ctx, remoteActualPath, finalName, encName); err != nil {
			return fmt.Errorf("failed to update name index: %w", err)
		}
	}
	return op.MakeDir(ctx, remoteStorage, stdpath.Join(remoteActualPath, finalName))
}

func (d *Crypt) Move(ctx context.Context, srcObj, dstDir model.Obj) error {
	srcPath := srcObj.GetPath()
	srcDir := stdpath.Clean(stdpath.Dir(srcPath))
	srcName := stdpath.Base(srcPath)
	dstDirPath := dstDir.GetPath()
	// when moving an entry stored under a short name, the index entry must
	// follow it to the destination directory
	if d.fileShorteningActive() && srcDir != dstDirPath && isShortName(srcName) {
		encName, err := d.lookupIndexEntry(ctx, srcDir, srcName)
		if err != nil {
			log.Warnf("crypt: failed to load name index of %s: %v", srcDir, err)
		}
		if encName != "" {
			if err := d.addIndexEntry(ctx, dstDirPath, srcName, encName); err != nil {
				return fmt.Errorf("failed to update name index: %w", err)
			}
			if _, err := fs.Move(ctx, srcPath, dstDirPath); err != nil {
				return err
			}
			if err := d.removeIndexEntry(ctx, srcDir, srcName); err != nil {
				log.Warnf("crypt: failed to remove stale index entry %s: %v", srcName, err)
			}
			return nil
		}
	}
	_, err := fs.Move(ctx, srcPath, dstDirPath)
	return err
}

func (d *Crypt) Rename(ctx context.Context, srcObj model.Obj, newName string) error {
	remoteStorage, remoteActualPath, err := op.GetStorageAndActualPath(srcObj.GetPath())
	if err != nil {
		return err
	}
	dirPath := stdpath.Dir(remoteActualPath)
	oldName := stdpath.Base(remoteActualPath)
	var encName, finalName string
	if srcObj.IsDir() {
		encName = d.cipher.EncryptDirName(newName)
		finalName = d.shortenDirName(encName)
	} else {
		encName = d.cipher.EncryptFileName(newName)
		finalName = d.shortenFileName(encName)
	}
	if finalName != encName {
		// register the new short name before the rename; the old entry is
		// kept until the rename succeeds so a failure stays reversible
		if err := d.addIndexEntry(ctx, dirPath, finalName, encName); err != nil {
			return fmt.Errorf("failed to update name index: %w", err)
		}
	}
	if err := op.Rename(ctx, remoteStorage, remoteActualPath, finalName); err != nil {
		return err
	}
	if oldName != finalName && isShortName(oldName) {
		if err := d.removeIndexEntry(ctx, dirPath, oldName); err != nil {
			log.Warnf("crypt: failed to remove stale index entry %s: %v", oldName, err)
		}
	}
	return nil
}

func (d *Crypt) Copy(ctx context.Context, srcObj, dstDir model.Obj) error {
	srcPath := srcObj.GetPath()
	dstDirPath := dstDir.GetPath()
	if d.fileShorteningActive() {
		if srcName := stdpath.Base(srcPath); isShortName(srcName) {
			encName, err := d.lookupIndexEntry(ctx, stdpath.Dir(srcPath), srcName)
			if err != nil {
				log.Warnf("crypt: failed to load name index of %s: %v", stdpath.Dir(srcPath), err)
			}
			if encName != "" {
				// a stale entry is harmless if the copy fails
				if err := d.addIndexEntry(ctx, dstDirPath, srcName, encName); err != nil {
					return fmt.Errorf("failed to update name index: %w", err)
				}
			}
		}
	}
	_, err := fs.Copy(ctx, srcPath, dstDirPath)
	return err
}

func (d *Crypt) Remove(ctx context.Context, obj model.Obj) error {
	remoteStorage, remoteActualPath, err := op.GetStorageAndActualPath(obj.GetPath())
	if err != nil {
		return err
	}
	if err := op.Remove(ctx, remoteStorage, remoteActualPath); err != nil {
		return err
	}
	if d.fileShorteningActive() {
		if name := stdpath.Base(remoteActualPath); isShortName(name) {
			if err := d.removeIndexEntry(ctx, stdpath.Dir(remoteActualPath), name); err != nil {
				log.Warnf("crypt: failed to remove index entry of %s: %v", name, err)
			}
		}
	}
	return nil
}

func (d *Crypt) Put(ctx context.Context, dstDir model.Obj, streamer model.FileStreamer, up driver.UpdateProgress) error {
	remoteStorage, remoteActualPath, err := op.GetStorageAndActualPath(dstDir.GetPath())
	if err != nil {
		return err
	}

	// Encrypt the data into wrappedIn
	wrappedIn, err := d.cipher.EncryptData(streamer)
	if err != nil {
		return fmt.Errorf("failed to EncryptData: %w", err)
	}

	encName := d.cipher.EncryptFileName(streamer.GetName())
	finalName := d.shortenFileName(encName)
	if finalName != encName {
		// register before upload: a stale entry is harmless, while an
		// unindexed short name would make the upload invisible
		if err := d.addIndexEntry(ctx, remoteActualPath, finalName, encName); err != nil {
			return fmt.Errorf("failed to update name index: %w", err)
		}
	}

	// doesn't support seekableStream, since rapid-upload is not working for encrypted data
	streamOut := &stream.FileStream{
		Obj: &model.Object{
			ID:       streamer.GetID(),
			Path:     streamer.GetPath(),
			Name:     finalName,
			Size:     d.cipher.EncryptedSize(streamer.GetSize()),
			Modified: streamer.ModTime(),
			IsFolder: streamer.IsDir(),
		},
		Reader:            wrappedIn,
		Mimetype:          "application/octet-stream",
		ForceStreamUpload: true,
		Exist:             streamer.GetExist(),
	}
	return op.Put(ctx, remoteStorage, remoteActualPath, streamOut, up)
}

func (d *Crypt) GetDetails(ctx context.Context) (*model.StorageDetails, error) {
	remoteStorage, _, err := op.GetStorageAndActualPath(d.RemotePath)
	if err != nil {
		return nil, errs.NotImplement
	}
	remoteDetails, err := op.GetStorageDetails(ctx, remoteStorage)
	if err != nil {
		return nil, err
	}
	return &model.StorageDetails{
		DiskUsage: remoteDetails.DiskUsage,
	}, nil
}

var _ driver.Driver = (*Crypt)(nil)
