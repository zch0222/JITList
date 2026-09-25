package crypt

import (
	"context"
	"encoding/json"
	"io"
	"os"
	stdpath "path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/OpenListTeam/OpenList/v4/drivers/local"
	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/db"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/OpenListTeam/OpenList/v4/internal/stream"
	"github.com/OpenListTeam/OpenList/v4/pkg/http_range"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func init() {
	dB, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	conf.Conf = conf.DefaultConfig("data")
	db.Init(dB)
}

// newCryptOnLocal mounts a crypt storage with shortening enabled over a fresh
// local storage and returns the driver plus the paths of the encrypted data
func newCryptOnLocal(t *testing.T) (d *Crypt, remotePath, dataDir string) {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	suffix := strings.NewReplacer("/", "_", " ", "_").Replace(t.Name())
	localMount := "/local_" + suffix
	cryptMount := "/crypt_" + suffix
	remotePath = localMount + "/data"
	dataDir = filepath.Join(root, "data")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}

	localAddition, err := json.Marshal(map[string]string{"root_folder_path": root})
	if err != nil {
		t.Fatal(err)
	}
	localID, err := op.CreateStorage(ctx, model.Storage{
		Driver:    "Local",
		MountPath: localMount,
		Addition:  string(localAddition),
	})
	if err != nil {
		t.Fatalf("create local storage: %v", err)
	}
	t.Cleanup(func() { deleteStorage(t, localID) })

	addition, err := json.Marshal(Addition{
		FileNameEnc:      "standard",
		DirNameEnc:       "true",
		RemotePath:       remotePath,
		Password:         "password",
		Salt:             "salt",
		EncryptedSuffix:  ".bin",
		FileNameEncoding: "base64",
		FileNameShorten:  true,
		ShowHidden:       true,
	})
	if err != nil {
		t.Fatal(err)
	}
	cryptID, err := op.CreateStorage(ctx, model.Storage{
		Driver:    "Crypt",
		MountPath: cryptMount,
		Addition:  string(addition),
	})
	if err != nil {
		t.Fatalf("create crypt storage: %v", err)
	}
	t.Cleanup(func() { deleteStorage(t, cryptID) })

	driverStorage, err := op.GetStorageByMountPath(cryptMount)
	if err != nil {
		t.Fatalf("get crypt storage: %v", err)
	}
	d, ok := driverStorage.(*Crypt)
	if !ok {
		t.Fatalf("crypt mount is backed by %T", driverStorage)
	}
	return d, remotePath, dataDir
}

// TestLegacyIndexOnRealStorage covers an index written under the plain name by
// an earlier version: it stays readable and openable, and the next write
// migrates it to the encrypted name
func TestLegacyIndexOnRealStorage(t *testing.T) {
	ctx := context.Background()
	d, remotePath, dataDir := newCryptOnLocal(t)
	parent := &model.Object{Path: remotePath, Name: "data", IsFolder: true}

	dirEnc := d.cipher.EncryptDirName("k")
	dirShort := shortName(dirEnc)
	legacyPath := filepath.Join(dataDir, indexFileName)
	if err := os.WriteFile(legacyPath, encryptedTestIndex(t, d, map[string]string{dirShort: dirEnc}), 0o644); err != nil {
		t.Fatal(err)
	}

	requireIndexEntry(t, ctx, d, remotePath, dirShort, dirEnc)

	objs, err := d.List(ctx, parent, model.ListArgs{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	found := false
	for _, obj := range objs {
		if obj.GetName() == indexFileName {
			found = true
		}
	}
	if !found {
		t.Errorf("the plain-named index is missing from the listing")
	}

	indexObj, err := d.Get(ctx, "/"+indexFileName)
	if err != nil {
		t.Fatalf("Get(%s): %v", indexFileName, err)
	}
	if want := stdpath.Join(remotePath, indexFileName); indexObj.GetPath() != want {
		t.Errorf("index obj path = %q, want %q", indexObj.GetPath(), want)
	}

	// the next write moves the index to the encrypted name
	if err := d.MakeDir(ctx, parent, "k2"); err != nil {
		t.Fatalf("MakeDir: %v", err)
	}
	if _, err := os.Stat(legacyPath); err == nil {
		t.Errorf("the plain-named index should be gone after it was migrated")
	}
	requireOnDisk(t, filepath.Join(dataDir, d.indexFileNames()[0]))
	requireIndexEntry(t, ctx, d, remotePath, dirShort, dirEnc)
}

func deleteStorage(t *testing.T, id uint) {
	t.Helper()
	if err := op.DeleteStorageById(context.Background(), id); err != nil {
		t.Errorf("delete fixture storage %d: %v", id, err)
	}
}

func requireOnDisk(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Errorf("%s is missing on the underlying storage: %v", path, err)
	}
}

func requireIndexEntry(t *testing.T, ctx context.Context, d *Crypt, dir, short, enc string) map[string]string {
	t.Helper()
	idx, err := d.loadIndex(ctx, dir)
	if err != nil {
		t.Fatalf("loadIndex(%s): %v", dir, err)
	}
	if idx[short] != enc {
		t.Errorf("index[%s] = %q, want %q (index: %v)", short, idx[short], enc, idx)
	}
	return idx
}

// TestIndexOnRealStorage drives the driver through the real fs/op stack. The
// index paths have to resolve there, which only happens when the driver hands
// over object paths instead of the mount-stripped paths of the op layer.
func TestIndexOnRealStorage(t *testing.T) {
	ctx := context.Background()
	d, remotePath, dataDir := newCryptOnLocal(t)
	parent := &model.Object{Path: remotePath, Name: "data", IsFolder: true}

	// creating a directory registers its short name before the mkdir
	if err := d.MakeDir(ctx, parent, "k"); err != nil {
		t.Fatalf("MakeDir: %v", err)
	}
	dirEnc := d.cipher.EncryptDirName("k")
	dirShort := shortName(dirEnc)
	requireOnDisk(t, filepath.Join(dataDir, dirShort))
	requireIndexEntry(t, ctx, d, remotePath, dirShort, dirEnc)

	// on the remote the index lives under its encrypted name
	requireOnDisk(t, filepath.Join(dataDir, d.indexFileNames()[0]))
	if _, err := os.Stat(filepath.Join(dataDir, indexFileName)); err == nil {
		t.Errorf("the index is also present under its plain name")
	}

	// uploading a file does the same for its name
	const contents = "hello"
	fileStream := &stream.FileStream{
		Obj:    &model.Object{Name: "hello.txt", Size: int64(len(contents)), Modified: time.Now()},
		Reader: strings.NewReader(contents),
	}
	if err := d.Put(ctx, parent, fileStream, func(float64) {}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	fileEnc := d.cipher.EncryptFileName("hello.txt")
	fileShort := shortName(fileEnc)
	requireOnDisk(t, filepath.Join(dataDir, fileShort))
	requireIndexEntry(t, ctx, d, remotePath, fileShort, fileEnc)

	// the listing resolves the short names and shows the index file as well
	objs, err := d.List(ctx, parent, model.ListArgs{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	names := map[string]int64{}
	for _, obj := range objs {
		names[obj.GetName()] = obj.GetSize()
	}
	if _, ok := names["k"]; !ok {
		t.Errorf("listing %v is missing the created directory", names)
	}
	if size := names["hello.txt"]; size != int64(len(contents)) {
		t.Errorf("listing %v reports %d bytes for the file, want %d", names, size, len(contents))
	}
	if _, ok := names[indexFileName]; !ok {
		t.Errorf("listing %v is missing the index file", names)
	}

	// the index file opens and downloads like any other entry; the download
	// is the decrypted mapping
	indexObj, err := d.Get(ctx, "/"+indexFileName)
	if err != nil {
		t.Fatalf("Get(%s): %v", indexFileName, err)
	}
	if indexObj.GetName() != indexFileName {
		t.Errorf("index obj name = %q, want %q", indexObj.GetName(), indexFileName)
	}
	if indexObj.IsDir() {
		t.Errorf("index obj is reported as a directory")
	}
	link, err := d.Link(ctx, indexObj, model.LinkArgs{})
	if err != nil {
		t.Fatalf("Link(%s): %v", indexFileName, err)
	}
	defer link.Close()
	rc, err := link.RangeReader.RangeRead(ctx, http_range.Range{Start: 0, Length: -1})
	if err != nil {
		t.Fatalf("RangeRead(%s): %v", indexFileName, err)
	}
	defer rc.Close()
	downloaded, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read %s: %v", indexFileName, err)
	}
	if int64(len(downloaded)) != indexObj.GetSize() {
		t.Errorf("downloaded %d bytes, the object reports %d", len(downloaded), indexObj.GetSize())
	}
	var downloadedIndex indexFile
	if err := json.Unmarshal(downloaded, &downloadedIndex); err != nil {
		t.Fatalf("the downloaded index is not valid JSON: %v", err)
	}
	if downloadedIndex.Names[fileShort] != fileEnc {
		t.Errorf("the downloaded index misses the uploaded file: %v", downloadedIndex.Names)
	}

	// renaming moves the entry over to the new short name
	dirObj := &model.Object{Path: stdpath.Join(remotePath, dirShort), Name: dirShort, IsFolder: true}
	if err := d.Rename(ctx, dirObj, "k2"); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	dirEnc2 := d.cipher.EncryptDirName("k2")
	dirShort2 := shortName(dirEnc2)
	requireOnDisk(t, filepath.Join(dataDir, dirShort2))
	idx := requireIndexEntry(t, ctx, d, remotePath, dirShort2, dirEnc2)
	if _, stale := idx[dirShort]; stale {
		t.Errorf("the index kept the old short name after the rename: %v", idx)
	}

	// removing a file drops its entry
	fileObj := &model.Object{Path: stdpath.Join(remotePath, fileShort), Name: fileShort}
	if err := d.Remove(ctx, fileObj); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	idx, err = d.loadIndex(ctx, remotePath)
	if err != nil {
		t.Fatalf("loadIndex: %v", err)
	}
	if _, stale := idx[fileShort]; stale {
		t.Errorf("the index kept the removed file's entry: %v", idx)
	}
}
