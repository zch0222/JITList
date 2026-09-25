package crypt

import (
	"context"
	"encoding/json"
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
