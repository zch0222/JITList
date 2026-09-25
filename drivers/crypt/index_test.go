package crypt

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	stdpath "path"
	"strings"
	"testing"

	"github.com/OpenListTeam/OpenList/v4/internal/errs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	rcCrypt "github.com/rclone/rclone/backend/crypt"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/obscure"
)

// memIO is an in-memory fileIO for unit tests
type memIO struct {
	files map[string][]byte
}

func (m *memIO) ReadFile(ctx context.Context, path string) ([]byte, error) {
	if data, ok := m.files[path]; ok {
		return data, nil
	}
	return nil, errs.ObjectNotFound
}

func (m *memIO) WriteFile(ctx context.Context, dir, name string, data []byte) error {
	m.files[stdpath.Join(dir, name)] = data
	return nil
}

func (m *memIO) Remove(ctx context.Context, path string) error {
	if _, ok := m.files[path]; !ok {
		return errs.ObjectNotFound
	}
	delete(m.files, path)
	return nil
}

func testCipher(t *testing.T, mode, dirEnc, password string) *rcCrypt.Cipher {
	t.Helper()
	pwd, err := obscure.Obscure(password)
	if err != nil {
		t.Fatalf("obscure password: %v", err)
	}
	salt, err := obscure.Obscure("salt")
	if err != nil {
		t.Fatalf("obscure salt: %v", err)
	}
	c, err := rcCrypt.NewCipher(configmap.Simple{
		"password":                  pwd,
		"password2":                 salt,
		"filename_encryption":       mode,
		"directory_name_encryption": dirEnc,
		"filename_encoding":         "base64",
		"suffix":                    ".bin",
		"pass_bad_blocks":           "",
	})
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	return c
}

func newTestCrypt(t *testing.T, mode, dirEnc string, shorten bool, io fileIO) *Crypt {
	t.Helper()
	return &Crypt{
		Addition: Addition{
			FileNameEnc:     mode,
			DirNameEnc:      dirEnc,
			FileNameShorten: shorten,
		},
		cipher: testCipher(t, mode, dirEnc, "password"),
		fileIO: io,
	}
}

func newMemIO() *memIO {
	return &memIO{files: map[string][]byte{}}
}

func TestShortNameFormat(t *testing.T) {
	sh := shortName("some-encrypted-name")
	if len(sh) != shortNameTotalLen {
		t.Errorf("shortName length = %d, want %d", len(sh), shortNameTotalLen)
	}
	if !isShortName(sh) {
		t.Errorf("shortName %q doesn't match the short name pattern", sh)
	}
	if shortName("some-encrypted-name") != sh {
		t.Errorf("shortName is not deterministic")
	}
	if shortName("another-name") == sh {
		t.Errorf("distinct inputs produced the same short name")
	}
	for _, bad := range []string{"", "!", "abc", "!zz", sh + "0", strings.ToUpper(sh)} {
		if isShortName(bad) {
			t.Errorf("isShortName(%q) = true, want false", bad)
		}
	}
}

func TestShortenName(t *testing.T) {
	encLong := testCipher(t, "standard", "false", "password").EncryptFileName(strings.Repeat("超", 100) + ".txt")

	type fn func(*Crypt) func(string) string
	fileFn := fn(func(d *Crypt) func(string) string { return d.shortenFileName })
	dirFn := fn(func(d *Crypt) func(string) string { return d.shortenDirName })

	tests := []struct {
		name    string
		mode    string
		dirEnc  string
		shorten bool
		fn      fn
		enc     string
		want    string
	}{
		{"file switch on", "standard", "false", true, fileFn, encLong, shortName(encLong)},
		{"file switch off", "standard", "false", false, fileFn, encLong, encLong},
		{"file mode off", "off", "false", true, fileFn, "plain.txt.bin", "plain.txt.bin"},
		{"dir switch on", "standard", "true", true, dirFn, encLong, shortName(encLong)},
		{"dir switch off", "standard", "true", false, dirFn, encLong, encLong},
		{"dir enc off", "standard", "false", true, dirFn, encLong, encLong},
		{"dir mode off", "off", "true", true, dirFn, "plain", "plain"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := newTestCrypt(t, tt.mode, tt.dirEnc, tt.shorten, newMemIO())
			if got := tt.fn(d)(tt.enc); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestShortenDirPathSegments(t *testing.T) {
	c := testCipher(t, "standard", "true", "password")
	seg1 := c.EncryptDirName("a")
	seg2 := c.EncryptDirName("目录")
	encPath := "/" + seg1 + "/" + seg2

	d := newTestCrypt(t, "standard", "true", true, newMemIO())
	want := "/" + shortName(seg1) + "/" + shortName(seg2)
	if got := d.shortenDirPathSegments(encPath); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if got := d.shortenDirPathSegments("/"); got != "/" {
		t.Errorf("root path = %q, want /", got)
	}

	d = newTestCrypt(t, "standard", "true", false, newMemIO())
	if got := d.shortenDirPathSegments(encPath); got != encPath {
		t.Errorf("switch off, path should be unchanged, got %q", got)
	}

	d = newTestCrypt(t, "standard", "false", true, newMemIO())
	if got := d.shortenDirPathSegments(encPath); got != encPath {
		t.Errorf("dir shortening inactive, path should be unchanged, got %q", got)
	}
}

func TestIndexRoundtrip(t *testing.T) {
	ctx := context.Background()
	m := newMemIO()
	d := newTestCrypt(t, "standard", "true", true, m)

	if err := d.addIndexEntry(ctx, "/r", shortName("e1"), "e1"); err != nil {
		t.Fatalf("addIndexEntry: %v", err)
	}
	got, err := d.loadIndex(ctx, "/r")
	if err != nil {
		t.Fatalf("loadIndex: %v", err)
	}
	if len(got) != 1 || got[shortName("e1")] != "e1" {
		t.Errorf("index roundtrip mismatch: %v", got)
	}

	// the index is stored under the encrypted name, not the plain one
	encIndexPath := stdpath.Join("/r", d.indexFileNames()[0])
	if _, ok := m.files[encIndexPath]; !ok {
		t.Errorf("the index was not written under its encrypted name")
	}
	if _, ok := m.files[stdpath.Join("/r", indexFileName)]; ok {
		t.Errorf("the index was written under the plain name")
	}

	// corrupted index content must not parse
	data := m.files[encIndexPath]
	data[len(data)/2] ^= 0xFF
	m.files[encIndexPath] = data
	if _, err := d.loadIndex(ctx, "/r"); err == nil {
		t.Errorf("loading a corrupted index should fail")
	}
}

func TestUpdateIndex(t *testing.T) {
	ctx := context.Background()
	m := newMemIO()
	d := newTestCrypt(t, "standard", "true", true, m)

	key := shortName("e1")
	// re-adding the same entry is idempotent
	if err := d.addIndexEntry(ctx, "/r", key, "e1"); err != nil {
		t.Fatalf("addIndexEntry: %v", err)
	}
	if err := d.addIndexEntry(ctx, "/r", key, "e1"); err != nil {
		t.Fatalf("re-add same entry: %v", err)
	}
	// same short key with a different value is a collision
	if err := d.addIndexEntry(ctx, "/r", key, "e2"); err == nil {
		t.Errorf("expected a collision error")
	}

	if err := d.addIndexEntry(ctx, "/r", shortName("e2"), "e2"); err != nil {
		t.Fatalf("addIndexEntry: %v", err)
	}
	got, err := d.loadIndex(ctx, "/r")
	if err != nil {
		t.Fatalf("loadIndex: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("index should have 2 entries, got %d", len(got))
	}

	// removing the last entry deletes the index file
	if err := d.removeIndexEntry(ctx, "/r", key); err != nil {
		t.Fatalf("removeIndexEntry: %v", err)
	}
	if err := d.removeIndexEntry(ctx, "/r", shortName("e2")); err != nil {
		t.Fatalf("removeIndexEntry: %v", err)
	}
	if _, ok := m.files[stdpath.Join("/r", d.indexFileNames()[0])]; ok {
		t.Errorf("empty index should be deleted from the remote")
	}

	// removing from a missing index is tolerated
	if err := d.removeIndexEntry(ctx, "/missing", shortName("e1")); err != nil {
		t.Errorf("removeIndexEntry on missing index: %v", err)
	}
}

// encryptedTestIndex builds the remote content of an index file
func encryptedTestIndex(t *testing.T, d *Crypt, names map[string]string) []byte {
	t.Helper()
	plain, err := json.Marshal(indexFile{Version: indexVersion, Names: names})
	if err != nil {
		t.Fatalf("marshal index: %v", err)
	}
	encReader, err := d.cipher.EncryptData(bytes.NewReader(plain))
	if err != nil {
		t.Fatalf("encrypt index: %v", err)
	}
	data, err := io.ReadAll(encReader)
	if err != nil {
		t.Fatalf("read encrypted index: %v", err)
	}
	return data
}

func TestIndexNamePreference(t *testing.T) {
	ctx := context.Background()
	m := newMemIO()
	d := newTestCrypt(t, "standard", "true", true, m)
	encIndexPath := stdpath.Join("/r", d.cipher.EncryptFileName(indexFileName))
	plainIndexPath := stdpath.Join("/r", indexFileName)

	// an index written under the plain name by an earlier version is read
	m.files[plainIndexPath] = encryptedTestIndex(t, d, map[string]string{"!a": "legacy"})
	got, err := d.loadIndex(ctx, "/r")
	if err != nil {
		t.Fatalf("loadIndex: %v", err)
	}
	if got["!a"] != "legacy" {
		t.Errorf("the plain-named index was not read: %v", got)
	}

	// the encrypted name wins when both are present
	m.files[encIndexPath] = encryptedTestIndex(t, d, map[string]string{"!a": "current"})
	got, err = d.loadIndex(ctx, "/r")
	if err != nil {
		t.Fatalf("loadIndex: %v", err)
	}
	if got["!a"] != "current" {
		t.Errorf("the encrypted index should win over the plain one: %v", got)
	}
}

func TestIndexLegacyMigration(t *testing.T) {
	ctx := context.Background()
	m := newMemIO()
	d := newTestCrypt(t, "standard", "true", true, m)
	plainIndexPath := stdpath.Join("/r", indexFileName)
	m.files[plainIndexPath] = encryptedTestIndex(t, d, map[string]string{"!old": "old"})

	// writing replaces the plain-named file with the encrypted one
	if err := d.addIndexEntry(ctx, "/r", "!new", "new"); err != nil {
		t.Fatalf("addIndexEntry: %v", err)
	}
	if _, ok := m.files[plainIndexPath]; ok {
		t.Errorf("the plain-named index should be dropped after it was migrated")
	}
	got, err := d.loadIndex(ctx, "/r")
	if err != nil {
		t.Fatalf("loadIndex: %v", err)
	}
	if len(got) != 2 || got["!old"] != "old" || got["!new"] != "new" {
		t.Errorf("migrated index mismatch: %v", got)
	}
}

func TestIndexLegacyRemoval(t *testing.T) {
	ctx := context.Background()
	m := newMemIO()
	d := newTestCrypt(t, "standard", "true", true, m)
	plainIndexPath := stdpath.Join("/r", indexFileName)
	m.files[plainIndexPath] = encryptedTestIndex(t, d, map[string]string{"!old": "old"})

	// removing the last entry deletes the file that was read, and nothing is
	// written under the encrypted name
	if err := d.removeIndexEntry(ctx, "/r", "!old"); err != nil {
		t.Fatalf("removeIndexEntry: %v", err)
	}
	if _, ok := m.files[plainIndexPath]; ok {
		t.Errorf("the plain-named index should be deleted once it is empty")
	}
	if _, ok := m.files[stdpath.Join("/r", d.indexFileNames()[0])]; ok {
		t.Errorf("nothing should be written under the encrypted name")
	}
}

func TestIndexWriteWithForeignPassword(t *testing.T) {
	ctx := context.Background()
	m := newMemIO()
	d := newTestCrypt(t, "standard", "true", true, m)
	m.files[stdpath.Join("/r", indexFileName)] = encryptedTestIndex(t, d, map[string]string{"!a": "legacy"})

	// another password derives another encrypted name and cannot decrypt the
	// plain-named index either, so it must not clobber it
	other := newTestCrypt(t, "standard", "true", true, m)
	other.cipher = testCipher(t, "standard", "true", "other-password")
	if err := other.addIndexEntry(ctx, "/r", "!b", "b"); err == nil {
		t.Errorf("writing to a foreign index should fail instead of clobbering it")
	}
	got, err := d.loadIndex(ctx, "/r")
	if err != nil {
		t.Fatalf("loadIndex: %v", err)
	}
	if len(got) != 1 || got["!a"] != "legacy" {
		t.Errorf("the foreign write changed the index: %v", got)
	}
}

func TestDecryptRemoteName(t *testing.T) {
	ctx := context.Background()
	m := newMemIO()
	d := newTestCrypt(t, "standard", "true", true, m)

	// with the switch on every name is stored under its short name
	long := strings.Repeat("超", 100) + ".txt"
	longShort := shortName(d.cipher.EncryptFileName(long))
	if err := d.addIndexEntry(ctx, "/r", longShort, d.cipher.EncryptFileName(long)); err != nil {
		t.Fatalf("addIndexEntry: %v", err)
	}
	got, err := d.decryptRemoteName(ctx, "/r/"+longShort, longShort, false)
	if err != nil || got != long {
		t.Errorf("decryptRemoteName short = %q, %v; want %q", got, err, long)
	}

	shortFile := d.cipher.EncryptFileName("ok.txt")
	shortFileShort := shortName(shortFile)
	if err := d.addIndexEntry(ctx, "/r", shortFileShort, shortFile); err != nil {
		t.Fatalf("addIndexEntry: %v", err)
	}
	if got, err := d.decryptRemoteName(ctx, "/r/"+shortFileShort, shortFileShort, false); err != nil || got != "ok.txt" {
		t.Errorf("decryptRemoteName plain = %q, %v", got, err)
	}

	// unknown short name fails
	if _, err := d.decryptRemoteName(ctx, "/r/"+shortName("nobody"), shortName("nobody"), false); err == nil {
		t.Errorf("unknown short name should fail")
	}

	// the index file has no encrypted name and keeps its plain one
	got, err = d.decryptRemoteName(ctx, "/r/"+indexFileName, indexFileName, false)
	if err != nil || got != indexFileName {
		t.Errorf("decryptRemoteName(%s) = %q, %v; want the plain name", indexFileName, got, err)
	}
}

func TestResolveListingShortNames(t *testing.T) {
	ctx := context.Background()
	m := newMemIO()
	d := newTestCrypt(t, "standard", "true", true, m)

	longFile := strings.Repeat("超", 100) + ".txt"
	longFileEnc := d.cipher.EncryptFileName(longFile)
	longFileShort := shortName(longFileEnc)

	normalEnc := d.cipher.EncryptFileName("short.txt")
	normalShort := shortName(normalEnc)

	dirEnc := d.cipher.EncryptDirName("dir")
	dirShort := shortName(dirEnc)

	longDir := strings.Repeat("目录", 80)
	longDirEnc := d.cipher.EncryptDirName(longDir)
	longDirShort := shortName(longDirEnc)

	// an orphan short name exists on the remote but not in the index
	orphanShort := shortName(d.cipher.EncryptFileName(strings.Repeat("缺", 100)))

	for _, e := range []struct{ short, enc string }{
		{longFileShort, longFileEnc},
		{normalShort, normalEnc},
		{dirShort, dirEnc},
		{longDirShort, longDirEnc},
	} {
		if err := d.addIndexEntry(ctx, "/r", e.short, e.enc); err != nil {
			t.Fatalf("addIndexEntry: %v", err)
		}
	}

	objs := []model.Obj{
		&model.Object{Name: normalShort, Size: d.cipher.EncryptedSize(10)},
		&model.Object{Name: longFileShort, Size: d.cipher.EncryptedSize(20)},
		&model.Object{Name: dirShort, IsFolder: true},
		&model.Object{Name: longDirShort, IsFolder: true},
		&model.Object{Name: orphanShort, Size: d.cipher.EncryptedSize(30)},
		&model.Object{Name: "!!!not-encrypted!!!", Size: d.cipher.EncryptedSize(30)},
		&model.Object{Name: indexFileName, Size: d.cipher.EncryptedSize(64)},
	}

	resolved := d.resolveListing(ctx, "/r", objs)
	type entry struct {
		name string
		size int64
		dir  bool
	}
	got := make([]entry, 0, len(resolved))
	for _, r := range resolved {
		got = append(got, entry{r.name, r.size, r.remote.IsDir()})
	}
	want := []entry{
		{indexFileName, 64, false},
		{"short.txt", 10, false},
		{longFile, 20, false},
		{"dir", 0, true},
		{longDir, 0, true},
	}
	if len(got) != len(want) {
		t.Fatalf("resolved %d entries, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestIndexRemotePath(t *testing.T) {
	d := newTestCrypt(t, "standard", "true", true, newMemIO())
	d.RemotePath = "/remote"
	encName, plainName := d.indexFileNames()[0], d.indexFileNames()[1]
	if encName != d.cipher.EncryptFileName(indexFileName) || plainName != indexFileName {
		t.Fatalf("index names = %q, %q; want the encrypted name first, then the plain one", encName, plainName)
	}

	// the encrypted name is used in the remote root
	if got, want := d.indexRemotePath("/"+indexFileName, encName), "/remote/"+encName; got != want {
		t.Errorf("root index path = %q, want %q", got, want)
	}

	// the plain name is still addressable for files of earlier versions
	if got, want := d.indexRemotePath("/"+indexFileName, plainName), "/remote/"+plainName; got != want {
		t.Errorf("legacy index path = %q, want %q", got, want)
	}

	// in a subdirectory the directory segments are encrypted and shortened
	subEnc := d.cipher.EncryptDirName("sub")
	want := "/remote/" + shortName(subEnc) + "/" + encName
	if got := d.indexRemotePath("/sub/"+indexFileName, encName); got != want {
		t.Errorf("nested index path = %q, want %q", got, want)
	}

	// with directory encryption off the segments stay plain
	plain := newTestCrypt(t, "standard", "false", true, newMemIO())
	plain.RemotePath = "/remote"
	if got, want := plain.indexRemotePath("/sub/"+indexFileName, plainName), "/remote/sub/"+plainName; got != want {
		t.Errorf("plain dir index path = %q, want %q", got, want)
	}
}

func TestResolveListingWithoutIndex(t *testing.T) {
	ctx := context.Background()
	d := newTestCrypt(t, "standard", "true", true, newMemIO())

	// with no index file on the remote the listing falls back to the default
	// behavior: encrypted names decrypt, shortened names stay unresolvable
	shortEnc := d.cipher.EncryptFileName("shortened.txt")
	objs := []model.Obj{
		&model.Object{Name: d.cipher.EncryptFileName("plain.txt"), Size: d.cipher.EncryptedSize(7)},
		&model.Object{Name: d.cipher.EncryptDirName("sub"), IsFolder: true},
		&model.Object{Name: shortName(shortEnc), Size: d.cipher.EncryptedSize(9)},
	}
	resolved := d.resolveListing(ctx, "/r", objs)
	if len(resolved) != 2 {
		t.Fatalf("resolved %d entries, want 2: %+v", len(resolved), resolved)
	}
	if resolved[0].name != "plain.txt" || resolved[0].size != 7 {
		t.Errorf("plain file not resolved: %+v", resolved[0])
	}
	if resolved[1].name != "sub" || !resolved[1].remote.IsDir() {
		t.Errorf("plain dir not resolved: %+v", resolved[1])
	}
}

func TestResolveListingBrokenIndex(t *testing.T) {
	ctx := context.Background()
	m := newMemIO()
	d := newTestCrypt(t, "standard", "true", true, m)

	enc := d.cipher.EncryptFileName("shortened.txt")
	short := shortName(enc)
	if err := d.addIndexEntry(ctx, "/r", short, enc); err != nil {
		t.Fatalf("addIndexEntry: %v", err)
	}
	indexPath := stdpath.Join("/r", d.indexFileNames()[0])
	data := m.files[indexPath]
	data[len(data)/2] ^= 0xFF
	m.files[indexPath] = data

	// an unreadable index only leaves the shortened entries unresolvable, the
	// rest of the directory is unaffected
	objs := []model.Obj{
		&model.Object{Name: d.cipher.EncryptFileName("plain.txt"), Size: d.cipher.EncryptedSize(7)},
		&model.Object{Name: short, Size: d.cipher.EncryptedSize(9)},
	}
	resolved := d.resolveListing(ctx, "/r", objs)
	if len(resolved) != 1 || resolved[0].name != "plain.txt" {
		t.Fatalf("resolved %+v, want only plain.txt", resolved)
	}
}

func TestResolveListingPlainDirs(t *testing.T) {
	ctx := context.Background()
	m := newMemIO()
	d := newTestCrypt(t, "standard", "false", true, m)

	// with directory encryption off, dir names pass through unchanged while
	// file names are still shortened
	fileEnc := d.cipher.EncryptFileName("f.txt")
	fileShort := shortName(fileEnc)
	if err := d.addIndexEntry(ctx, "/r", fileShort, fileEnc); err != nil {
		t.Fatalf("addIndexEntry: %v", err)
	}
	objs := []model.Obj{
		&model.Object{Name: "plainDir", IsFolder: true},
		&model.Object{Name: fileShort, Size: d.cipher.EncryptedSize(1)},
	}
	resolved := d.resolveListing(ctx, "/r", objs)
	if len(resolved) != 2 {
		t.Fatalf("resolved %d entries, want 2", len(resolved))
	}
	if resolved[0].name != "plainDir" || !resolved[0].remote.IsDir() {
		t.Errorf("plain dir not preserved: %+v", resolved[0])
	}
	if resolved[1].name != "f.txt" {
		t.Errorf("file name not resolved: %+v", resolved[1])
	}
}

func TestResolveListingKeepsFullNamesWhenOff(t *testing.T) {
	ctx := context.Background()
	d := newTestCrypt(t, "standard", "true", false, newMemIO())

	// with the switch off, previously written full encrypted names must keep
	// decrypting directly, without any index
	objs := []model.Obj{
		&model.Object{Name: d.cipher.EncryptDirName("dir"), IsFolder: true},
		&model.Object{Name: d.cipher.EncryptFileName("f.txt"), Size: d.cipher.EncryptedSize(1)},
	}
	resolved := d.resolveListing(ctx, "/r", objs)
	if len(resolved) != 2 {
		t.Fatalf("resolved %d entries, want 2", len(resolved))
	}
	if resolved[0].name != "dir" || !resolved[0].remote.IsDir() {
		t.Errorf("dir name not decrypted: %+v", resolved[0])
	}
	if resolved[1].name != "f.txt" {
		t.Errorf("file name not decrypted: %+v", resolved[1])
	}
}
