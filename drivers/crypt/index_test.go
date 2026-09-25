package crypt

import (
	"context"
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

func newTestCrypt(t *testing.T, mode, dirEnc string, limit int, io fileIO) *Crypt {
	t.Helper()
	return &Crypt{
		Addition: Addition{
			FileNameEnc:         mode,
			DirNameEnc:          dirEnc,
			FileNameLengthLimit: limit,
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
	long := strings.Repeat("超", 100) + ".txt" // 100 CJK chars => far over 255 after encryption
	encLong := testCipher(t, "standard", "false", "password").EncryptFileName(long)
	if len(encLong) <= 255 {
		t.Fatalf("test name too short: %d", len(encLong))
	}

	tests := []struct {
		name    string
		mode    string
		dirEnc  string
		limit   int
		enc     string
		shorten func(d *Crypt) func(string) string
		want    string
	}{
		{"file over limit", "standard", "false", 255, encLong, func(d *Crypt) func(string) string { return d.shortenFileName }, shortName(encLong)},
		{"file under limit", "standard", "false", 255, "short-name", func(d *Crypt) func(string) string { return d.shortenFileName }, "short-name"},
		{"limit disabled", "standard", "false", 0, encLong, func(d *Crypt) func(string) string { return d.shortenFileName }, encLong},
		{"encryption off", "off", "false", 10, "plain.txt.bin", func(d *Crypt) func(string) string { return d.shortenFileName }, "plain.txt.bin"},
		{"dir over limit", "standard", "true", 255, encLong, func(d *Crypt) func(string) string { return d.shortenDirName }, shortName(encLong)},
		{"dir enc off", "standard", "false", 255, encLong, func(d *Crypt) func(string) string { return d.shortenDirName }, encLong},
		{"dir enc on but mode off", "off", "true", 10, "plain", func(d *Crypt) func(string) string { return d.shortenDirName }, "plain"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := newTestCrypt(t, tt.mode, tt.dirEnc, tt.limit, newMemIO())
			if got := tt.shorten(d)(tt.enc); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestShortenDirPathSegments(t *testing.T) {
	shortSeg := testCipher(t, "standard", "true", "password").EncryptDirName("短")
	longSeg := testCipher(t, "standard", "true", "password").EncryptDirName(strings.Repeat("目录", 80))
	encPath := "/" + shortSeg + "/" + longSeg

	d := newTestCrypt(t, "standard", "true", 255, newMemIO())
	want := "/" + shortSeg + "/" + shortName(longSeg)
	if got := d.shortenDirPathSegments(encPath); got != want {
		t.Errorf("got %q, want %q", got, want)
	}

	d = newTestCrypt(t, "standard", "false", 255, newMemIO())
	if got := d.shortenDirPathSegments(encPath); got != encPath {
		t.Errorf("dir shortening inactive, path should be unchanged, got %q", got)
	}

	d = newTestCrypt(t, "standard", "true", 0, newMemIO())
	if got := d.shortenDirPathSegments(encPath); got != encPath {
		t.Errorf("limit disabled, path should be unchanged, got %q", got)
	}
}

func TestIndexRoundtrip(t *testing.T) {
	ctx := context.Background()
	m := newMemIO()
	d := newTestCrypt(t, "standard", "true", 255, m)

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

	// a cipher with a different password cannot read the index
	other := newTestCrypt(t, "standard", "true", 255, m)
	other.cipher = testCipher(t, "standard", "true", "other-password")
	if _, err := other.loadIndex(ctx, "/r"); err == nil {
		t.Errorf("loading the index with a wrong password should fail")
	}

	// corrupted index content must not parse
	indexPath := stdpath.Join("/r", indexFileName)
	data := m.files[indexPath]
	data[len(data)/2] ^= 0xFF
	m.files[indexPath] = data
	if _, err := d.loadIndex(ctx, "/r"); err == nil {
		t.Errorf("loading a corrupted index should fail")
	}
}

func TestUpdateIndex(t *testing.T) {
	ctx := context.Background()
	m := newMemIO()
	d := newTestCrypt(t, "standard", "true", 255, m)

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
	if _, ok := m.files[stdpath.Join("/r", indexFileName)]; ok {
		t.Errorf("empty index should be deleted from the remote")
	}

	// removing from a missing index is tolerated
	if err := d.removeIndexEntry(ctx, "/missing", shortName("e1")); err != nil {
		t.Errorf("removeIndexEntry on missing index: %v", err)
	}
}

func TestDecryptRemoteName(t *testing.T) {
	ctx := context.Background()
	m := newMemIO()
	d := newTestCrypt(t, "standard", "true", 255, m)

	long := strings.Repeat("超", 100) + ".txt"
	enc := d.cipher.EncryptFileName(long)
	sh := shortName(enc)
	if err := d.addIndexEntry(ctx, "/r", sh, enc); err != nil {
		t.Fatalf("addIndexEntry: %v", err)
	}

	got, err := d.decryptRemoteName(ctx, "/r/"+sh, sh, false)
	if err != nil || got != long {
		t.Errorf("decryptRemoteName short = %q, %v; want %q", got, err, long)
	}

	// normal encrypted names still decrypt directly
	short := d.cipher.EncryptFileName("ok.txt")
	if got, err := d.decryptRemoteName(ctx, "/r/"+short, short, false); err != nil || got != "ok.txt" {
		t.Errorf("decryptRemoteName plain = %q, %v", got, err)
	}

	// unknown short name fails
	if _, err := d.decryptRemoteName(ctx, "/r/"+shortName("nobody"), shortName("nobody"), false); err == nil {
		t.Errorf("unknown short name should fail")
	}
}

func TestResolveListing(t *testing.T) {
	ctx := context.Background()
	m := newMemIO()
	d := newTestCrypt(t, "standard", "true", 255, m)

	longFile := strings.Repeat("超", 100) + ".txt"
	longFileEnc := d.cipher.EncryptFileName(longFile)
	longFileShort := shortName(longFileEnc)
	if len(longFileEnc) <= 255 {
		t.Fatalf("longFileEnc too short: %d", len(longFileEnc))
	}

	longDir := strings.Repeat("目录", 80)
	longDirEnc := d.cipher.EncryptDirName(longDir)
	longDirShort := shortName(longDirEnc)
	if len(longDirEnc) <= 255 {
		t.Fatalf("longDirEnc too short: %d", len(longDirEnc))
	}

	// missing entry: an indexed name exists in the dir but not in the index
	orphanShort := shortName(d.cipher.EncryptFileName(strings.Repeat("缺", 100)))

	if err := d.addIndexEntry(ctx, "/r", longFileShort, longFileEnc); err != nil {
		t.Fatalf("addIndexEntry: %v", err)
	}
	if err := d.addIndexEntry(ctx, "/r", longDirShort, longDirEnc); err != nil {
		t.Fatalf("addIndexEntry: %v", err)
	}

	normalEnc := d.cipher.EncryptFileName("short.txt")
	normalDirEnc := d.cipher.EncryptDirName("dir")
	objs := []model.Obj{
		&model.Object{Name: normalEnc, Size: d.cipher.EncryptedSize(10)},
		&model.Object{Name: longFileShort, Size: d.cipher.EncryptedSize(20)},
		&model.Object{Name: longDirShort, IsFolder: true},
		&model.Object{Name: normalDirEnc, IsFolder: true},
		&model.Object{Name: orphanShort, Size: d.cipher.EncryptedSize(30)},
		&model.Object{Name: "!!!not-encrypted!!!", Size: d.cipher.EncryptedSize(30)},
		&model.Object{Name: indexFileName, Size: 42},
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
		{"short.txt", 10, false},
		{"dir", 0, true},
		// short names are resolved in a second pass and appended at the end
		{longFile, 20, false},
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

func TestResolveListingPlainDirs(t *testing.T) {
	ctx := context.Background()
	d := newTestCrypt(t, "standard", "false", 255, newMemIO())

	// with directory encryption off, dir names pass through unchanged
	objs := []model.Obj{
		&model.Object{Name: "plainDir", IsFolder: true},
		&model.Object{Name: d.cipher.EncryptFileName("f.txt"), Size: d.cipher.EncryptedSize(1)},
	}
	resolved := d.resolveListing(ctx, "/r", objs)
	if len(resolved) != 2 {
		t.Fatalf("resolved %d entries, want 2", len(resolved))
	}
	if resolved[0].name != "plainDir" || !resolved[0].remote.IsDir() {
		t.Errorf("plain dir not preserved: %+v", resolved[0])
	}
	if resolved[1].name != "f.txt" {
		t.Errorf("file name not decrypted: %+v", resolved[1])
	}
}
