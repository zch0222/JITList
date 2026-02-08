package jit

import (
	"context"

	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
)

type Addition struct {
	RootPath  string `json:"root_path" required:"true" help:"Path to local directory containing .jit files"`
	TargetDir string `json:"target_dir" required:"true" help:"Target directory in OpenList (e.g. /pikpak/cache)"`
}

var config = driver.Config{
	Name:      "JIT Load",
	LocalSort: true,
}

func (d *JIT) Config() driver.Config {
	return config
}

func (d *JIT) GetAddition() driver.Additional {
	return &d.Addition
}

func (d *JIT) Init(ctx context.Context) error {
	return nil
}

func (d *JIT) Drop(ctx context.Context) error {
	return nil
}

func (d *JIT) GetStorage() *model.Storage {
	return &d.Storage
}

func (d *JIT) SetStorage(s model.Storage) {
	d.Storage = s
}

func (d *JIT) GetRootPath() string {
	// d.RootPath 是你在后台填写的 "Root Path" 配置项（例如 /etc/alist/jit_files）
	return d.RootPath
}
