package jit

import (
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
)

type JITFile struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
	URL  string `json:"url"` // Magnet, ed2k, or http url for rapid upload
}

type JITObj struct {
	model.Object
	url string
}

func (o *JITObj) GetName() string {
	return o.Name
}

func (o *JITObj) GetSize() int64 {
	return o.Size
}

func (o *JITObj) ModTime() time.Time {
	return o.Modified
}

func (o *JITObj) CreateTime() time.Time {
	return o.Ctime
}

func (o *JITObj) IsDir() bool {
	return o.IsFolder
}

func (o *JITObj) GetID() string {
	return o.ID
}

func (o *JITObj) GetPath() string {
	return o.Path
}

func (o *JITObj) GetHash() utils.HashInfo {
	return o.HashInfo
}
