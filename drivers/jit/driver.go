package jit

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/OpenListTeam/OpenList/v4/drivers/pikpak"
	driver "github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// init 注册 JIT 驱动到 OpenList 系统中
// 这样用户在后台添加存储时就能看到 "JIT Load" 选项
func init() {
	op.RegisterDriver(func() driver.Driver {
		return &JIT{}
	})
}

// JIT 驱动结构体
// 实现了 driver.Driver 接口
type JIT struct {
	model.Storage
	Addition
}

// List 列出目录下的文件
// 核心逻辑：
// 1. 扫描 RootPath 下的本地文件
// 2. 如果是文件夹，直接展示
// 3. 如果是 .jit 后缀的文件，读取其内容（JSON），解析出真实文件名和大小，伪装成该文件展示
func (d *JIT) List(ctx context.Context, dir model.Obj, args model.ListArgs) ([]model.Obj, error) {
	// 拼接本地完整路径
	fullPath := dir.GetPath()
	entries, err := os.ReadDir(fullPath)
	if err != nil {
		return nil, err
	}

	var objs []model.Obj
	for _, entry := range entries {
		if entry.IsDir() {
			// 如果是普通文件夹，直接添加
			objs = append(objs, &JITObj{
				Object: model.Object{
					Name:     entry.Name(),
					IsFolder: true,
					Modified: time.Now(),
					Path:     filepath.Join(dir.GetPath(), entry.Name()),
					ID:       filepath.Join(fullPath, entry.Name()),
				},
			})
		} else if strings.HasSuffix(entry.Name(), ".jit") {
			// 如果是 .jit 文件，读取并解析
			content, err := os.ReadFile(filepath.Join(fullPath, entry.Name()))
			if err != nil {
				continue
			}
			var jFile JITFile
			if err := json.Unmarshal(content, &jFile); err != nil {
				continue
			}

			// 获取展示用的文件名
			// 优先使用 JSON 中的 Name，如果没有则使用文件名去掉 .jit 后缀
			displayName := jFile.Name
			if displayName == "" {
				displayName = strings.TrimSuffix(entry.Name(), ".jit")
			}

			// 添加到文件列表，注意 ID 存储的是本地 .jit 文件的绝对路径
			objs = append(objs, &JITObj{
				Object: model.Object{
					Name:     displayName,
					Size:     jFile.Size,
					Modified: time.Now(),
					IsFolder: false,
					Path:     filepath.Join(dir.GetPath(), displayName),
					ID:       filepath.Join(fullPath, entry.Name()), // ID 是 .jit 文件的真实路径
				},
				url: jFile.URL,
			})
		}
	}
	return objs, nil
}

// Link 获取文件的下载/播放链接
// 这是 JIT 驱动的核心逻辑：
// 1. 读取 .jit 文件获取资源链接 (磁力链/HTTP链接)
// 2. 检查目标网盘（如 PikPak）是否已经存在该文件（秒传检测）
// 3. 如果不存在，触发离线下载任务
// 4. 轮询等待任务完成
// 5. 返回目标网盘的真实文件链接
func (d *JIT) Link(ctx context.Context, file model.Obj, args model.LinkArgs) (*model.Link, error) {
	log.Infof("JIT Link start: file=%s, ID=%s", file.GetName(), file.GetID())

	// 1. 读取 .jit 文件内容获取 URL
	jitFilePath := file.GetID()
	content, err := os.ReadFile(jitFilePath)
	if err != nil {
		log.Errorf("JIT failed to read jit file: %s, err: %v", jitFilePath, err)
		return nil, errors.Wrap(err, "failed to read jit file")
	}
	var jFile JITFile
	if err := json.Unmarshal(content, &jFile); err != nil {
		log.Errorf("JIT failed to parse jit file: %s, err: %v", jitFilePath, err)
		return nil, errors.Wrap(err, "failed to parse jit file")
	}

	log.Infof("JIT loaded jit file: name=%s, url=%s, target_dir=%s", jFile.Name, jFile.URL, d.TargetDir)

	// 2. 获取目标存储驱动实例（例如 PikPak）
	storage, actualPath, err := op.GetStorageAndActualPath(d.TargetDir)
	if err != nil {
		log.Errorf("JIT failed to get storage for target_dir: %s, err: %v", d.TargetDir, err)
		return nil, errors.Wrap(err, "failed to get target storage")
	}
	log.Infof("JIT target storage found: mount_path=%s, actual_path=%s", storage.GetStorage().MountPath, actualPath)

	// 3. 检查目标目录中是否已存在该文件
	// 注意：这里假设目标网盘的文件名与 .jit 中定义的一致
	targetFilePath := filepath.Join(actualPath, jFile.Name)
	log.Infof("JIT checking if file exists at: %s", targetFilePath)

	_, _ = op.List(ctx, storage, actualPath, model.ListArgs{Refresh: true})
	existingObj, err := op.GetUnwrap(ctx, storage, targetFilePath)

	if err == nil {
		// 文件已存在
		log.Infof("JIT file already exists: %s", existingObj.GetPath())

		// 检查是否是文件夹
		if existingObj.IsDir() {
			log.Infof("JIT existing object is a directory, searching for video file")
			files, err := storage.List(ctx, existingObj, model.ListArgs{})
			if err == nil && len(files) > 0 {
				var maxFile model.Obj
				var maxSize int64
				for _, f := range files {
					log.Infof("JIT scanning existing file: %s (size: %d, isDir: %v)", f.GetName(), f.GetSize(), f.IsDir())
					if !f.IsDir() && f.GetSize() > maxSize {
						maxSize = f.GetSize()
						maxFile = f
					}
				}
				if maxFile != nil {
					existingObj = maxFile
					log.Infof("JIT selected max file from existing dir: %s", maxFile.GetName())
				}
			}
		}

		link, err := storage.Link(ctx, existingObj, args)
		return link, err
	}
	log.Infof("JIT file not found (err: %v), triggering offline download", err)

	// 4. 如果文件不存在，触发离线下载/秒传
	pikpakDriver, ok := storage.(*pikpak.PikPak)
	if !ok {
		log.Errorf("JIT target storage is not PikPak")
		return nil, errors.New("currently only PikPak is supported as target driver")
	}

	// 获取目标父目录对象
	parentDirObj, err := op.GetUnwrap(ctx, storage, actualPath)
	if err != nil {
		log.Errorf("JIT failed to get parent dir: %s, err: %v", actualPath, err)
		// 如果目标目录不存在，可能需要创建（这里暂略，假设目录已存在）
		return nil, errors.Wrap(err, "target directory not found")
	}

	// 添加离线下载任务
	log.Infof("JIT: triggering offline download for %s url: %s", jFile.Name, jFile.URL)
	task, err := pikpakDriver.OfflineDownload(ctx, jFile.URL, parentDirObj, jFile.Name)
	if err != nil {
		log.Errorf("JIT failed to add offline task: %v", err)
		return nil, errors.Wrap(err, "failed to add offline task")
	}
	log.Infof("JIT offline task started: task_id=%s", task.ID)

	// 5. 轮询等待任务完成（超时时间 30 秒）
	timeout := time.After(30 * time.Second)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Warnf("JIT context done")
			return nil, ctx.Err()
		case <-timeout:
			log.Warnf("JIT timeout")
			return nil, errors.New("wait for rapid upload timeout")
		case <-ticker.C:
			// 检查任务状态
			if task != nil {
				// 获取最新的任务状态
				currentTask, err := pikpakDriver.GetOfflineTask(ctx, task.ID)
				if err == nil {
					task = currentTask
					log.Infof("JIT task polling: phase=%s, progress=%d", task.Phase, task.Progress)
				} else {
					log.Warnf("JIT failed to get task status: %v", err)
				}

				if task.Phase == "PHASE_TYPE_COMPLETE" {
					log.Infof("JIT task complete. FileID=%s, Name=%s, FileName=%s", task.FileID, task.Name, task.FileName)
					// 任务完成，根据 file_id 获取文件对象
					// 1. 如果是文件，直接返回
					// 2. 如果是文件夹，需要进一步查找其中的视频文件
					if task.FileID != "" {
						// 这里我们需要一种方法通过 ID 获取对象，或者知道它的路径
						// 由于 PikPak 驱动主要是基于路径的，但也支持 ID 操作（虽然 op.GetUnwrap 是基于路径）
						// 我们可以尝试通过 task.Name 来猜测路径
						// 注意：磁力链接下载后的文件名可能与 .jit 中的 Name 不一致

						// 尝试直接使用 task.Name 拼接路径
						// 如果是文件夹，我们需要列出里面的文件
						downloadedName := task.Name
						if task.FileName != "" {
							downloadedName = task.FileName
						}

						// 构建可能的路径
						possiblePath := filepath.Join(actualPath, downloadedName)
						log.Infof("JIT checking downloaded path: %s", possiblePath)

						downloadedObj, err := op.GetUnwrap(ctx, storage, possiblePath)
						if err == nil {
							if downloadedObj.IsDir() {
								log.Infof("JIT result is dir, searching for video file")
								// 如果是文件夹，列出文件并找到最大的视频文件
								files, err := storage.List(ctx, downloadedObj, model.ListArgs{})
								if err == nil && len(files) > 0 {
									var maxFile model.Obj
									var maxSize int64
									for _, f := range files {
										log.Infof("JIT scanning file: %s (size: %d, isDir: %v)", f.GetName(), f.GetSize(), f.IsDir())
										if !f.IsDir() && f.GetSize() > maxSize {
											maxSize = f.GetSize()
											maxFile = f
										}
									}
									if maxFile != nil {
										downloadedObj = maxFile
										log.Infof("JIT selected max file: %s", maxFile.GetName())
									}
								}
							}

							log.Infof("JIT linking object: %s", downloadedObj.GetPath())
							link, err := storage.Link(ctx, downloadedObj, args)
							return link, err
						} else {
							log.Warnf("JIT failed to get downloaded object: %v", err)
						}
					}
				} else if task.Phase == "PHASE_TYPE_ERROR" {
					log.Errorf("JIT task error: %s", task.Message)
					return nil, errors.New("offline task failed: " + task.Message)
				}
			}

			// 兼容旧逻辑：检查文件是否已生成
			// 这里通过直接获取文件对象来判断任务是否完成
			newObj, err := op.GetUnwrap(ctx, storage, targetFilePath)
			if err == nil {
				log.Infof("JIT fallback check success")
				// 成功！获取并返回链接
				link, err := storage.Link(ctx, newObj, args)
				return link, err
			}

			// 如果任务出错
			if task != nil && task.Phase == "PHASE_TYPE_ERROR" {
				return nil, errors.New("offline task failed: " + task.Message)
			}
			// 继续轮询...
		}
	}
}

// Get 根据路径获取文件信息
// 用于处理非列表页的直接访问
func (d *JIT) Get(ctx context.Context, path string) (model.Obj, error) {
	// path 是相对于挂载点的路径，例如 "movie.mp4"
	// 我们需要找到对应的 .jit 文件，例如 "movie.mp4.jit"

	fullPath := filepath.Join(d.RootPath, path)
	jitPath := fullPath + ".jit"

	// 先检查是否直接对应本地文件夹
	info, err := os.Stat(jitPath)
	if err != nil {
		// 如果 .jit 不存在，检查是否是普通文件夹
		info, err = os.Stat(fullPath)
		if err == nil && info.IsDir() {
			return &JITObj{
				Object: model.Object{
					Name:     filepath.Base(path),
					IsFolder: true,
					Modified: info.ModTime(),
					Path:     path,
					ID:       fullPath,
				},
			}, nil
		}
		return nil, err
	}

	// 读取并解析 .jit 文件
	content, err := os.ReadFile(jitPath)
	if err != nil {
		return nil, err
	}
	var jFile JITFile
	if err := json.Unmarshal(content, &jFile); err != nil {
		return nil, err
	}

	return &JITObj{
		Object: model.Object{
			Name:     jFile.Name,
			Size:     jFile.Size,
			Modified: info.ModTime(),
			IsFolder: false,
			Path:     path,
			ID:       jitPath,
		},
		url: jFile.URL,
	}, nil
}
