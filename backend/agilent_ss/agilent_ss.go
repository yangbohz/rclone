// agilent_ss 包实现了对 Agilent Secure Storage 的 Rclone 后端支持。
// 此版本包含了多语言支持、并发安全修复、多级缓存优化以及对最新Rclone API的兼容性修复。
package agilent_ss

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/fserrors"
	"github.com/rclone/rclone/fs/fshttp"
	"github.com/rclone/rclone/fs/hash"
	"github.com/rclone/rclone/lib/pacer"

	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

// --- 常量定义 ---
const (
	minSleep         = 10 * time.Millisecond
	maxSleep         = 2 * time.Second
	decayConstant    = 2
	defaultLimit     = 200
	timeFormat       = time.RFC3339Nano
	rootID           = "root"
	folderKind       = "folder"
	fileKind         = "file"
)

// --- 多语言消息键定义 ---
const (
	MsgActionMkdir           = "ActionMkdir"; MsgActionDelete = "ActionDelete"; MsgActionRename = "ActionRename"; MsgActionMove = "ActionMove"
	MsgActionCopy            = "ActionCopy"; MsgActionUpload = "ActionUpload"; MsgActionDownload = "ActionDownload"
	MsgErrParseOptions       = "ErrParseOptions"; MsgErrCreateLoginRequest = "ErrCreateLoginRequest"; MsgErrLoginRequest = "ErrLoginRequest"
	MsgErrLoginStatus        = "ErrLoginStatus"; MsgErrDecodeLoginResponse= "ErrDecodeLoginResponse"; MsgErrTokenNotFound = "ErrTokenNotFound"
	MsgErrQueryRoot          = "ErrQueryRoot"; MsgErrFindParentDir = "ErrFindParentDir"; MsgErrFindSrcDir = "ErrFindSrcDir"
	MsgErrFindDstDir         = "ErrFindDstDir"; MsgErrMarshalRequest = "ErrMarshalRequest"; MsgErrCreateRequest = "ErrCreateRequest"
	MsgErrRequestFailed      = "ErrRequestFailed"; MsgErrAPIStatus = "ErrAPIStatus"; MsgErrDecodeResponse = "ErrDecodeResponse"
	MsgErrIDNotFoundInResponse = "ErrIDNotFoundInResponse"; MsgErrDirNotEmpty = "ErrDirNotEmpty"; MsgErrCantPurgeRoot = "ErrCantPurgeRoot"
	MsgErrSrcObjectType      = "ErrSrcObjectType"; MsgErrDownloadStatus = "ErrDownloadStatus"; MsgErrUploadStatus = "ErrUploadStatus"
	MsgDebugRename           = "DebugRename"; MsgDebugMove = "DebugMove"; MsgDebugRangeSupport = "DebugRangeSupport"
	MsgDebugRangeUnsupported = "DebugRangeUnsupported"; MsgDebugFullDownload = "DebugFullDownload"; MsgDebugUnknownItem = "DebugUnknownItem"
)

// init 函数在Rclone启动时被调用
func init() {
	fs.Register(&fs.RegInfo{
		Name:        "agilent_ss", Description: "Agilent Secure Storage", NewFs: NewFs,
		Options: []fs.Option{
			{Name: "server", Help: "Your server address (e.g., mycloud.example.com).", Required: true},
			{Name: "user", Help: "Your login username.", Required: true},
			{Name: "pass", Help: "Your login password.", Required: true, IsPassword: true},
			{Name: "domain", Help: "Optional domain for login."},
			{
				Name: "language", Help: "Language for messages (en/zh).", Default: "en", Advanced: true,
				Examples: []fs.OptionExample{{Value: "en", Help: "English"}, {Value: "zh", Help: "中文"}},
			},
		},
	})
	
	// --- 设置多语言消息 ---
	message.SetString(language.English, MsgActionMkdir, "mkdir"); message.SetString(language.English, MsgActionDelete, "delete"); message.SetString(language.English, MsgActionRename, "rename")
	message.SetString(language.English, MsgActionMove, "move"); message.SetString(language.English, MsgActionCopy, "copy"); message.SetString(language.English, MsgActionUpload, "upload")
	message.SetString(language.English, MsgActionDownload, "download"); message.SetString(language.English, MsgErrParseOptions, "Failed to parse options")
	message.SetString(language.English, MsgErrCreateLoginRequest, "Failed to create login request"); message.SetString(language.English, MsgErrLoginRequest, "Login request failed")
	message.SetString(language.English, MsgErrLoginStatus, "Login failed: unexpected status code %s"); message.SetString(language.English, MsgErrDecodeLoginResponse, "Failed to decode login response")
	message.SetString(language.English, MsgErrTokenNotFound, "Login successful but no token was returned"); message.SetString(language.English, MsgErrQueryRoot, "Failed to query root directory")
	message.SetString(language.English, MsgErrFindParentDir, "Could not find parent directory for '%s'"); message.SetString(language.English, MsgErrFindSrcDir, "Operation failed, could not find source directory '%s'")
	message.SetString(language.English, MsgErrFindDstDir, "Operation failed, could not find destination directory '%s'"); message.SetString(language.English, MsgErrMarshalRequest, "Failed to marshal request body for %s")
	message.SetString(language.English, MsgErrCreateRequest, "Failed to create %s request"); message.SetString(language.English, MsgErrRequestFailed, "%s request failed")
	message.SetString(language.English, MsgErrAPIStatus, "%s failed, API returned status: %s"); message.SetString(language.English, MsgErrDecodeResponse, "Failed to decode %s response")
	message.SetString(language.English, MsgErrIDNotFoundInResponse, "%s successful but no ID found in response"); message.SetString(language.English, MsgErrSrcObjectType, "Source object type invalid")
	message.SetString(language.English, MsgErrDirNotEmpty, "Directory is not empty"); message.SetString(language.English, MsgErrCantPurgeRoot, "Can't purge root directory")
	message.SetString(language.English, MsgErrDownloadStatus, "Download failed: unexpected status %s"); message.SetString(language.English, MsgErrUploadStatus, "Upload failed, status: %s")
	message.SetString(language.English, MsgDebugRename, "Detected folder rename operation: '%s' -> '%s'"); message.SetString(language.English, MsgDebugMove, "Detected move operation: '%s' -> '%s'")
	message.SetString(language.English, MsgDebugRangeSupport, "Server supports range requests, starting chunked download."); message.SetString(language.English, MsgDebugRangeUnsupported, "Server does not support range requests, returned full file. Rclone will handle the required chunk.")
	message.SetString(language.English, MsgDebugFullDownload, "Starting full file download."); message.SetString(language.English, MsgDebugUnknownItem, "Found unknown item type '%s' for item '%s'")
	
	message.SetString(language.Chinese, MsgActionMkdir, "创建目录"); message.SetString(language.Chinese, MsgActionDelete, "删除"); message.SetString(language.Chinese, MsgActionRename, "重命名")
	message.SetString(language.Chinese, MsgActionMove, "移动"); message.SetString(language.Chinese, MsgActionCopy, "复制"); message.SetString(language.Chinese, MsgActionUpload, "上传")
	message.SetString(language.Chinese, MsgActionDownload, "下载"); message.SetString(language.Chinese, MsgErrParseOptions, "解析配置失败")
	message.SetString(language.Chinese, MsgErrCreateLoginRequest, "创建登录请求失败"); message.SetString(language.Chinese, MsgErrLoginRequest, "登录请求失败")
	message.SetString(language.Chinese, MsgErrLoginStatus, "登录失败：非预期的状态码 %s"); message.SetString(language.Chinese, MsgErrDecodeLoginResponse, "解析登录响应失败")
	message.SetString(language.Chinese, MsgErrTokenNotFound, "登录成功但未返回Token"); message.SetString(language.Chinese, MsgErrQueryRoot, "查询根目录失败")
	message.SetString(language.Chinese, MsgErrFindParentDir, "找不到父目录 '%s'"); message.SetString(language.Chinese, MsgErrFindSrcDir, "操作失败，找不到源目录 '%s'")
	message.SetString(language.Chinese, MsgErrFindDstDir, "操作失败，找不到目标目录 '%s'"); message.SetString(language.Chinese, MsgErrMarshalRequest, "序列化 %s 请求体失败")
	message.SetString(language.Chinese, MsgErrCreateRequest, "创建 %s 请求失败"); message.SetString(language.Chinese, MsgErrRequestFailed, "%s 请求失败")
	message.SetString(language.Chinese, MsgErrAPIStatus, "%s 失败，API返回状态码: %s"); message.SetString(language.Chinese, MsgErrDecodeResponse, "解析 %s 响应失败")
	message.SetString(language.Chinese, MsgErrIDNotFoundInResponse, "%s 成功但响应中未找到新ID"); message.SetString(language.Chinese, MsgErrSrcObjectType, "源对象类型错误")
	message.SetString(language.Chinese, MsgErrDirNotEmpty, "目录非空"); message.SetString(language.Chinese, MsgErrCantPurgeRoot, "不允许清除根目录")
	message.SetString(language.Chinese, MsgErrDownloadStatus, "下载失败：非预期的状态码 %s"); message.SetString(language.Chinese, MsgErrUploadStatus, "上传失败，状态码: %s")
	message.SetString(language.Chinese, MsgDebugRename, "检测到文件夹重命名操作: '%s' -> '%s'"); message.SetString(language.Chinese, MsgDebugMove, "检测到移动操作: '%s' -> '%s'")
	message.SetString(language.Chinese, MsgDebugRangeSupport, "服务器支持范围请求，开始分段下载。"); message.SetString(language.Chinese, MsgDebugRangeUnsupported, "服务器不支持范围请求，已返回整个文件。Rclone将在客户端处理所需分段。")
	message.SetString(language.Chinese, MsgDebugFullDownload, "开始完整文件下载。"); message.SetString(language.Chinese, MsgDebugUnknownItem, "发现未知项目类型 '%s'，项目名 '%s'")
}

// Options 定义了配置参数。
type Options struct {
	Server   string `config:"server"`; Username string `config:"user"`; Password string `config:"pass"`
	Domain   string `config:"domain,optional"`; Language string `config:"language,optional"`
}

// Fs 代表远程系统。
// 在 Fs 结构体添加目录缓存字段
type Fs struct {
    name      string; root string; opt Options; features  *fs.Features
    token     string; pacer *pacer.Pacer
    cache     map[string]string 
    cacheLock sync.Mutex; printer *message.Printer
    // 移除 dirCache 字段，使用其他方式处理目录缓存
}

// listResponse 定义了从服务器返回的列表响应结构
type listResponse struct {
    Nodes []node `json:"nodes"`
}

// node 定义了列表中的单个项目
type node struct {
    ID                  string `json:"id"`
    Name                string `json:"name"`
    Kind                string `json:"kind"`
    Size                int64  `json:"size"`
    ContentModifiedDate string `json:"contentModifiedDate"`
}

// Object describes an Agilent Secure Storage object
type Object struct {
    fs      *Fs       // what this object is part of
    remote  string    // The remote path
    id      string    // ID of the object
    modTime time.Time // The modified time of the object if known
    size    int64     // Size of the object
}

// 修改 NewFs 函数中的配置解码部分
func NewFs(ctx context.Context, name, root string, m configmap.Mapper) (fs.Fs, error) {
    opt := new(Options); p := message.NewPrinter(language.English) 
    // 替换旧的解码方式
    if err := configmap.Set(m, opt); err != nil {
        return nil, errors.Wrap(err, p.Sprintf(MsgErrParseOptions))
    }
    // 在初始化 Fs 时添加目录缓存
    f := &Fs{
        name: name, root: root, opt: *opt, token: authResponse.Token,
        pacer:   pacer.New(),
        cache:   make(map[string]string),
        printer: p,
    }
    f.features = (&fs.Features{
        CanHaveEmptyDirectories: true,
    }).Fill(ctx, f)
    if root != "" {
        if _, err = f.pathToID(ctx, ""); err != nil { return nil, errors.Wrap(err, p.Sprintf(MsgErrQueryRoot)) }
    }
    return f, nil
}

// Name 返回此远程配置的名称。
func (f *Fs) Name() string { return f.name }
// Root 返回用户配置的根路径。
func (f *Fs) Root() string { return f.root }
// String 返回对此后端的描述字符串。
func (f *Fs) String() string { return fmt.Sprintf("Agilent Secure Storage at %s", f.opt.Server) }
// Features 返回此后端支持的可选特性。
func (f *Fs) Features() *fs.Features { return f.features }
// Precision 返回后端支持的文件修改时间精度。
func (f *Fs) Precision() time.Duration { return time.Nanosecond }
// Hashes 返回此后端支持的哈希类型。
func (f *Fs) Hashes() hash.Set { return hash.NewHashSet() }

// List 列出指定目录中的对象和目录。
func (f *Fs) List(ctx context.Context, dir string) (entries fs.DirEntries, err error) {
	parentID, err := f.pathToID(ctx, dir)
	if err != nil { return nil, err }
	var offset int
	for {
		params := url.Values{}; params.Add("limit", fmt.Sprintf("%d", defaultLimit)); params.Add("offset", fmt.Sprintf("%d", offset))
		params.Add("select", "name,kind,size,contentModifiedDate,id"); params.Add("orderBy", "kind desc,name asc")
		listURL := fmt.Sprintf("https://%s/openlab/sdms/browse/v1.0/items/%s/children", f.opt.Server, parentID)
		var listResult listResponse
		err = f.pacer.Call(func() (bool, error) { 
			var doErr error; listResult, doErr = f.listPath(ctx, listURL, params); return fserrors.ShouldRetry(doErr), doErr
		})
		if err != nil { return nil, err }
		if len(listResult.Nodes) == 0 { break }
		for _, node := range listResult.Nodes {
			remote := path.Join(dir, node.Name)
			modTime, _ := time.Parse(timeFormat, node.ContentModifiedDate)
			switch node.Kind {
			case folderKind:
				d := fs.NewDir(remote, modTime).SetID(node.ID); entries = append(entries, d)
				f.cacheLock.Lock(); f.cache[remote] = node.ID; f.cacheLock.Unlock()
			case fileKind:
				entries = append(entries, &Object{fs: f, remote: remote, id: node.ID, modTime: modTime, size: node.Size})
			default:
				fs.Debugf(f, f.printer.Sprintf(MsgDebugUnknownItem, node.Kind, node.Name))
			}
		}
		offset += len(listResult.Nodes)
	}
	return entries, nil
}

// NewObject 返回一个占位符对象，用于后续的上传操作。
func (f *Fs) NewObject(ctx context.Context, remote string) (fs.Object, error) { return &Object{fs: f, remote: remote}, nil }

// Mkdir 创建一个目录。
func (f *Fs) Mkdir(ctx context.Context, dir string) error {
	parentDir, leaf := path.Split(dir); parentDir = path.Clean(parentDir)
	parentID, err := f.pathToID(ctx, parentDir)
	if err != nil { return errors.Wrapf(err, f.printer.Sprintf(MsgErrFindParentDir, parentDir)) }
	reqBody := map[string]string{"name": leaf}; reqBodyBytes, _ := json.Marshal(reqBody)
	action := f.printer.Sprintf(MsgActionMkdir)
	mkdirURL := fmt.Sprintf("https://%s/openlab/sdms/action/v1.0/items/%s/children", f.opt.Server, parentID)
	req, err := http.NewRequest("POST", mkdirURL, bytes.NewReader(reqBodyBytes))
	if err != nil { return errors.Wrap(err, f.printer.Sprintf(MsgErrCreateRequest, action)) }
	req.Header.Set("Authorization", "Bearer "+f.token); req.Header.Set("Content-Type", "application/json"); req.Header.Set("Accept", "application/json")
	var resp *http.Response
	err = f.pacer.Call(func() (bool, error) { var doErr error; resp, doErr = fshttp.NewClient(ctx).Do(req); return fserrors.ShouldRetry(doErr), doErr })
	if err != nil { return errors.Wrap(err, f.printer.Sprintf(MsgErrRequestFailed, action)) }
	defer fs.CheckClose(resp.Body, &err)
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK { return errors.New(f.printer.Sprintf(MsgErrAPIStatus, action, resp.Status)) }
	// 移除这行: fs.GetDirCache(ctx).Purge(parentDir)
	// 替换为:
	f.cacheLock.Lock()
	delete(f.cache, parentDir)
	f.cacheLock.Unlock()
	var result struct{ ID string `json:"id"` }
	if err := json.NewDecoder(resp.Body).Decode(&result); err == nil && result.ID != "" {
		f.cacheLock.Lock(); f.cache[dir] = result.ID; f.cacheLock.Unlock()
	}
	return nil
}

// Rmdir 删除一个空目录。
func (f *Fs) Rmdir(ctx context.Context, dir string) error {
	entries, err := f.List(ctx, dir); if err != nil { return err }
	if len(entries) != 0 { return errors.New(f.printer.Sprintf(MsgErrDirNotEmpty)) }
	itemID, err := f.pathToID(ctx, dir); if err != nil { return err }
	if err = f.deleteItemByID(ctx, itemID, "Rclone rmdir"); err != nil { return err }
	parentDir, _ := path.Split(dir); fs.GetDirCache(ctx).Purge(path.Clean(parentDir))
	f.cacheLock.Lock(); delete(f.cache, dir); f.cacheLock.Unlock()
	return nil
}

// Purge 删除一个目录及其所有内容。
func (f *Fs) Purge(ctx context.Context, dir string) error {
	if dir == "" { return errors.New(f.printer.Sprintf(MsgErrCantPurgeRoot)) }
	itemID, err := f.pathToID(ctx, dir)
	if err != nil { if err == fs.ErrorDirNotFound { return nil }; return err }
	if err = f.deleteItemByID(ctx, itemID, "Rclone purge"); err != nil { return err }
	parentDir, _ := path.Split(dir); fs.GetDirCache(ctx).Purge(path.Clean(parentDir))
	f.cacheLock.Lock()
	for k := range f.cache { if strings.HasPrefix(k, dir) { delete(f.cache, k) } }
	f.cacheLock.Unlock()
	return nil
}

// DirMove 移动或重命名一个目录。
func (f *Fs) DirMove(ctx context.Context, srcFS fs.Fs, srcRemote string) (err error) {
	src, ok := srcFS.(*Fs); if !ok { return fs.ErrorCantDirMove }
	srcParent, srcLeaf := path.Split(srcRemote); dstParent, dstLeaf := path.Split(f.root)
	if srcParent == dstParent {
		action := f.printer.Sprintf(MsgActionRename)
		fs.Debugf(src, f.printer.Sprintf(MsgDebugRename, srcLeaf, dstLeaf))
		dirID, err := src.pathToID(ctx, srcRemote)
		if err != nil { return errors.Wrapf(err, f.printer.Sprintf(MsgErrFindSrcDir, srcRemote)) }
		reqBody := map[string]string{"name": dstLeaf}; reqBodyBytes, _ := json.Marshal(reqBody)
		renameURL := fmt.Sprintf("https://%s/openlab/sdms/action/v1.0/items/%s/children", src.opt.Server, dirID)
		req, _ := http.NewRequest("PUT", renameURL, bytes.NewReader(reqBodyBytes))
		req.Header.Set("Authorization", "Bearer "+src.token); req.Header.Set("Content-Type", "application/json")
		resp, err := fshttp.NewClient(ctx).Do(req)
		if err != nil { return errors.Wrap(err, f.printer.Sprintf(MsgErrRequestFailed, action)) }
		defer fs.CheckClose(resp.Body, &err)
		if resp.StatusCode != http.StatusOK { return errors.New(f.printer.Sprintf(MsgErrAPIStatus, action, resp.Status)) }
	} else {
		fs.Debugf(src, f.printer.Sprintf(MsgDebugMove, srcRemote, f.root))
		srcID, err := src.pathToID(ctx, srcRemote)
		if err != nil { return errors.Wrapf(err, f.printer.Sprintf(MsgErrFindSrcDir, srcRemote)) }
		dstParentID, err := f.pathToID(ctx, f.root)
		if err != nil { return errors.Wrapf(err, f.printer.Sprintf(MsgErrFindDstDir, f.root)) }
		if _, err = src.moveOrCopyItem(ctx, srcID, dstParentID, "move"); err != nil { return err }
	}
	fs.GetDirCache(ctx).Purge(path.Clean(srcParent)); fs.GetDirCache(ctx).Purge(path.Clean(dstParent))
	src.cacheLock.Lock()
	for k := range src.cache { if strings.HasPrefix(k, srcRemote) { delete(src.cache, k) } }
	src.cacheLock.Unlock()
	return nil
}

// --- 辅助方法 ---

func (f *Fs) pathToID(ctx context.Context, dir string) (string, error) {
	if dir == "" || dir == "." || dir == "/" { return rootID, nil }
	f.cacheLock.Lock(); cachedID, ok := f.cache[dir]; f.cacheLock.Unlock()
	if ok { return cachedID, nil }
	parts := strings.Split(dir, "/"); currentID := rootID; currentPath := ""
	for _, part := range parts {
		if part == "" { continue }
		nextPath := path.Join(currentPath, part)
		f.cacheLock.Lock(); cachedID, ok = f.cache[nextPath]; f.cacheLock.Unlock()
		if ok { currentID = cachedID; currentPath = nextPath; continue }
		var foundNode *node; var offset int
		for {
			params := url.Values{}; params.Add("limit", "500"); params.Add("offset", fmt.Sprintf("%d", offset)); params.Add("select", "name,kind,id")
			listURL := fmt.Sprintf("https://%s/openlab/sdms/browse/v1.0/items/%s/children", f.opt.Server, currentID)
			var listResult listResponse
			err := f.pacer.Call(func() (bool, error) { var doErr error; listResult, doErr = f.listPath(ctx, listURL, params); return fserrors.ShouldRetry(doErr), doErr })
			if err != nil { return "", err }
			for i := range listResult.Nodes { if listResult.Nodes[i].Name == part && listResult.Nodes[i].Kind == folderKind { foundNode = &listResult.Nodes[i]; break } }
			if foundNode != nil || len(listResult.Nodes) < 500 { break }
			offset += 500
		}
		if foundNode == nil { return "", fs.ErrorDirNotFound }
		f.cacheLock.Lock(); f.cache[nextPath] = foundNode.ID; f.cacheLock.Unlock()
		currentID = foundNode.ID; currentPath = nextPath
	}
	return currentID, nil
}

func (f *Fs) listPath(ctx context.Context, urlString string, params url.Values) (listResponse, error) {
	var listResult listResponse; action := "list"
	req, _ := http.NewRequest("GET", urlString, nil)
	req.URL.RawQuery = params.Encode(); req.Header.Set("Authorization", "Bearer "+f.token); req.Header.Set("Accept", "application/json")
	resp, err := fshttp.NewClient(ctx).Do(req)
	if err != nil { return listResult, errors.Wrap(err, f.printer.Sprintf(MsgErrRequestFailed, action)) }
	defer fs.CheckClose(resp.Body, &err)
	if resp.StatusCode != http.StatusOK { return listResult, errors.New(f.printer.Sprintf(MsgErrAPIStatus, action, resp.Status)) }
	err = json.NewDecoder(resp.Body).Decode(&listResult)
	return listResult, errors.Wrapf(err, f.printer.Sprintf(MsgErrDecodeResponse, action))
}

func (f *Fs) deleteItemByID(ctx context.Context, itemID, reason string) error {
	action := f.printer.Sprintf(MsgActionDelete); params := url.Values{}; params.Add("reason", reason)
	deleteURL := fmt.Sprintf("https://%s/openlab/sdms/delete/v1.0/items/%s", f.opt.Server, itemID)
	req, _ := http.NewRequest("DELETE", deleteURL, nil)
	req.URL.RawQuery = params.Encode(); req.Header.Set("Authorization", "Bearer "+f.token)
	resp, err := fshttp.NewClient(ctx).Do(req)
	if err != nil { return errors.Wrap(err, f.printer.Sprintf(MsgErrRequestFailed, action)) }
	defer fs.CheckClose(resp.Body, &err)
	if resp.StatusCode != http.StatusNoContent { return errors.New(f.printer.Sprintf(MsgErrAPIStatus, action, resp.Status)) }
	return nil
}

func (f *Fs) moveOrCopyItem(ctx context.Context, srcID string, dstParentID string, action string) (newID string, err error) {
	trAction := f.printer.Sprintf(MsgActionMove); if action == "copy" { trAction = f.printer.Sprintf(MsgActionCopy) }
	actionURL := fmt.Sprintf("https://%s/openlab/sdms/action/v1.0/items/%s/%s/%s", f.opt.Server, srcID, action, dstParentID)
	req, _ := http.NewRequest("POST", actionURL, nil); req.Header.Set("Authorization", "Bearer "+f.token)
	resp, err := fshttp.NewClient(ctx).Do(req)
	if err != nil { return "", errors.Wrapf(err, f.printer.Sprintf(MsgErrRequestFailed, trAction)) }
	defer fs.CheckClose(resp.Body, &err)
	if resp.StatusCode != http.StatusCreated { return "", errors.New(f.printer.Sprintf(MsgErrAPIStatus, trAction, resp.Status)) }
	var result struct{ ID string `json:"id"` }
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil { return "", errors.Wrapf(err, f.printer.Sprintf(MsgErrDecodeResponse, trAction)) }
	if result.ID == "" { return "", errors.New(f.printer.Sprintf(MsgErrIDNotFoundInResponse, trAction)) }
	return result.ID, nil
}

// --- Object 的方法 ---

func (o *Object) Remote() string { return o.remote }
func (o *Object) ModTime(ctx context.Context) time.Time { return o.modTime }
func (o *Object) Size() int64 { return o.size }
func (o *Object) Fs() fs.Info { return o.fs }
func (o *Object) String() string { return o.remote }
func (o *Object) Storable() bool { return true }
func (o *Object) SetModTime(ctx context.Context, modTime time.Time) error { return fs.ErrorNotImplemented }
func (o *Object) Hash(ctx context.Context, ty hash.Type) (string, error) { return "", hash.ErrUnsupported }

func (o *Object) Open(ctx context.Context, options ...fs.OpenOption) (in io.ReadCloser, err error) {
	var rangeOption *fs.RangeOption; for _, option := range options { if opt, ok := option.(*fs.OpenOptionRange); ok { rangeOption = &opt.RangeOption } }
	downloadURL := fmt.Sprintf("https://%s/openlab/sdms/content/v1.0/file/%s/content", o.fs.opt.Server, o.id)
	req, _ := http.NewRequestWithContext(ctx, "GET", downloadURL, nil)
	req.Header.Set("Authorization", "Bearer "+o.fs.token); fs.OpenOptionAddHeaders(req.Header, options)
	var resp *http.Response
	err = o.fs.pacer.Call(func() (bool, error) { var doErr error; resp, doErr = fshttp.NewClient(ctx).Do(req); return fserrors.ShouldRetry(doErr), doErr })
	if err != nil { return nil, errors.Wrap(err, o.fs.printer.Sprintf(MsgErrRequestFailed, o.fs.printer.Sprintf(MsgActionDownload))) }
	switch resp.StatusCode {
	case http.StatusPartialContent: fs.Debugf(o, o.fs.printer.Sprintf(MsgDebugRangeSupport)); return resp.Body, nil
	case http.StatusOK:
		if rangeOption != nil { fs.Debugf(o, o.fs.printer.Sprintf(MsgDebugRangeUnsupported)); return fs.NewLimitedReadCloser(resp.Body, rangeOption.Start, rangeOption.End), nil }
		fs.Debugf(o, o.fs.printer.Sprintf(MsgDebugFullDownload)); return resp.Body, nil
	case http.StatusNotFound: fs.CheckClose(resp.Body, &err); return nil, fs.ErrorObjectNotFound
	default: fs.CheckClose(resp.Body, &err); return nil, errors.New(o.fs.printer.Sprintf(MsgErrDownloadStatus, resp.Status))
	}
}

func (o *Object) Update(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) error {
	parentDir, _ := path.Split(o.remote); parentDir = path.Clean(parentDir)
	parentID, err := o.fs.pathToID(ctx, parentDir); action := o.fs.printer.Sprintf(MsgActionUpload)
	if err != nil { return errors.Wrapf(err, o.fs.printer.Sprintf(MsgErrFindParentDir, parentDir)) }
	body := &bytes.Buffer{}; writer := multipart.NewWriter(body); filename := path.Base(o.remote)
	part, _ := writer.CreateFormField("filename"); part.Write([]byte(filename))
	part, _ = writer.CreateFormFile("file", filename)
	if _, err = io.Copy(part, in); err != nil { return errors.Wrap(err, "copy to form failed") }
	writer.Close()
	uploadURL := fmt.Sprintf("https://%s/openlab/sdms/content/v1.0/items/%s/content", o.fs.opt.Server, parentID)
	req, _ := http.NewRequest("POST", uploadURL, body)
	req.Header.Set("Authorization", "Bearer "+o.fs.token); req.Header.Set("Content-Type", writer.FormDataContentType())
	var resp *http.Response
	err = o.fs.pacer.Call(func() (bool, error) { var doErr error; resp, doErr = fshttp.NewClient(ctx).Do(req); return fserrors.ShouldRetry(doErr), doErr })
	if err != nil { return errors.Wrap(err, o.fs.printer.Sprintf(MsgErrRequestFailed, action)) }
	defer fs.CheckClose(resp.Body, &err)
	if resp.StatusCode != http.StatusCreated { return errors.New(o.fs.printer.Sprintf(MsgErrUploadStatus, resp.Status)) }
	fs.GetDirCache(ctx).Purge(parentDir)
	o.size = src.Size(); o.modTime = src.ModTime(ctx)
	return nil
}

func (o *Object) Remove(ctx context.Context) error {
	err := o.fs.deleteItemByID(ctx, o.id, "Rclone delete"); if err != nil { return err }
	parentDir, _ := path.Split(o.remote); fs.GetDirCache(ctx).Purge(path.Clean(parentDir))
	return nil
}

func (o *Object) Move(ctx context.Context, srcObj fs.Object, dstRemote string) (fs.Object, error) {
	src, ok := srcObj.(*Object); if !ok { return nil, errors.New(o.fs.printer.Sprintf(MsgErrSrcObjectType)) }
	srcParent, _ := path.Split(src.remote); dstParent, _ := path.Split(dstRemote)
	if srcParent == dstParent { return nil, fs.ErrorCantMove }
	dstParentID, err := o.fs.pathToID(ctx, dstParent)
	if err != nil { return nil, errors.Wrapf(err, o.fs.printer.Sprintf(MsgErrFindDstDir, dstParent)) }
	newID, err := o.fs.moveOrCopyItem(ctx, src.id, dstParentID, "move")
	if err != nil { return nil, err }
	newObj := &Object{fs: o.fs, remote: dstRemote, id: newID, modTime: src.modTime, size: src.size}
	fs.GetDirCache(ctx).Purge(path.Clean(srcParent)); fs.GetDirCache(ctx).Purge(path.Clean(dstParent))
	o.fs.cacheLock.Lock(); delete(o.fs.cache, src.remote); o.fs.cache[newObj.remote] = newID; o.fs.cacheLock.Unlock()
	return newObj, nil
}

func (o *Object) Copy(ctx context.Context, srcObj fs.Object, dstRemote string) (fs.Object, error) {
	src, ok := srcObj.(*Object); if !ok { return nil, errors.New(o.fs.printer.Sprintf(MsgErrSrcObjectType)) }
	dstParent, _ := path.Split(dstRemote)
	dstParentID, err := o.fs.pathToID(ctx, dstParent)
	if err != nil { return nil, errors.Wrapf(err, o.fs.printer.Sprintf(MsgErrFindDstDir, dstParent)) }
	newID, err := o.fs.moveOrCopyItem(ctx, src.id, dstParentID, "copy")
	if err != nil { return nil, err }
	fs.GetDirCache(ctx).Purge(path.Clean(dstParent))
	return &Object{fs: o.fs, remote: dstRemote, id: newID, modTime: time.Now(), size: src.size}, nil
}
