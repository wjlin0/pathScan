package util

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/projectdiscovery/gologger"
	http "github.com/projectdiscovery/retryablehttp-go"
	fileutil "github.com/projectdiscovery/utils/file"
	folderutil "github.com/projectdiscovery/utils/folder"
	"golang.org/x/net/proxy"
	"hash"
	"io"
	"io/fs"
	"math/rand"
	"net"
	defaultHttp "net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ParseProxyAuth 辅助函数：解析代理授权信息（格式为“username:password”）
func ParseProxyAuth(auth string) (string, string, bool) {
	parts := strings.SplitN(auth, ":", 2)
	if len(parts) != 2 || parts[0] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// GetCheckRedirectFunc 辅助函数：获取 CheckRedirect 函数
func GetCheckRedirectFunc(errUseLastResponse bool) func(req *defaultHttp.Request, via []*defaultHttp.Request) error {
	if errUseLastResponse {
		return func(req *defaultHttp.Request, via []*defaultHttp.Request) error {
			return defaultHttp.ErrUseLastResponse
		}
	} else {
		return nil
	}
}

// GetProxyFunc 辅助函数：获取代理设置函数
func GetProxyFunc(proxy, auth string) func(*defaultHttp.Request) (*url.URL, error) {
	if proxy == "" {
		return defaultHttp.ProxyFromEnvironment
	}
	proxyURL, err := url.Parse(proxy)
	if err != nil {
		gologger.Error().Msgf("Failed to parse proxy URL：%s", err)
		return nil
	}
	if auth != "" {
		username, password, ok := ParseProxyAuth(auth)
		if !ok {
			gologger.Error().Msgf("Failed to parse proxy authorization information：%s", auth)
			return nil
		}
		proxyURL.User = url.UserPassword(username, password)
	}
	return defaultHttp.ProxyURL(proxyURL)
}
func GetProxyURL(proxy, auth string) (*url.URL, error) {
	if proxy == "" {
		return nil, nil
	}
	proxyURL, err := url.Parse(proxy)
	if err != nil {
		return nil, err
	}
	if auth != "" {
		username, password, ok := ParseProxyAuth(auth)
		if !ok {
			gologger.Error().Msgf("Failed to parse proxy authorization information：%s", auth)
			return nil, err
		}
		proxyURL.User = url.UserPassword(username, password)
	}
	return proxyURL, nil
}

// Unzip 覆盖解压
func Unzip(p string, reader *bytes.Reader) error {

	zipReader, err := zip.NewReader(reader, reader.Size())
	if err != nil {
		return fmt.Errorf("failed to uncompress zip file: %w", err)
	}
	for _, f := range zipReader.File {
		filePath := filepath.Join(p, f.Name)
		if f.FileInfo().IsDir() {
			err := fileutil.CreateFolders(filePath)
			if err != nil {
				return fmt.Errorf("无法打开压缩包: %w\n", err)
			}
			continue
		}
		file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			gologger.Error().Msgf(fmt.Errorf("Error opening file: %w\n", err).Error())
			continue
		}
		fileZip, err := f.Open()
		if err != nil {
			gologger.Error().Msgf(fmt.Errorf("Error reading compressed package: %w\n", err).Error())
			continue
		}
		_, err = io.Copy(file, fileZip)
		if err != nil {
			gologger.Error().Msgf(fmt.Errorf("file encountered an error while writing: %w\n", err).Error())
			continue
		}
	}
	return nil

}

// compareAndWriteTemplates compares and returns the stats of a template update operations.
func Nunzip(p string, zipReader *zip.Reader) error {

	// We use file-checksums that are md5 hashes to store the list of files->hashes
	// that have been downloaded previously.
	// If the path isn't found in new update after being read from the previous checksum,
	// it is removed. This allows us fine-grained control over the download process
	// as well as solves a long problem with nuclei-template updates.
	configuredTemplateDirectory := p
	for _, zipTemplateFile := range zipReader.File {
		templateAbsolutePath, skipFile, err := calculateTemplateAbsolutePath(zipTemplateFile.Name, configuredTemplateDirectory)
		if err != nil {
			return err
		}
		if skipFile {
			continue
		}

		_, err = writeUnZippedTemplateFile(templateAbsolutePath, zipTemplateFile)
		if err != nil {
			return err
		}

		_, err = filepath.Rel(configuredTemplateDirectory, templateAbsolutePath)
		if err != nil {
			return fmt.Errorf("could not calculate relative path for template: %s. %w", templateAbsolutePath, err)
		}

	}
	return nil
}
func writeUnZippedTemplateFile(templateAbsolutePath string, zipTemplateFile *zip.File) (string, error) {
	templateFile, err := os.OpenFile(templateAbsolutePath, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return "", fmt.Errorf("could not create template file: %w", err)
	}

	zipTemplateFileReader, err := zipTemplateFile.Open()
	if err != nil {
		_ = templateFile.Close()
		return "", fmt.Errorf("could not open archive to extract file: %w", err)
	}

	md5Hash := md5.New()

	// Save file and also read into hash.HashMethod for md5
	if _, err := io.Copy(templateFile, io.TeeReader(zipTemplateFileReader, md5Hash)); err != nil {
		_ = templateFile.Close()
		return "", fmt.Errorf("could not write template file: %w", err)
	}

	if err := templateFile.Close(); err != nil {
		return "", fmt.Errorf("could not close file newly created template file: %w", err)
	}

	checksum := hex.EncodeToString(md5Hash.Sum(nil))
	return checksum, nil
}
func calculateTemplateAbsolutePath(zipFilePath, configuredTemplateDirectory string) (string, bool, error) {
	directory, fileName := filepath.Split(zipFilePath)

	if !strings.EqualFold(fileName, ".version") {
		if strings.TrimSpace(fileName) == "" || strings.HasPrefix(fileName, ".") || strings.EqualFold(fileName, "README.md") {
			return "", true, nil
		}
	}

	var (
		directoryPathChunks                 []string
		relativeDirectoryPathWithoutZipRoot string
	)
	if folderutil.IsUnixOS() {
		directoryPathChunks = strings.Split(directory, string(os.PathSeparator))
	} else if folderutil.IsWindowsOS() {
		pathInfo, _ := folderutil.NewPathInfo(directory)
		directoryPathChunks = pathInfo.Parts
	}
	relativeDirectoryPathWithoutZipRoot = filepath.Join(directoryPathChunks[1:]...)

	if strings.HasPrefix(relativeDirectoryPathWithoutZipRoot, ".") {
		return "", true, nil
	}

	templateDirectory := filepath.Join(configuredTemplateDirectory, relativeDirectoryPathWithoutZipRoot)

	if err := os.MkdirAll(templateDirectory, 0755); err != nil {
		return "", false, fmt.Errorf("failed to create template folder: %s. %w", templateDirectory, err)
	}

	return filepath.Join(templateDirectory, fileName), false, nil
}

func RandStr(length int) string {
	str := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	strByte := []byte(str)
	result := []byte{}
	rand.Seed(time.Now().UnixNano() + int64(rand.Intn(100)))
	for i := 0; i < length; i++ {
		result = append(result, strByte[rand.Intn(len(strByte))])
	}
	return string(result)
}
func DataRoot(elem ...string) string {
	home, _ := os.UserHomeDir()
	var e []string
	home = filepath.Join(home, ".config", "pathScan")
	e = append(e, home)
	e = append(e, elem...)
	return filepath.Join(e...)
}

func AppendCreate(name string) (*os.File, error) {
	return os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
}

func FindStringSubmatch(reg, str string) []string {
	compile := regexp.MustCompile(reg)
	return compile.FindStringSubmatch(str)
}
func MatchString(reg, str string) bool {
	compile := regexp.MustCompile(reg)
	return compile.MatchString(str)
}
func GetHash(body []byte, method string) ([]byte, error) {
	var h hash.Hash
	switch method {
	case "md5":
		h = md5.New()
	case "sha1":
		h = sha1.New()
	case "sha256":
		h = sha256.New()
	default:
		return nil, fmt.Errorf("unsupported hash method:%s", method)
	}
	h.Write(body)
	return []byte(hex.EncodeToString(h.Sum(nil))), nil
}

func ExtractHost(rawURL string) string {
	// 找到第一个斜杠或冒号的位置
	slashIndex := strings.Index(rawURL, "/")
	colonIndex := strings.Index(rawURL, ":")
	// 在斜杠和冒号之间取较小的索引值
	var index int
	if slashIndex != -1 && colonIndex != -1 {
		index = slashIndex
	} else if slashIndex != -1 {
		index = slashIndex
	} else if colonIndex != -1 {
		index = colonIndex
	} else {
		// 如果没有斜杠和冒号，则直接返回原始URL
		return rawURL
	}
	// 截取索引位置之前的部分作为主机名
	host := rawURL[:index]

	return host
}

var exts = []string{
	"com", "org", "net", "info", "biz", "us", "uk", "cn", "jp", "de", "fr", "ca", "au", "in", "ru",
	"app", "blog", "guru", "tech", "travel", "store", "online",
	"xyz", "club", "media", "design", "space", "global", "world", "pro",
	"edu", "gov", "mil", "co",
}

func GetPartString(part string, data map[string]interface{}) (string, bool) {
	if part == "" {
		part = "body"
	}
	if part == "header" {
		part = "all_headers"
	}
	var itemStr string
	switch part {
	case "all":
		builder := &strings.Builder{}
		builder.WriteString(ToString(data["body"]))
		builder.WriteString(ToString(data["all_headers"]))
		itemStr = builder.String()
	default:
		item, ok := data[part]
		if !ok {
			return "", false
		}
		itemStr = ToString(item)

	}
	return itemStr, true
}

// ToString converts an interface to string in a quick way
func ToString(data interface{}) string {
	switch s := data.(type) {
	case nil:
		return ""
	case string:
		return s
	case bool:
		return strconv.FormatBool(s)
	case float64:
		return strconv.FormatFloat(s, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(s), 'f', -1, 32)
	case int:
		return strconv.Itoa(s)
	case int64:
		return strconv.FormatInt(s, 10)
	case int32:
		return strconv.Itoa(int(s))
	case int16:
		return strconv.FormatInt(int64(s), 10)
	case int8:
		return strconv.FormatInt(int64(s), 10)
	case uint:
		return strconv.FormatUint(uint64(s), 10)
	case uint64:
		return strconv.FormatUint(s, 10)
	case uint32:
		return strconv.FormatUint(uint64(s), 10)
	case uint16:
		return strconv.FormatUint(uint64(s), 10)
	case uint8:
		return strconv.FormatUint(uint64(s), 10)
	case []byte:
		return string(s)
	case fmt.Stringer:
		return s.String()
	case error:
		return s.Error()
	default:
		return fmt.Sprintf("%v", data)
	}
}

func GetMainDomain(domain string) string {
	top := 2
	parts := strings.Split(domain, ".")
	if len(parts) <= 2 {
		return domain
	}
	ext := parts[len(parts)-2]
	for _, e := range exts {
		if ext == e {
			top = 3
			break
		}
	}
	if len(parts) <= top {
		return domain
	}
	return strings.Join(parts[len(parts)-top:], ".")
}
func IsSubdomainOrSameDomain(orl string, link string) bool {
	o, _ := url.Parse(orl)
	l, err := url.Parse(link)
	if err != nil {
		return false
	}
	if orl == link {
		return false
	}
	// 如果 old 是ip,直接返回 false
	if net.ParseIP(o.Hostname()) != nil {
		return false
	}
	linkHostname := l.Hostname()
	oldHostname := o.Hostname()
	// 没有 协议 的情况，使用正则匹配 提取出 linkHostname
	if l.Host == "" {
		linkHostname = ExtractHost(l.Path)
	}

	topDomain := ""
	oldDomainLen := len(strings.Split(oldHostname, "."))

	linkDomainLen := len(strings.Split(linkHostname, "."))

	switch oldDomainLen {
	case 2:
		topDomain = oldHostname
	case 1:
		return false
	default:
		topDomain = strings.Join(strings.Split(oldHostname, ".")[1:], ".")
	}
	// 如果等于顶级域名返回 true
	if linkDomainLen == len(strings.Split(topDomain, ".")) && linkHostname == topDomain {
		return true
	}
	// 如果是子域名或者是同级域名返回 true
	if linkDomainLen >= oldDomainLen && strings.Contains(linkHostname, topDomain) {
		return true
	}

	return false
}
func ExtractURLs(text string) []string {
	// 正则表达式模式匹配URL
	pattern := `https?://[^\s<>()'"]+|www\.[^\s<>()'"]+`
	re := regexp.MustCompile(pattern)
	// 查找所有匹配的URL
	urls_ := re.FindAllString(text, -1)
	urlMap := make(map[string]struct{})
	for _, url_ := range urls_ {
		urlMap[url_] = struct{}{}
	}
	var urls []string
	for k, _ := range urlMap {
		urls = append(urls_, k)
	}
	return urls
}

func GetTrueUrl(text *url.URL) string {
	// 获取URL的主机和方案部分
	host := text.Host
	scheme := text.Scheme

	// 拼接主机和方案部分
	trueURL := scheme + "://" + host
	return trueURL
}
func ListFilesWithExtension(rootPath, extension string) ([]string, error) {
	var files []string

	err := filepath.WalkDir(rootPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if !d.IsDir() && filepath.Ext(d.Name()) == extension {
			files = append(files, path)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return files, nil
}

func JoinPath(target, path string) string {
	target = strings.TrimRight(target, "/")
	if !strings.HasPrefix(path, "/") {
		path = fmt.Sprintf("/%s", path)
	}
	return fmt.Sprintf("%s%s", target, path)
}

func GetRequestPackage(request *http.Request) string {
	if request == nil {
		return ""
	}
	var bodyBytes []byte
	// 备份请求体
	if request.Body != nil {
		bodyBytes, _ = io.ReadAll(request.Body)
		request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	// 拼接请求行
	requestLine := fmt.Sprintf("%s %s %s\r\n", request.Method, request.URL.Path, request.Proto)

	// 拼接请求头
	var headers strings.Builder

	//单独拼接Host
	headers.WriteString(fmt.Sprintf("Host: %s\r\n", request.Host))

	for key, values := range request.Header {
		for _, value := range values {
			if strings.ToLower(key) == "host" {
				continue
			}
			headers.WriteString(fmt.Sprintf("%s: %s\r\n", key, value))
		}
	}
	body := string(bodyBytes)
	// 拼接空行
	blankLine := "\r\n"
	// 将请求行、请求头和空行合并成原始请求包内容
	requestPackage := strings.Join([]string{requestLine, headers.String(), blankLine, body}, "")

	return requestPackage
}

func GetResponsePackage(response *defaultHttp.Response, body []byte, getBody bool) string {
	if response == nil {
		return ""
	}
	var responsePackage strings.Builder

	var bodyBytes []byte
	// 备份请求体
	if body != nil && getBody {
		bodyBytes = body
		//buffer := bytes.Buffer{}
		//_, err := io.Copy(&buffer, response.Body)
		//if err != nil {
		//	return ""
		//}
		//bodyBytes = buffer.Bytes()
		//response.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	// 拼接响应行
	statusLine := fmt.Sprintf("%s %s %s\r\n", response.Proto, response.Status, defaultHttp.StatusText(response.StatusCode))

	// 拼接响应头
	var headers strings.Builder
	for key, values := range response.Header {
		for _, value := range values {
			headers.WriteString(fmt.Sprintf("%s: %s\r\n", key, value))
		}
	}

	// 拼接空行
	blankLine := "\r\n"
	//body :=
	responsePackage.WriteString(statusLine)
	responsePackage.WriteString(headers.String())
	responsePackage.WriteString(blankLine)
	if getBody {
		responsePackage.WriteString(string(bodyBytes))
	}

	// 将响应行、响应头和空行合并成原始响应包内容

	return responsePackage.String()
}

// ReadFile 从指定文件中读取数据
func ReadFile(filename string) (string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ReplaceStringsInFile 用于读取文件，替换其中的特定字符串，并在原文件上进行修改
func ReplaceStringsInFile(templateFile, oldString, newString string) error {
	// 打开模板文件
	file, err := os.OpenFile(templateFile, os.O_RDWR, 0666)
	if err != nil {
		return fmt.Errorf("error opening template file: %w", err)
	}
	defer file.Close()

	// 逐行读取模板文件并进行替换后写回原文件
	scanner := bufio.NewScanner(file)
	var lines []string
	for scanner.Scan() {
		line := scanner.Text()
		updatedLine := strings.Replace(line, oldString, newString, -1)
		lines = append(lines, updatedLine)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading template file: %w", err)
	}

	// 清空文件内容
	file.Truncate(0)

	// 将替换后的内容写回文件
	file.Seek(0, 0)
	writer := bufio.NewWriter(file)
	for _, line := range lines {
		_, err := fmt.Fprintln(writer, line)
		if err != nil {
			return fmt.Errorf("error writing to template file: %w", err)
		}
	}
	writer.Flush()

	return nil
}

// WriteFile 将数据写入指定文件
func WriteFile(filename string, string2 string) error {
	// 打开文件，如果文件不存在则创建，如果文件已存在则截断文件（清空文件内容）
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	// 写入数据
	_, err = file.Write([]byte(string2))
	if err != nil {
		return err
	}

	return nil
}

func FindStringInFile(filepath string, target string) bool {
	// 打开文件
	file, err := os.Open(filepath)
	if err != nil {
		return false
	}
	defer file.Close()

	// 创建一个Scanner来读取文件内容
	scanner := bufio.NewScanner(file)

	// 遍历每一行，查找是否存在目标字符串
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), target) {
			return true
		}
	}

	// 如果未找到目标字符串，则返回false
	return false
}
func GetMatchVersion(defaultMatchDir string) (string, error) {
	open, err := os.Open(filepath.Join(defaultMatchDir, ".version"))
	if err != nil {
		return "", err
	}
	defer open.Close()
	scanner := bufio.NewScanner(open)
	var version string
	if scanner.Scan() {
		// 获取第一行的内容
		version = scanner.Text()
	} else {
		return "", nil
	}
	return version, nil
}

func NewProxyDialer(proxyUrl, proxyAuth string) (proxy.Dialer, error) {
	var auther *proxy.Auth
	if proxyAuth != "" {
		auth := strings.Split(proxyAuth, ":")
		auther = &proxy.Auth{
			User:     auth[0],
			Password: auth[1],
		}
	}
	return proxy.SOCKS5("tcp", proxyUrl, auther, proxy.Direct)
}
func FindOffset(file *os.File, target string) (int64, error) {
	stat, err := file.Stat()
	if err != nil {
		return 0, err
	}

	fileSize := stat.Size()
	bufferSize := 1024 // 可根据需要调整缓冲区大小
	buffer := make([]byte, bufferSize)
	offset := int64(0)

	for offset < fileSize {
		n, readErr := file.ReadAt(buffer, offset)
		if readErr != nil {
			return 0, readErr
		}
		if index := bytes.Index(buffer[:n], []byte(target)); index != -1 {
			return offset + int64(index), nil
		}

		offset += int64(n)
	}
	return 0, fmt.Errorf("not find target")
}

// RemoveDuplicateStrings 字符串数组去重
func RemoveDuplicateStrings(arr []string) []string {
	var result []string
	temp := map[string]byte{}
	for _, e := range arr {
		if temp[e] == 0 {
			temp[e] = 1
			result = append(result, e)
		}
	}
	return result
}

// 移除字符串重复的、为空的的字符串
func RemoveDuplicateAndEmptyStrings(arr []string) []string {
	var result []string
	temp := map[string]byte{}
	for _, e := range arr {
		if temp[e] == 0 && e != "" {
			temp[e] = 1
			result = append(result, e)
		}
	}
	return result
}
