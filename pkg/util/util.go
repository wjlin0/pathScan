package util

import (
	"archive/zip"
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/projectdiscovery/gologger"
	fileutil "github.com/projectdiscovery/utils/file"
	"hash"
	"io"
	"math/rand"
	"net"
	defaultHttp "net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
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
		return nil
	}
	proxyURL, err := url.Parse(proxy)
	if err != nil {
		gologger.Error().Msgf("解析代理 URL 失败：%s", err)
		return nil
	}
	if auth != "" {
		username, password, ok := ParseProxyAuth(auth)
		if !ok {
			gologger.Error().Msgf("解析代理授权信息失败：%s", auth)
			return nil
		}
		proxyURL.User = url.UserPassword(username, password)
	}
	return defaultHttp.ProxyURL(proxyURL)
}

// Unzip 覆盖解压
func Unzip(p string, reader *bytes.Reader) error {

	zipReader, err := zip.NewReader(reader, reader.Size())
	if err != nil {
		return fmt.Errorf("failed to uncompress zip file: %w", err)
	}
	for _, f := range zipReader.File {
		filePath := filepath.Join(p, filepath.Base(f.Name))
		if f.FileInfo().IsDir() {
			err := fileutil.CreateFolders(filePath)
			if err != nil {
				return fmt.Errorf("无法打开压缩包: %w\n", err)
			}
			continue
		}
		file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			gologger.Error().Msgf(fmt.Errorf("打开文件是出错: %w\n", err).Error())
			continue
		}
		fileZip, err := f.Open()
		if err != nil {
			gologger.Error().Msgf(fmt.Errorf("读取压缩包出错: %w\n", err).Error())
			continue
		}
		_, err = io.Copy(file, fileZip)
		if err != nil {
			gologger.Error().Msgf(fmt.Errorf("写入时文件是出错: %w\n", err).Error())
			continue
		}
	}
	return nil

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
func IsSubdomainOrSameDomain(orl string, link string) bool {
	o, _ := url.Parse(orl)
	l, err := url.Parse(link)
	if err != nil {
		return false
	}
	if orl == link {
		return false
	}
	// 如果 old 是ip,直接返回 true
	if net.ParseIP(o.Hostname()) != nil {
		return true
	}

	topDomain := ""
	oldDomainLen := len(strings.Split(o.Hostname(), "."))
	linkDomainLen := len(strings.Split(l.Hostname(), "."))
	switch oldDomainLen {
	case 2:
		topDomain = o.Hostname()
	case 1:
		return false
	default:
		topDomain = strings.Join(strings.Split(o.Hostname(), ".")[1:], ".")
	}
	// 如果等于顶级域名返回 true
	if linkDomainLen == len(strings.Split(topDomain, ".")) && l.Hostname() == topDomain {
		return true
	}
	// 如果是子域名或者是同级域名返回 true
	if linkDomainLen >= oldDomainLen && strings.Contains(l.Hostname(), topDomain) {
		return true
	}

	return false
}
func ExtractURLs(text string) []string {
	// 正则表达式模式匹配URL
	pattern := `https?://[^\s<>"]+|www\.[^\s<>"]+`
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
