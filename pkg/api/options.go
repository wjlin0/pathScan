package api

import (
	"github.com/lqqyt2423/go-mitmproxy/proxy"
	folderutil "github.com/projectdiscovery/utils/folder"
	"github.com/wjlin0/pathScan/pkg/api/web"
	"github.com/wjlin0/pathScan/pkg/util"
	"net/http"
	"strings"

	"path/filepath"
)

var (
	defaultPathScanDir     = filepath.Join(folderutil.HomeDirOrDefault("."), ".config", "pathScan")
	defaultPathScanApiDir  = filepath.Join(defaultPathScanDir, "api")
	defaultPathScanCertDir = filepath.Join(defaultPathScanApiDir, "cert")
)

type Options struct {
	Addr              string   `json:"addr,omitempty"`
	WebAddr           string   `json:"web-addr"`
	StreamLargeBodies int64    `json:"stream-large-bodies,omitempty"`
	SslInsecure       bool     `json:"ssl-insecure,omitempty"`
	CaRootPath        string   `json:"ca-root-path,omitempty"`
	Upstream          string   `json:"upstream,omitempty"`
	AllowHosts        []string `json:"allow-hosts"`
}

func New(scanOpt map[string]interface{}) (*Options, error) {
	url, err := util.GetProxyURL(scanOpt["proxy"].(string), scanOpt["proxy-auth"].(string))
	if err != nil {
		return nil, err
	}
	var upstream string
	if url != nil {
		upstream = url.String()
	}
	var caPath string
	if scanOpt["proxy-api-cert-path"].(string) == "" {
		caPath = defaultPathScanCertDir
	}
	return &Options{
		Addr:              scanOpt["proxy-api-server"].(string),
		StreamLargeBodies: scanOpt["proxy-api-large-body"].(int64),
		SslInsecure:       scanOpt["proxy-api-ssl-insecure"].(bool),
		CaRootPath:        caPath,
		AllowHosts:        scanOpt["proxy-api-allow-hosts"].([]string),
		WebAddr:           scanOpt["proxy-api-web-server"].(string),
		Upstream:          upstream,
	}, nil
}
func (opt *Options) Start() error {
	p, err := proxy.NewProxy(&proxy.Options{
		Addr:              opt.Addr,
		StreamLargeBodies: opt.StreamLargeBodies,
		SslInsecure:       opt.SslInsecure,
		CaRootPath:        opt.CaRootPath,
		Upstream:          opt.Upstream,
	})
	if err != nil {
		return err
	}
	p.SetShouldInterceptRule(func(req *http.Request) bool {
		return matchHost(req.Host, opt.AllowHosts)
	})
	p.AddAddon(web.NewWebAddon(opt.WebAddr))
	return p.Start()
}
func splitHostPort(address string) (string, string) {
	index := strings.LastIndex(address, ":")
	if index == -1 {
		return address, ""
	}
	return address[:index], address[index+1:]
}
func matchHostname(hostname string, h string) bool {
	if h == "*" {
		return true
	}
	if strings.HasPrefix(h, "*.") {
		return hostname == h[2:] || strings.HasSuffix(hostname, h[1:])
	}
	return h == hostname
}
func matchHost(address string, hosts []string) bool {
	hostname, port := splitHostPort(address)
	for _, host := range hosts {
		h, p := splitHostPort(host)
		if matchHostname(hostname, h) && (p == "" || p == port) {
			return true
		}
	}
	return false
}
