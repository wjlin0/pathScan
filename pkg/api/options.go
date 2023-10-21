package api

import (
	"github.com/lqqyt2423/go-mitmproxy/proxy"
	folderutil "github.com/projectdiscovery/utils/folder"
	apiProxy "github.com/wjlin0/pathScan/pkg/api/web"
	"github.com/wjlin0/pathScan/pkg/common/identification"
	"github.com/wjlin0/pathScan/pkg/result"
	"github.com/wjlin0/pathScan/pkg/util"
	"net/http"
	"path/filepath"
	"strings"
)

var (
	defaultPathScanDir     = filepath.Join(folderutil.HomeDirOrDefault("."), ".config", "pathScan")
	defaultPathScanApiDir  = filepath.Join(defaultPathScanDir, "api")
	defaultPathScanCertDir = filepath.Join(defaultPathScanApiDir, "cert")
)

type Options struct {
	Addr              string   `json:"addr,omitempty"`
	StreamLargeBodies int64    `json:"stream-large-bodies,omitempty"`
	CaRootPath        string   `json:"ca-root-path,omitempty"`
	Upstream          string   `json:"upstream,omitempty"`
	AllowHosts        []string `json:"allow-hosts"`
	regexOpts         []*identification.Options
	output            chan *result.Result
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
		CaRootPath:        caPath,
		AllowHosts:        scanOpt["proxy-api-allow-hosts"].([]string),
		output:            scanOpt["output"].(chan *result.Result),
		regexOpts:         scanOpt["regexOpts"].([]*identification.Options),
		Upstream:          upstream,
	}, nil
}
func (opt *Options) Start() error {
	p, err := proxy.NewProxy(&proxy.Options{
		Addr:              opt.Addr,
		StreamLargeBodies: opt.StreamLargeBodies,
		SslInsecure:       true,
		CaRootPath:        opt.CaRootPath,
		Upstream:          opt.Upstream,
	})
	if err != nil {
		return err
	}
	p.SetShouldInterceptRule(func(req *http.Request) bool {
		return matchHost(req.Host, opt.AllowHosts)
	})
	p.AddAddon(apiProxy.NewWebAddon(opt.Addr, opt.AllowHosts, opt.regexOpts, opt.output))

	//p.AddAddon(web.NewWebAddon(":8083"))
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
