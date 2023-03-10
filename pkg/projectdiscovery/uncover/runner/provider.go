package runner

import (
	"math/rand"
	"strings"

	"github.com/wjlin0/pathScan/pkg/projectdiscovery/uncover/uncover"
)

type Provider struct {
	Shodan     []string `yaml:"shodan"`
	Censys     []string `yaml:"censys"`
	Fofa       []string `yaml:"fofa"`
	Quake      []string `yaml:"quake"`
	Hunter     []string `yaml:"hunter"`
	ZoomEye    []string `yaml:"zoomeye"`
	Netlas     []string `yaml:"netlas"`
	CriminalIP []string `yaml:"criminalip"`
	Zone       []string `yaml:"zone"`
	Binary     []string `yaml:"binary"`
}

func (provider *Provider) GetKeys() uncover.Keys {
	keys := uncover.Keys{}

	if len(provider.Censys) > 0 {
		censysKeys := provider.Censys[rand.Intn(len(provider.Censys))]
		parts := strings.Split(censysKeys, ":")
		if len(parts) == 2 {
			keys.CensysToken = parts[0]
			keys.CensysSecret = parts[1]
		}
	}

	if len(provider.Shodan) > 0 {
		keys.Shodan = provider.Shodan[rand.Intn(len(provider.Shodan))]
	}

	if len(provider.Fofa) > 0 {
		fofaKeys := provider.Fofa[rand.Intn(len(provider.Fofa))]
		parts := strings.Split(fofaKeys, ":")
		if len(parts) == 2 {
			keys.FofaEmail = parts[0]
			keys.FofaKey = parts[1]
		}
	}

	if len(provider.Quake) > 0 {
		keys.QuakeToken = provider.Quake[rand.Intn(len(provider.Quake))]
	}

	if len(provider.Hunter) > 0 {
		keys.HunterToken = provider.Hunter[rand.Intn(len(provider.Hunter))]
	}

	if len(provider.ZoomEye) > 0 {
		keys.ZoomEyeToken = provider.ZoomEye[rand.Intn(len(provider.ZoomEye))]
	}

	if len(provider.Netlas) > 0 {
		keys.NetlasToken = provider.Netlas[rand.Intn(len(provider.Netlas))]
	}

	if len(provider.CriminalIP) > 0 {
		keys.CriminalIPToken = provider.CriminalIP[rand.Intn(len(provider.CriminalIP))]
	}
	if len(provider.Zone) > 0 {
		keys.ZoneToken = provider.Zone[rand.Intn(len(provider.Zone))]
	}
	if len(provider.Binary) > 0 {
		keys.BinaryToken = provider.Binary[rand.Intn(len(provider.Binary))]
	}
	return keys
}

func (provider *Provider) HasKeys() bool {
	return len(provider.Censys) > 0 ||
		len(provider.Shodan) > 0 ||
		len(provider.Fofa) > 0 ||
		len(provider.Quake) > 0 ||
		len(provider.Hunter) > 0 ||
		len(provider.ZoomEye) > 0 ||
		len(provider.Netlas) > 0 ||
		len(provider.CriminalIP) > 0 ||
		len(provider.Zone) > 0 ||
		len(provider.Binary) > 0
}
