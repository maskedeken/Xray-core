package obfs

import (
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/transport/internet"
)

const protocolName = "obfs"

func (c *Config) GetCustomizedHost() string {
	if c.Host != "" {
		return c.Host
	}

	return "bing.com"
}

func init() {
	common.Must(internet.RegisterProtocolConfigCreator(protocolName, func() interface{} {
		return new(Config)
	}))
}
