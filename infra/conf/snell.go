package conf

import (
	"github.com/golang/protobuf/proto"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/snell"
)

// SnellServerTarget is configuration of a single snell server
type SnellServerTarget struct {
	Address  *Address `json:"address"`
	Port     uint16   `json:"port"`
	Password string   `json:"password"`
	Email    string   `json:"email"`
	Level    byte     `json:"level"`
}

// SnellClientConfig is configuration of snell servers
type SnellClientConfig struct {
	Servers []*SnellServerTarget `json:"servers"`
}

// Build implements Buildable
func (c *SnellClientConfig) Build() (proto.Message, error) {
	config := new(snell.ClientConfig)

	if len(c.Servers) == 0 {
		return nil, newError("0 Snell server configured.")
	}

	serverSpecs := make([]*protocol.ServerEndpoint, len(c.Servers))
	for idx, rec := range c.Servers {
		if rec.Address == nil {
			return nil, newError("Snell server address is not set.")
		}
		if rec.Port == 0 {
			return nil, newError("Invalid Snell port.")
		}
		if rec.Password == "" {
			return nil, newError("Snell password is not specified.")
		}
		account := &snell.Account{
			Password: rec.Password,
		}

		snell := &protocol.ServerEndpoint{
			Address: rec.Address.Build(),
			Port:    uint32(rec.Port),
			User: []*protocol.User{
				{
					Level:   uint32(rec.Level),
					Email:   rec.Email,
					Account: serial.ToTypedMessage(account),
				},
			},
		}

		serverSpecs[idx] = snell
	}

	config.Server = serverSpecs

	return config, nil
}

// SnellServerConfig is Inbound configuration
type SnellServerConfig struct {
	Password string `json:"password"`
	Level    byte   `json:"level"`
	Email    string `json:"email"`
}

// Build implements Buildable
func (c *SnellServerConfig) Build() (proto.Message, error) {
	config := new(snell.ServerConfig)
	user := new(protocol.User)
	account := &snell.Account{
		Password: c.Password,
	}
	user.Email = c.Email
	user.Level = uint32(c.Level)
	user.Account = serial.ToTypedMessage(account)
	config.User = user

	return config, nil
}
