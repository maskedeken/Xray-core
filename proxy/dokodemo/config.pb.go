// Code generated by protoc-gen-go. DO NOT EDIT.
// source: proxy/dokodemo/config.proto

package dokodemo

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	net "github.com/xtls/xray-core/common/net"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type Config struct {
	Address *net.IPOrDomain `protobuf:"bytes,1,opt,name=address,proto3" json:"address,omitempty"`
	Port    uint32          `protobuf:"varint,2,opt,name=port,proto3" json:"port,omitempty"`
	// List of networks that the Dokodemo accepts.
	// Deprecated. Use networks.
	NetworkList *net.NetworkList `protobuf:"bytes,3,opt,name=network_list,json=networkList,proto3" json:"network_list,omitempty"` // Deprecated: Do not use.
	// List of networks that the Dokodemo accepts.
	Networks             []net.Network `protobuf:"varint,7,rep,packed,name=networks,proto3,enum=xray.common.net.Network" json:"networks,omitempty"`
	Timeout              uint32        `protobuf:"varint,4,opt,name=timeout,proto3" json:"timeout,omitempty"` // Deprecated: Do not use.
	FollowRedirect       bool          `protobuf:"varint,5,opt,name=follow_redirect,json=followRedirect,proto3" json:"follow_redirect,omitempty"`
	UserLevel            uint32        `protobuf:"varint,6,opt,name=user_level,json=userLevel,proto3" json:"user_level,omitempty"`
	Flow                 string        `protobuf:"bytes,8,opt,name=flow,proto3" json:"flow,omitempty"`
	XXX_NoUnkeyedLiteral struct{}      `json:"-"`
	XXX_unrecognized     []byte        `json:"-"`
	XXX_sizecache        int32         `json:"-"`
}

func (m *Config) Reset()         { *m = Config{} }
func (m *Config) String() string { return proto.CompactTextString(m) }
func (*Config) ProtoMessage()    {}
func (*Config) Descriptor() ([]byte, []int) {
	return fileDescriptor_c131e861c122b509, []int{0}
}

func (m *Config) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Config.Unmarshal(m, b)
}
func (m *Config) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Config.Marshal(b, m, deterministic)
}
func (m *Config) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Config.Merge(m, src)
}
func (m *Config) XXX_Size() int {
	return xxx_messageInfo_Config.Size(m)
}
func (m *Config) XXX_DiscardUnknown() {
	xxx_messageInfo_Config.DiscardUnknown(m)
}

var xxx_messageInfo_Config proto.InternalMessageInfo

func (m *Config) GetAddress() *net.IPOrDomain {
	if m != nil {
		return m.Address
	}
	return nil
}

func (m *Config) GetPort() uint32 {
	if m != nil {
		return m.Port
	}
	return 0
}

// Deprecated: Do not use.
func (m *Config) GetNetworkList() *net.NetworkList {
	if m != nil {
		return m.NetworkList
	}
	return nil
}

func (m *Config) GetNetworks() []net.Network {
	if m != nil {
		return m.Networks
	}
	return nil
}

// Deprecated: Do not use.
func (m *Config) GetTimeout() uint32 {
	if m != nil {
		return m.Timeout
	}
	return 0
}

func (m *Config) GetFollowRedirect() bool {
	if m != nil {
		return m.FollowRedirect
	}
	return false
}

func (m *Config) GetUserLevel() uint32 {
	if m != nil {
		return m.UserLevel
	}
	return 0
}

func (m *Config) GetFlow() string {
	if m != nil {
		return m.Flow
	}
	return ""
}

func init() {
	proto.RegisterType((*Config)(nil), "xray.proxy.dokodemo.Config")
}

func init() {
	proto.RegisterFile("proxy/dokodemo/config.proto", fileDescriptor_c131e861c122b509)
}

var fileDescriptor_c131e861c122b509 = []byte{
	// 340 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x74, 0x91, 0xcf, 0x4e, 0x2a, 0x31,
	0x14, 0x87, 0x33, 0x03, 0x97, 0x3f, 0xe5, 0x8a, 0x49, 0x59, 0xd8, 0x08, 0x26, 0x13, 0x37, 0xce,
	0xc6, 0x69, 0x82, 0xfa, 0x02, 0xc0, 0xc6, 0x84, 0x28, 0xe9, 0xca, 0xe8, 0x82, 0xc0, 0x4c, 0xc1,
	0x86, 0x4e, 0x0f, 0x69, 0x8b, 0xc0, 0x2b, 0xf9, 0x24, 0x3e, 0x96, 0x69, 0x67, 0xd0, 0x10, 0x75,
	0xd7, 0xfe, 0xfa, 0xf5, 0x3b, 0xe7, 0xe4, 0xa0, 0xee, 0x5a, 0xc3, 0x6e, 0x4f, 0x33, 0x58, 0x41,
	0xc6, 0x73, 0xa0, 0x29, 0xa8, 0x85, 0x58, 0x26, 0x6b, 0x0d, 0x16, 0x70, 0x67, 0xa7, 0x67, 0xfb,
	0xc4, 0x13, 0xc9, 0x81, 0x38, 0x27, 0x29, 0xe4, 0x39, 0x28, 0xaa, 0xb8, 0xa5, 0xb3, 0x2c, 0xd3,
	0xdc, 0x98, 0x02, 0x3f, 0x7a, 0x51, 0xdc, 0x6e, 0x41, 0xaf, 0x8a, 0x97, 0xcb, 0x8f, 0x10, 0xd5,
	0x86, 0xde, 0x8c, 0xef, 0x50, 0xbd, 0xfc, 0x45, 0x82, 0x28, 0x88, 0x5b, 0xfd, 0x6e, 0xe2, 0xab,
	0x14, 0x7f, 0x13, 0xc5, 0x6d, 0x72, 0x3f, 0x79, 0xd4, 0x23, 0xc8, 0x67, 0x42, 0xb1, 0x03, 0x8b,
	0x31, 0xaa, 0xae, 0x41, 0x5b, 0x12, 0x46, 0x41, 0x7c, 0xc2, 0xfc, 0x19, 0x0f, 0xd1, 0xff, 0xb2,
	0xcc, 0x54, 0x0a, 0x63, 0x49, 0xc5, 0xfb, 0x7a, 0x3f, 0x7c, 0x0f, 0x05, 0x34, 0x16, 0xc6, 0x0e,
	0x42, 0x12, 0xb0, 0x96, 0xfa, 0x0e, 0xf0, 0x2d, 0x6a, 0x94, 0x57, 0x43, 0xea, 0x51, 0x25, 0x6e,
	0xf7, 0xc9, 0x5f, 0x02, 0xf6, 0x45, 0xe2, 0x1e, 0xaa, 0x5b, 0x91, 0x73, 0xd8, 0x58, 0x52, 0x75,
	0x1d, 0x79, 0xef, 0x21, 0xc2, 0x57, 0xe8, 0x74, 0x01, 0x52, 0xc2, 0x76, 0xaa, 0x79, 0x26, 0x34,
	0x4f, 0x2d, 0xf9, 0x17, 0x05, 0x71, 0x83, 0xb5, 0x8b, 0x98, 0x95, 0x29, 0xbe, 0x40, 0x68, 0x63,
	0xb8, 0x9e, 0x4a, 0xfe, 0xc6, 0x25, 0xa9, 0xf9, 0xd9, 0x9a, 0x2e, 0x19, 0xbb, 0xc0, 0x0d, 0xbd,
	0x90, 0xb0, 0x25, 0x8d, 0x28, 0x88, 0x9b, 0xcc, 0x9f, 0x07, 0x2f, 0xe8, 0x2c, 0x85, 0x3c, 0xf9,
	0x65, 0x33, 0x93, 0xe0, 0x39, 0x5e, 0x0a, 0xfb, 0xba, 0x99, 0xbb, 0xde, 0xe9, 0xce, 0x4a, 0x43,
	0x1d, 0x76, 0x9d, 0x82, 0xe6, 0xf4, 0x78, 0xcf, 0xef, 0x61, 0xe7, 0xc9, 0x19, 0x26, 0xde, 0x30,
	0x2a, 0xd3, 0x79, 0xcd, 0xaf, 0xeb, 0xe6, 0x33, 0x00, 0x00, 0xff, 0xff, 0x7e, 0x5e, 0x84, 0xf3,
	0x16, 0x02, 0x00, 0x00,
}
