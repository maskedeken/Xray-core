// Code generated by protoc-gen-go. DO NOT EDIT.
// source: transport/internet/obfs/config.proto

package obfs

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
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

type ObfsType int32

const (
	ObfsType_HTTP ObfsType = 0
	ObfsType_TLS  ObfsType = 1
)

var ObfsType_name = map[int32]string{
	0: "HTTP",
	1: "TLS",
}

var ObfsType_value = map[string]int32{
	"HTTP": 0,
	"TLS":  1,
}

func (x ObfsType) String() string {
	return proto.EnumName(ObfsType_name, int32(x))
}

func (ObfsType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_0d1cff93ac1a5312, []int{0}
}

type Config struct {
	Type                 ObfsType `protobuf:"varint,2,opt,name=type,proto3,enum=xray.transport.internet.obfs.ObfsType" json:"type,omitempty"`
	Host                 string   `protobuf:"bytes,3,opt,name=host,proto3" json:"host,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Config) Reset()         { *m = Config{} }
func (m *Config) String() string { return proto.CompactTextString(m) }
func (*Config) ProtoMessage()    {}
func (*Config) Descriptor() ([]byte, []int) {
	return fileDescriptor_0d1cff93ac1a5312, []int{0}
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

func (m *Config) GetType() ObfsType {
	if m != nil {
		return m.Type
	}
	return ObfsType_HTTP
}

func (m *Config) GetHost() string {
	if m != nil {
		return m.Host
	}
	return ""
}

func init() {
	proto.RegisterEnum("xray.transport.internet.obfs.ObfsType", ObfsType_name, ObfsType_value)
	proto.RegisterType((*Config)(nil), "xray.transport.internet.obfs.Config")
}

func init() {
	proto.RegisterFile("transport/internet/obfs/config.proto", fileDescriptor_0d1cff93ac1a5312)
}

var fileDescriptor_0d1cff93ac1a5312 = []byte{
	// 223 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0x52, 0x29, 0x29, 0x4a, 0xcc,
	0x2b, 0x2e, 0xc8, 0x2f, 0x2a, 0xd1, 0xcf, 0xcc, 0x2b, 0x49, 0x2d, 0xca, 0x4b, 0x2d, 0xd1, 0xcf,
	0x4f, 0x4a, 0x2b, 0xd6, 0x4f, 0xce, 0xcf, 0x4b, 0xcb, 0x4c, 0xd7, 0x2b, 0x28, 0xca, 0x2f, 0xc9,
	0x17, 0x92, 0xa9, 0x28, 0x4a, 0xac, 0xd4, 0x83, 0x2b, 0xd5, 0x83, 0x29, 0xd5, 0x03, 0x29, 0x55,
	0x8a, 0xe3, 0x62, 0x73, 0x06, 0xab, 0x16, 0xb2, 0xe2, 0x62, 0x29, 0xa9, 0x2c, 0x48, 0x95, 0x60,
	0x52, 0x60, 0xd4, 0xe0, 0x33, 0x52, 0xd3, 0xc3, 0xa7, 0x4d, 0xcf, 0x3f, 0x29, 0xad, 0x38, 0xa4,
	0xb2, 0x20, 0x35, 0x08, 0xac, 0x47, 0x48, 0x88, 0x8b, 0x25, 0x23, 0xbf, 0xb8, 0x44, 0x82, 0x59,
	0x81, 0x51, 0x83, 0x33, 0x08, 0xcc, 0xf6, 0x62, 0xe1, 0x60, 0x14, 0x60, 0xd2, 0x92, 0xe5, 0xe2,
	0x80, 0xa9, 0x15, 0xe2, 0xe0, 0x62, 0xf1, 0x08, 0x09, 0x09, 0x10, 0x60, 0x10, 0x62, 0xe7, 0x62,
	0x0e, 0xf1, 0x09, 0x16, 0x60, 0x74, 0x2a, 0xe3, 0x52, 0x48, 0xce, 0xcf, 0xc5, 0x6b, 0x57, 0x00,
	0x63, 0x94, 0x61, 0x7a, 0x66, 0x49, 0x46, 0x69, 0x92, 0x5e, 0x72, 0x7e, 0xae, 0x7e, 0x45, 0x49,
	0x4e, 0xb1, 0x3e, 0x48, 0xbd, 0x6e, 0x72, 0x7e, 0x51, 0xaa, 0x3e, 0x8e, 0x20, 0x58, 0xc5, 0x24,
	0x13, 0x01, 0x32, 0x33, 0x04, 0x6e, 0xa6, 0x27, 0xcc, 0x4c, 0x90, 0x73, 0x92, 0xd8, 0xc0, 0x61,
	0x63, 0x0c, 0x08, 0x00, 0x00, 0xff, 0xff, 0xea, 0x7a, 0x18, 0xb5, 0x43, 0x01, 0x00, 0x00,
}
