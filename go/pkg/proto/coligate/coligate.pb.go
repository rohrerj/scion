// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.27.1
// 	protoc        v3.15.3
// source: proto/coligate/v1/coligate.proto

package coligate

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type UpdateSigmasRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Asid              uint64           `protobuf:"varint,1,opt,name=asid,proto3" json:"asid,omitempty"`
	Suffix            []byte           `protobuf:"bytes,2,opt,name=suffix,proto3" json:"suffix,omitempty"`
	Bwcls             uint32           `protobuf:"varint,3,opt,name=bwcls,proto3" json:"bwcls,omitempty"`
	Rlc               uint32           `protobuf:"varint,4,opt,name=rlc,proto3" json:"rlc,omitempty"`
	ValidityTimestamp int64            `protobuf:"varint,5,opt,name=validityTimestamp,proto3" json:"validityTimestamp,omitempty"`
	HopInterfaces     []*HopInterfaces `protobuf:"bytes,6,rep,name=hopInterfaces,proto3" json:"hopInterfaces,omitempty"`
	Macs              [][]byte         `protobuf:"bytes,7,rep,name=macs,proto3" json:"macs,omitempty"`
}

func (x *UpdateSigmasRequest) Reset() {
	*x = UpdateSigmasRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_coligate_v1_coligate_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpdateSigmasRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpdateSigmasRequest) ProtoMessage() {}

func (x *UpdateSigmasRequest) ProtoReflect() protoreflect.Message {
	mi := &file_proto_coligate_v1_coligate_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpdateSigmasRequest.ProtoReflect.Descriptor instead.
func (*UpdateSigmasRequest) Descriptor() ([]byte, []int) {
	return file_proto_coligate_v1_coligate_proto_rawDescGZIP(), []int{0}
}

func (x *UpdateSigmasRequest) GetAsid() uint64 {
	if x != nil {
		return x.Asid
	}
	return 0
}

func (x *UpdateSigmasRequest) GetSuffix() []byte {
	if x != nil {
		return x.Suffix
	}
	return nil
}

func (x *UpdateSigmasRequest) GetBwcls() uint32 {
	if x != nil {
		return x.Bwcls
	}
	return 0
}

func (x *UpdateSigmasRequest) GetRlc() uint32 {
	if x != nil {
		return x.Rlc
	}
	return 0
}

func (x *UpdateSigmasRequest) GetValidityTimestamp() int64 {
	if x != nil {
		return x.ValidityTimestamp
	}
	return 0
}

func (x *UpdateSigmasRequest) GetHopInterfaces() []*HopInterfaces {
	if x != nil {
		return x.HopInterfaces
	}
	return nil
}

func (x *UpdateSigmasRequest) GetMacs() [][]byte {
	if x != nil {
		return x.Macs
	}
	return nil
}

type HopInterfaces struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Ingressid uint32 `protobuf:"varint,1,opt,name=ingressid,proto3" json:"ingressid,omitempty"`
	Egressid  uint32 `protobuf:"varint,2,opt,name=egressid,proto3" json:"egressid,omitempty"`
}

func (x *HopInterfaces) Reset() {
	*x = HopInterfaces{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_coligate_v1_coligate_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HopInterfaces) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HopInterfaces) ProtoMessage() {}

func (x *HopInterfaces) ProtoReflect() protoreflect.Message {
	mi := &file_proto_coligate_v1_coligate_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HopInterfaces.ProtoReflect.Descriptor instead.
func (*HopInterfaces) Descriptor() ([]byte, []int) {
	return file_proto_coligate_v1_coligate_proto_rawDescGZIP(), []int{1}
}

func (x *HopInterfaces) GetIngressid() uint32 {
	if x != nil {
		return x.Ingressid
	}
	return 0
}

func (x *HopInterfaces) GetEgressid() uint32 {
	if x != nil {
		return x.Egressid
	}
	return 0
}

type UpdateSigmasResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *UpdateSigmasResponse) Reset() {
	*x = UpdateSigmasResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_coligate_v1_coligate_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpdateSigmasResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpdateSigmasResponse) ProtoMessage() {}

func (x *UpdateSigmasResponse) ProtoReflect() protoreflect.Message {
	mi := &file_proto_coligate_v1_coligate_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpdateSigmasResponse.ProtoReflect.Descriptor instead.
func (*UpdateSigmasResponse) Descriptor() ([]byte, []int) {
	return file_proto_coligate_v1_coligate_proto_rawDescGZIP(), []int{2}
}

var File_proto_coligate_v1_coligate_proto protoreflect.FileDescriptor

var file_proto_coligate_v1_coligate_proto_rawDesc = []byte{
	0x0a, 0x20, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x63, 0x6f, 0x6c, 0x69, 0x67, 0x61, 0x74, 0x65,
	0x2f, 0x76, 0x31, 0x2f, 0x63, 0x6f, 0x6c, 0x69, 0x67, 0x61, 0x74, 0x65, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x12, 0x11, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x63, 0x6f, 0x6c, 0x69, 0x67, 0x61,
	0x74, 0x65, 0x2e, 0x76, 0x31, 0x22, 0xf3, 0x01, 0x0a, 0x13, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65,
	0x53, 0x69, 0x67, 0x6d, 0x61, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x12, 0x0a,
	0x04, 0x61, 0x73, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x04, 0x52, 0x04, 0x61, 0x73, 0x69,
	0x64, 0x12, 0x16, 0x0a, 0x06, 0x73, 0x75, 0x66, 0x66, 0x69, 0x78, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x06, 0x73, 0x75, 0x66, 0x66, 0x69, 0x78, 0x12, 0x14, 0x0a, 0x05, 0x62, 0x77, 0x63,
	0x6c, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x62, 0x77, 0x63, 0x6c, 0x73, 0x12,
	0x10, 0x0a, 0x03, 0x72, 0x6c, 0x63, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x03, 0x72, 0x6c,
	0x63, 0x12, 0x2c, 0x0a, 0x11, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x69, 0x74, 0x79, 0x54, 0x69, 0x6d,
	0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x18, 0x05, 0x20, 0x01, 0x28, 0x03, 0x52, 0x11, 0x76, 0x61,
	0x6c, 0x69, 0x64, 0x69, 0x74, 0x79, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x12,
	0x46, 0x0a, 0x0d, 0x68, 0x6f, 0x70, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x73,
	0x18, 0x06, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x20, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x63,
	0x6f, 0x6c, 0x69, 0x67, 0x61, 0x74, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x48, 0x6f, 0x70, 0x49, 0x6e,
	0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x73, 0x52, 0x0d, 0x68, 0x6f, 0x70, 0x49, 0x6e, 0x74,
	0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x73, 0x12, 0x12, 0x0a, 0x04, 0x6d, 0x61, 0x63, 0x73, 0x18,
	0x07, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x04, 0x6d, 0x61, 0x63, 0x73, 0x22, 0x49, 0x0a, 0x0d, 0x48,
	0x6f, 0x70, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x73, 0x12, 0x1c, 0x0a, 0x09,
	0x69, 0x6e, 0x67, 0x72, 0x65, 0x73, 0x73, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52,
	0x09, 0x69, 0x6e, 0x67, 0x72, 0x65, 0x73, 0x73, 0x69, 0x64, 0x12, 0x1a, 0x0a, 0x08, 0x65, 0x67,
	0x72, 0x65, 0x73, 0x73, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x08, 0x65, 0x67,
	0x72, 0x65, 0x73, 0x73, 0x69, 0x64, 0x22, 0x16, 0x0a, 0x14, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65,
	0x53, 0x69, 0x67, 0x6d, 0x61, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x32, 0x73,
	0x0a, 0x0e, 0x43, 0x6f, 0x6c, 0x69, 0x62, 0x72, 0x69, 0x47, 0x61, 0x74, 0x65, 0x77, 0x61, 0x79,
	0x12, 0x61, 0x0a, 0x0c, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x53, 0x69, 0x67, 0x6d, 0x61, 0x73,
	0x12, 0x26, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x63, 0x6f, 0x6c, 0x69, 0x67, 0x61, 0x74,
	0x65, 0x2e, 0x76, 0x31, 0x2e, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x53, 0x69, 0x67, 0x6d, 0x61,
	0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x27, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x2e, 0x63, 0x6f, 0x6c, 0x69, 0x67, 0x61, 0x74, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x55, 0x70, 0x64,
	0x61, 0x74, 0x65, 0x53, 0x69, 0x67, 0x6d, 0x61, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x22, 0x00, 0x42, 0x33, 0x5a, 0x31, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f,
	0x6d, 0x2f, 0x73, 0x63, 0x69, 0x6f, 0x6e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x73, 0x63, 0x69,
	0x6f, 0x6e, 0x2f, 0x67, 0x6f, 0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f,
	0x63, 0x6f, 0x6c, 0x69, 0x67, 0x61, 0x74, 0x65, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_proto_coligate_v1_coligate_proto_rawDescOnce sync.Once
	file_proto_coligate_v1_coligate_proto_rawDescData = file_proto_coligate_v1_coligate_proto_rawDesc
)

func file_proto_coligate_v1_coligate_proto_rawDescGZIP() []byte {
	file_proto_coligate_v1_coligate_proto_rawDescOnce.Do(func() {
		file_proto_coligate_v1_coligate_proto_rawDescData = protoimpl.X.CompressGZIP(file_proto_coligate_v1_coligate_proto_rawDescData)
	})
	return file_proto_coligate_v1_coligate_proto_rawDescData
}

var file_proto_coligate_v1_coligate_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_proto_coligate_v1_coligate_proto_goTypes = []interface{}{
	(*UpdateSigmasRequest)(nil),  // 0: proto.coligate.v1.UpdateSigmasRequest
	(*HopInterfaces)(nil),        // 1: proto.coligate.v1.HopInterfaces
	(*UpdateSigmasResponse)(nil), // 2: proto.coligate.v1.UpdateSigmasResponse
}
var file_proto_coligate_v1_coligate_proto_depIdxs = []int32{
	1, // 0: proto.coligate.v1.UpdateSigmasRequest.hopInterfaces:type_name -> proto.coligate.v1.HopInterfaces
	0, // 1: proto.coligate.v1.ColibriGateway.UpdateSigmas:input_type -> proto.coligate.v1.UpdateSigmasRequest
	2, // 2: proto.coligate.v1.ColibriGateway.UpdateSigmas:output_type -> proto.coligate.v1.UpdateSigmasResponse
	2, // [2:3] is the sub-list for method output_type
	1, // [1:2] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_proto_coligate_v1_coligate_proto_init() }
func file_proto_coligate_v1_coligate_proto_init() {
	if File_proto_coligate_v1_coligate_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_proto_coligate_v1_coligate_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpdateSigmasRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_proto_coligate_v1_coligate_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HopInterfaces); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_proto_coligate_v1_coligate_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpdateSigmasResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_proto_coligate_v1_coligate_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_proto_coligate_v1_coligate_proto_goTypes,
		DependencyIndexes: file_proto_coligate_v1_coligate_proto_depIdxs,
		MessageInfos:      file_proto_coligate_v1_coligate_proto_msgTypes,
	}.Build()
	File_proto_coligate_v1_coligate_proto = out.File
	file_proto_coligate_v1_coligate_proto_rawDesc = nil
	file_proto_coligate_v1_coligate_proto_goTypes = nil
	file_proto_coligate_v1_coligate_proto_depIdxs = nil
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConnInterface

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion6

// ColibriGatewayClient is the client API for ColibriGateway service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type ColibriGatewayClient interface {
	UpdateSigmas(ctx context.Context, in *UpdateSigmasRequest, opts ...grpc.CallOption) (*UpdateSigmasResponse, error)
}

type colibriGatewayClient struct {
	cc grpc.ClientConnInterface
}

func NewColibriGatewayClient(cc grpc.ClientConnInterface) ColibriGatewayClient {
	return &colibriGatewayClient{cc}
}

func (c *colibriGatewayClient) UpdateSigmas(ctx context.Context, in *UpdateSigmasRequest, opts ...grpc.CallOption) (*UpdateSigmasResponse, error) {
	out := new(UpdateSigmasResponse)
	err := c.cc.Invoke(ctx, "/proto.coligate.v1.ColibriGateway/UpdateSigmas", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ColibriGatewayServer is the server API for ColibriGateway service.
type ColibriGatewayServer interface {
	UpdateSigmas(context.Context, *UpdateSigmasRequest) (*UpdateSigmasResponse, error)
}

// UnimplementedColibriGatewayServer can be embedded to have forward compatible implementations.
type UnimplementedColibriGatewayServer struct {
}

func (*UnimplementedColibriGatewayServer) UpdateSigmas(context.Context, *UpdateSigmasRequest) (*UpdateSigmasResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateSigmas not implemented")
}

func RegisterColibriGatewayServer(s *grpc.Server, srv ColibriGatewayServer) {
	s.RegisterService(&_ColibriGateway_serviceDesc, srv)
}

func _ColibriGateway_UpdateSigmas_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateSigmasRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ColibriGatewayServer).UpdateSigmas(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/proto.coligate.v1.ColibriGateway/UpdateSigmas",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ColibriGatewayServer).UpdateSigmas(ctx, req.(*UpdateSigmasRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _ColibriGateway_serviceDesc = grpc.ServiceDesc{
	ServiceName: "proto.coligate.v1.ColibriGateway",
	HandlerType: (*ColibriGatewayServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "UpdateSigmas",
			Handler:    _ColibriGateway_UpdateSigmas_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "proto/coligate/v1/coligate.proto",
}
