// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: security/proto/providers/google/iam/certificateservice.proto

/*
	Package google_iam_credentials_v1 is a generated protocol buffer package.

	It is generated from these files:
		security/proto/providers/google/iam/certificateservice.proto

	It has these top-level messages:
		GetFederatedTokenRequest
		GetFederatedTokenResponse
		OAuth2Error
*/
package google_iam_credentials_v1

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"

//import _ "google/api"
//import google_api2 "github.com/googleapis/googleapis/google/api"
import _ "github.com/gogo/protobuf/gogoproto"
import google_api2 "google.golang.org/genproto/googleapis/api/httpbody"

import strings "strings"
import reflect "reflect"

import context "golang.org/x/net/context"
import grpc "google.golang.org/grpc"

import io "io"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion2 // please upgrade the proto package

type GetFederatedTokenRequest struct {
	// REQUIRED. Indicating that a token change is being performed.
	// The value must be 'urn:ietf:params:oauth:grant-type:token-exchange'.
	GrantType string `protobuf:"bytes,1,opt,name=grant_type,json=grantType,proto3" json:"grant_type,omitempty"`
	// REQUIRED. Resource where the client intends to use the requested security
	// token. The value should be the email or unique ID of a Google service
	// account.
	Audience string `protobuf:"bytes,2,opt,name=audience,proto3" json:"audience,omitempty"`
	// REQUIRED. Desired OAuth2 scopes that will be included in the resulting
	// access token.
	Scope []string `protobuf:"bytes,3,rep,name=scope" json:"scope,omitempty"`
	// REQUIRED. Identifier for the type of the requested security token.
	// The only currently supported value is
	// 'urn:ietf:params:oauth:token-type:access_token'
	RequestedTokenType string `protobuf:"bytes,4,opt,name=requested_token_type,json=requestedTokenType,proto3" json:"requested_token_type,omitempty"`
	// REQUIRED. Input token.
	// Must be in JWT format according to RFC7523 and must have
	// key ID and algorithm specified in the header.
	// Supported signing algorithms: RS256.
	// Mandatory payload fields (along the lines of RFC 7523, section 3):
	// - iss: issuer of the token. Must provide a discovery document at
	//        $iss/.well-known/openid-configuration . The document needs to be
	//        formatted according to section 4.2 of the OpenID Connect Discovery
	//        1.0 specification.
	// - iat: Issue time in seconds since epoch. Must be in the past.
	// - exp: Expiration time in seconds since epoch. Must be less than 48 hours
	//        after iat. We recommend to create tokens that last shorter than 6
	//        hours to improve security unless business reasons mandate longer
	//        expiration times. Shorter token lifetimes are generally more secure
	//        since tokens that have been exfiltrated by attackers can be used for
	//        a shorter time.
	// - sub: JWT subject, identity asserted in the JWT.
	// - aud: Configured in the mapper policy. By default the service account
	//        unique ID.
	//
	// Claims from the incoming token can be transferred into the output token
	// according to the mapper configuration. The outgoing claim size is limited.
	// Outgoing claims size must be less than 4kB serialized as JSON without
	// whitespace.
	//
	// Example header:
	// {
	//   "alg": "RS256",
	//   "kid": "us-east-11"
	// }
	// Example payload:
	// {
	//   "iss": "https://accounts.google.com",
	//   "iat": 1517963104,
	//   "exp": 1517966704,
	//   "aud": "113475438248934895348",
	//   "sub": "113475438248934895348",
	//   "my_claims": {
	//     "additional_claim": "value"
	//   }
	// }
	SubjectToken string `protobuf:"bytes,5,opt,name=subject_token,json=subjectToken,proto3" json:"subject_token,omitempty"`
	// REQUIRED. An identifier that indicates the type of the security token in
	// the 'subject_token' parameter. The only currently supported value is
	// 'urn:ietf:params:oauth:token-type:jwt'.
	SubjectTokenType string `protobuf:"bytes,6,opt,name=subject_token_type,json=subjectTokenType,proto3" json:"subject_token_type,omitempty"`
}

func (m *GetFederatedTokenRequest) Reset()      { *m = GetFederatedTokenRequest{} }
func (*GetFederatedTokenRequest) ProtoMessage() {}
func (*GetFederatedTokenRequest) Descriptor() ([]byte, []int) {
	return fileDescriptorCertificateservice, []int{0}
}

func (m *GetFederatedTokenRequest) GetGrantType() string {
	if m != nil {
		return m.GrantType
	}
	return ""
}

func (m *GetFederatedTokenRequest) GetAudience() string {
	if m != nil {
		return m.Audience
	}
	return ""
}

func (m *GetFederatedTokenRequest) GetScope() []string {
	if m != nil {
		return m.Scope
	}
	return nil
}

func (m *GetFederatedTokenRequest) GetRequestedTokenType() string {
	if m != nil {
		return m.RequestedTokenType
	}
	return ""
}

func (m *GetFederatedTokenRequest) GetSubjectToken() string {
	if m != nil {
		return m.SubjectToken
	}
	return ""
}

func (m *GetFederatedTokenRequest) GetSubjectTokenType() string {
	if m != nil {
		return m.SubjectTokenType
	}
	return ""
}

// Response message for GetFederatedToken API.
type GetFederatedTokenResponse struct {
	// The Google service account access token in the requested format.
	// Currently, the token is only going to be an OAuth2.0 access token.
	AccessToken string `protobuf:"bytes,1,opt,name=access_token,proto3" json:"access_token,omitempty"`
	// Same value as 'requested_token_type' parameter in request.
	IssuedTokenType string `protobuf:"bytes,2,opt,name=issued_token_type,proto3" json:"issued_token_type,omitempty"`
	// Type of token by usage as authenticator. The only currently supported value
	// is "Bearer".
	TokenType string `protobuf:"bytes,3,opt,name=token_type,proto3" json:"token_type,omitempty"`
	// Expiration time in seconds, measured from the time of issuance.
	ExpiresIn int64 `protobuf:"varint,4,opt,name=expires_in,proto3" json:"expires_in,omitempty"`
}

func (m *GetFederatedTokenResponse) Reset()      { *m = GetFederatedTokenResponse{} }
func (*GetFederatedTokenResponse) ProtoMessage() {}
func (*GetFederatedTokenResponse) Descriptor() ([]byte, []int) {
	return fileDescriptorCertificateservice, []int{1}
}

func (m *GetFederatedTokenResponse) GetAccessToken() string {
	if m != nil {
		return m.AccessToken
	}
	return ""
}

func (m *GetFederatedTokenResponse) GetIssuedTokenType() string {
	if m != nil {
		return m.IssuedTokenType
	}
	return ""
}

func (m *GetFederatedTokenResponse) GetTokenType() string {
	if m != nil {
		return m.TokenType
	}
	return ""
}

func (m *GetFederatedTokenResponse) GetExpiresIn() int64 {
	if m != nil {
		return m.ExpiresIn
	}
	return 0
}

// Custom error response for GetFederatedToken API. The error format is defined
// by the OAuth2.0 spec (RFC 6749).
type OAuth2Error struct {
	// Required. Constant that indicates which error occurred.
	Error string `protobuf:"bytes,1,opt,name=error,proto3" json:"error,omitempty"`
	// Human-readable description of the error.
	ErrorDescription string `protobuf:"bytes,2,opt,name=error_description,proto3" json:"error_description,omitempty"`
}

func (m *OAuth2Error) Reset()                    { *m = OAuth2Error{} }
func (*OAuth2Error) ProtoMessage()               {}
func (*OAuth2Error) Descriptor() ([]byte, []int) { return fileDescriptorCertificateservice, []int{2} }

func (m *OAuth2Error) GetError() string {
	if m != nil {
		return m.Error
	}
	return ""
}

func (m *OAuth2Error) GetErrorDescription() string {
	if m != nil {
		return m.ErrorDescription
	}
	return ""
}

func init() {
	proto.RegisterType((*GetFederatedTokenRequest)(nil), "google.iam.credentials.v1.GetFederatedTokenRequest")
	proto.RegisterType((*GetFederatedTokenResponse)(nil), "google.iam.credentials.v1.GetFederatedTokenResponse")
	proto.RegisterType((*OAuth2Error)(nil), "google.iam.credentials.v1.OAuth2Error")
}
func (this *GetFederatedTokenRequest) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*GetFederatedTokenRequest)
	if !ok {
		that2, ok := that.(GetFederatedTokenRequest)
		if ok {
			that1 = &that2
		} else {
			return false
		}
	}
	if that1 == nil {
		return this == nil
	} else if this == nil {
		return false
	}
	if this.GrantType != that1.GrantType {
		return false
	}
	if this.Audience != that1.Audience {
		return false
	}
	if len(this.Scope) != len(that1.Scope) {
		return false
	}
	for i := range this.Scope {
		if this.Scope[i] != that1.Scope[i] {
			return false
		}
	}
	if this.RequestedTokenType != that1.RequestedTokenType {
		return false
	}
	if this.SubjectToken != that1.SubjectToken {
		return false
	}
	if this.SubjectTokenType != that1.SubjectTokenType {
		return false
	}
	return true
}
func (this *GetFederatedTokenResponse) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*GetFederatedTokenResponse)
	if !ok {
		that2, ok := that.(GetFederatedTokenResponse)
		if ok {
			that1 = &that2
		} else {
			return false
		}
	}
	if that1 == nil {
		return this == nil
	} else if this == nil {
		return false
	}
	if this.AccessToken != that1.AccessToken {
		return false
	}
	if this.IssuedTokenType != that1.IssuedTokenType {
		return false
	}
	if this.TokenType != that1.TokenType {
		return false
	}
	if this.ExpiresIn != that1.ExpiresIn {
		return false
	}
	return true
}
func (this *OAuth2Error) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*OAuth2Error)
	if !ok {
		that2, ok := that.(OAuth2Error)
		if ok {
			that1 = &that2
		} else {
			return false
		}
	}
	if that1 == nil {
		return this == nil
	} else if this == nil {
		return false
	}
	if this.Error != that1.Error {
		return false
	}
	if this.ErrorDescription != that1.ErrorDescription {
		return false
	}
	return true
}
func (this *GetFederatedTokenRequest) GoString() string {
	if this == nil {
		return "nil"
	}
	s := make([]string, 0, 10)
	s = append(s, "&google_iam_credentials_v1.GetFederatedTokenRequest{")
	s = append(s, "GrantType: "+fmt.Sprintf("%#v", this.GrantType)+",\n")
	s = append(s, "Audience: "+fmt.Sprintf("%#v", this.Audience)+",\n")
	s = append(s, "Scope: "+fmt.Sprintf("%#v", this.Scope)+",\n")
	s = append(s, "RequestedTokenType: "+fmt.Sprintf("%#v", this.RequestedTokenType)+",\n")
	s = append(s, "SubjectToken: "+fmt.Sprintf("%#v", this.SubjectToken)+",\n")
	s = append(s, "SubjectTokenType: "+fmt.Sprintf("%#v", this.SubjectTokenType)+",\n")
	s = append(s, "}")
	return strings.Join(s, "")
}
func (this *GetFederatedTokenResponse) GoString() string {
	if this == nil {
		return "nil"
	}
	s := make([]string, 0, 8)
	s = append(s, "&google_iam_credentials_v1.GetFederatedTokenResponse{")
	s = append(s, "AccessToken: "+fmt.Sprintf("%#v", this.AccessToken)+",\n")
	s = append(s, "IssuedTokenType: "+fmt.Sprintf("%#v", this.IssuedTokenType)+",\n")
	s = append(s, "TokenType: "+fmt.Sprintf("%#v", this.TokenType)+",\n")
	s = append(s, "ExpiresIn: "+fmt.Sprintf("%#v", this.ExpiresIn)+",\n")
	s = append(s, "}")
	return strings.Join(s, "")
}
func (this *OAuth2Error) GoString() string {
	if this == nil {
		return "nil"
	}
	s := make([]string, 0, 6)
	s = append(s, "&google_iam_credentials_v1.OAuth2Error{")
	s = append(s, "Error: "+fmt.Sprintf("%#v", this.Error)+",\n")
	s = append(s, "ErrorDescription: "+fmt.Sprintf("%#v", this.ErrorDescription)+",\n")
	s = append(s, "}")
	return strings.Join(s, "")
}
func valueToGoStringCertificateservice(v interface{}, typ string) string {
	rv := reflect.ValueOf(v)
	if rv.IsNil() {
		return "nil"
	}
	pv := reflect.Indirect(rv).Interface()
	return fmt.Sprintf("func(v %v) *%v { return &v } ( %#v )", typ, typ, pv)
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for CertificateService service

type CertificateServiceClient interface {
	// Exchanges a third-party issued Json Web Token for an OAuth2.0 access token
	// belongs to a Google Cloud service account.
	// (-- The API is going to be exposed under
	// https://securetoken.googleapis.com/v1/identitybindingtoken as a MVP.
	// The returned HttpBody contains either GetFederatedTokenResponse or
	// OAuth2Error.
	GetFederatedToken(ctx context.Context, in *GetFederatedTokenRequest, opts ...grpc.CallOption) (*google_api2.HttpBody, error)
}

type certificateServiceClient struct {
	cc *grpc.ClientConn
}

func NewCertificateServiceClient(cc *grpc.ClientConn) CertificateServiceClient {
	return &certificateServiceClient{cc}
}

func (c *certificateServiceClient) GetFederatedToken(ctx context.Context, in *GetFederatedTokenRequest, opts ...grpc.CallOption) (*google_api2.HttpBody, error) {
	out := new(google_api2.HttpBody)
	err := grpc.Invoke(ctx, "/google.iam.credentials.v1.CertificateService/GetFederatedToken", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for CertificateService service

type CertificateServiceServer interface {
	// Exchanges a third-party issued Json Web Token for an OAuth2.0 access token
	// belongs to a Google Cloud service account.
	// (-- The API is going to be exposed under
	// https://securetoken.googleapis.com/v1/identitybindingtoken as a MVP.
	// The returned HttpBody contains either GetFederatedTokenResponse or
	// OAuth2Error.
	GetFederatedToken(context.Context, *GetFederatedTokenRequest) (*google_api2.HttpBody, error)
}

func RegisterCertificateServiceServer(s *grpc.Server, srv CertificateServiceServer) {
	s.RegisterService(&_CertificateService_serviceDesc, srv)
}

func _CertificateService_GetFederatedToken_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetFederatedTokenRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CertificateServiceServer).GetFederatedToken(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/google.iam.credentials.v1.CertificateService/GetFederatedToken",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CertificateServiceServer).GetFederatedToken(ctx, req.(*GetFederatedTokenRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _CertificateService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "google.iam.credentials.v1.CertificateService",
	HandlerType: (*CertificateServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetFederatedToken",
			Handler:    _CertificateService_GetFederatedToken_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "security/proto/providers/google/iam/certificateservice.proto",
}

func (m *GetFederatedTokenRequest) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *GetFederatedTokenRequest) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if len(m.GrantType) > 0 {
		dAtA[i] = 0xa
		i++
		i = encodeVarintCertificateservice(dAtA, i, uint64(len(m.GrantType)))
		i += copy(dAtA[i:], m.GrantType)
	}
	if len(m.Audience) > 0 {
		dAtA[i] = 0x12
		i++
		i = encodeVarintCertificateservice(dAtA, i, uint64(len(m.Audience)))
		i += copy(dAtA[i:], m.Audience)
	}
	if len(m.Scope) > 0 {
		for _, s := range m.Scope {
			dAtA[i] = 0x1a
			i++
			l = len(s)
			for l >= 1<<7 {
				dAtA[i] = uint8(uint64(l)&0x7f | 0x80)
				l >>= 7
				i++
			}
			dAtA[i] = uint8(l)
			i++
			i += copy(dAtA[i:], s)
		}
	}
	if len(m.RequestedTokenType) > 0 {
		dAtA[i] = 0x22
		i++
		i = encodeVarintCertificateservice(dAtA, i, uint64(len(m.RequestedTokenType)))
		i += copy(dAtA[i:], m.RequestedTokenType)
	}
	if len(m.SubjectToken) > 0 {
		dAtA[i] = 0x2a
		i++
		i = encodeVarintCertificateservice(dAtA, i, uint64(len(m.SubjectToken)))
		i += copy(dAtA[i:], m.SubjectToken)
	}
	if len(m.SubjectTokenType) > 0 {
		dAtA[i] = 0x32
		i++
		i = encodeVarintCertificateservice(dAtA, i, uint64(len(m.SubjectTokenType)))
		i += copy(dAtA[i:], m.SubjectTokenType)
	}
	return i, nil
}

func (m *GetFederatedTokenResponse) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *GetFederatedTokenResponse) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if len(m.AccessToken) > 0 {
		dAtA[i] = 0xa
		i++
		i = encodeVarintCertificateservice(dAtA, i, uint64(len(m.AccessToken)))
		i += copy(dAtA[i:], m.AccessToken)
	}
	if len(m.IssuedTokenType) > 0 {
		dAtA[i] = 0x12
		i++
		i = encodeVarintCertificateservice(dAtA, i, uint64(len(m.IssuedTokenType)))
		i += copy(dAtA[i:], m.IssuedTokenType)
	}
	if len(m.TokenType) > 0 {
		dAtA[i] = 0x1a
		i++
		i = encodeVarintCertificateservice(dAtA, i, uint64(len(m.TokenType)))
		i += copy(dAtA[i:], m.TokenType)
	}
	if m.ExpiresIn != 0 {
		dAtA[i] = 0x20
		i++
		i = encodeVarintCertificateservice(dAtA, i, uint64(m.ExpiresIn))
	}
	return i, nil
}

func (m *OAuth2Error) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *OAuth2Error) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if len(m.Error) > 0 {
		dAtA[i] = 0xa
		i++
		i = encodeVarintCertificateservice(dAtA, i, uint64(len(m.Error)))
		i += copy(dAtA[i:], m.Error)
	}
	if len(m.ErrorDescription) > 0 {
		dAtA[i] = 0x12
		i++
		i = encodeVarintCertificateservice(dAtA, i, uint64(len(m.ErrorDescription)))
		i += copy(dAtA[i:], m.ErrorDescription)
	}
	return i, nil
}

func encodeVarintCertificateservice(dAtA []byte, offset int, v uint64) int {
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return offset + 1
}
func (m *GetFederatedTokenRequest) Size() (n int) {
	var l int
	_ = l
	l = len(m.GrantType)
	if l > 0 {
		n += 1 + l + sovCertificateservice(uint64(l))
	}
	l = len(m.Audience)
	if l > 0 {
		n += 1 + l + sovCertificateservice(uint64(l))
	}
	if len(m.Scope) > 0 {
		for _, s := range m.Scope {
			l = len(s)
			n += 1 + l + sovCertificateservice(uint64(l))
		}
	}
	l = len(m.RequestedTokenType)
	if l > 0 {
		n += 1 + l + sovCertificateservice(uint64(l))
	}
	l = len(m.SubjectToken)
	if l > 0 {
		n += 1 + l + sovCertificateservice(uint64(l))
	}
	l = len(m.SubjectTokenType)
	if l > 0 {
		n += 1 + l + sovCertificateservice(uint64(l))
	}
	return n
}

func (m *GetFederatedTokenResponse) Size() (n int) {
	var l int
	_ = l
	l = len(m.AccessToken)
	if l > 0 {
		n += 1 + l + sovCertificateservice(uint64(l))
	}
	l = len(m.IssuedTokenType)
	if l > 0 {
		n += 1 + l + sovCertificateservice(uint64(l))
	}
	l = len(m.TokenType)
	if l > 0 {
		n += 1 + l + sovCertificateservice(uint64(l))
	}
	if m.ExpiresIn != 0 {
		n += 1 + sovCertificateservice(uint64(m.ExpiresIn))
	}
	return n
}

func (m *OAuth2Error) Size() (n int) {
	var l int
	_ = l
	l = len(m.Error)
	if l > 0 {
		n += 1 + l + sovCertificateservice(uint64(l))
	}
	l = len(m.ErrorDescription)
	if l > 0 {
		n += 1 + l + sovCertificateservice(uint64(l))
	}
	return n
}

func sovCertificateservice(x uint64) (n int) {
	for {
		n++
		x >>= 7
		if x == 0 {
			break
		}
	}
	return n
}
func sozCertificateservice(x uint64) (n int) {
	return sovCertificateservice(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (this *GetFederatedTokenRequest) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&GetFederatedTokenRequest{`,
		`GrantType:` + fmt.Sprintf("%v", this.GrantType) + `,`,
		`Audience:` + fmt.Sprintf("%v", this.Audience) + `,`,
		`Scope:` + fmt.Sprintf("%v", this.Scope) + `,`,
		`RequestedTokenType:` + fmt.Sprintf("%v", this.RequestedTokenType) + `,`,
		`SubjectToken:` + fmt.Sprintf("%v", this.SubjectToken) + `,`,
		`SubjectTokenType:` + fmt.Sprintf("%v", this.SubjectTokenType) + `,`,
		`}`,
	}, "")
	return s
}
func (this *GetFederatedTokenResponse) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&GetFederatedTokenResponse{`,
		`AccessToken:` + fmt.Sprintf("%v", this.AccessToken) + `,`,
		`IssuedTokenType:` + fmt.Sprintf("%v", this.IssuedTokenType) + `,`,
		`TokenType:` + fmt.Sprintf("%v", this.TokenType) + `,`,
		`ExpiresIn:` + fmt.Sprintf("%v", this.ExpiresIn) + `,`,
		`}`,
	}, "")
	return s
}
func (this *OAuth2Error) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&OAuth2Error{`,
		`Error:` + fmt.Sprintf("%v", this.Error) + `,`,
		`ErrorDescription:` + fmt.Sprintf("%v", this.ErrorDescription) + `,`,
		`}`,
	}, "")
	return s
}
func valueToStringCertificateservice(v interface{}) string {
	rv := reflect.ValueOf(v)
	if rv.IsNil() {
		return "nil"
	}
	pv := reflect.Indirect(rv).Interface()
	return fmt.Sprintf("*%v", pv)
}
func (m *GetFederatedTokenRequest) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowCertificateservice
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: GetFederatedTokenRequest: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: GetFederatedTokenRequest: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field GrantType", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowCertificateservice
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthCertificateservice
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.GrantType = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Audience", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowCertificateservice
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthCertificateservice
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Audience = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Scope", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowCertificateservice
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthCertificateservice
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Scope = append(m.Scope, string(dAtA[iNdEx:postIndex]))
			iNdEx = postIndex
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field RequestedTokenType", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowCertificateservice
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthCertificateservice
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.RequestedTokenType = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 5:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field SubjectToken", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowCertificateservice
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthCertificateservice
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.SubjectToken = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 6:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field SubjectTokenType", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowCertificateservice
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthCertificateservice
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.SubjectTokenType = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipCertificateservice(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthCertificateservice
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *GetFederatedTokenResponse) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowCertificateservice
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: GetFederatedTokenResponse: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: GetFederatedTokenResponse: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field AccessToken", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowCertificateservice
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthCertificateservice
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.AccessToken = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field IssuedTokenType", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowCertificateservice
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthCertificateservice
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.IssuedTokenType = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field TokenType", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowCertificateservice
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthCertificateservice
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.TokenType = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 4:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field ExpiresIn", wireType)
			}
			m.ExpiresIn = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowCertificateservice
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.ExpiresIn |= (int64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		default:
			iNdEx = preIndex
			skippy, err := skipCertificateservice(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthCertificateservice
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *OAuth2Error) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowCertificateservice
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: OAuth2Error: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: OAuth2Error: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Error", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowCertificateservice
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthCertificateservice
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Error = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ErrorDescription", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowCertificateservice
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthCertificateservice
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.ErrorDescription = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipCertificateservice(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthCertificateservice
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipCertificateservice(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowCertificateservice
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowCertificateservice
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
			return iNdEx, nil
		case 1:
			iNdEx += 8
			return iNdEx, nil
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowCertificateservice
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			iNdEx += length
			if length < 0 {
				return 0, ErrInvalidLengthCertificateservice
			}
			return iNdEx, nil
		case 3:
			for {
				var innerWire uint64
				var start int = iNdEx
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return 0, ErrIntOverflowCertificateservice
					}
					if iNdEx >= l {
						return 0, io.ErrUnexpectedEOF
					}
					b := dAtA[iNdEx]
					iNdEx++
					innerWire |= (uint64(b) & 0x7F) << shift
					if b < 0x80 {
						break
					}
				}
				innerWireType := int(innerWire & 0x7)
				if innerWireType == 4 {
					break
				}
				next, err := skipCertificateservice(dAtA[start:])
				if err != nil {
					return 0, err
				}
				iNdEx = start + next
			}
			return iNdEx, nil
		case 4:
			return iNdEx, nil
		case 5:
			iNdEx += 4
			return iNdEx, nil
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
	}
	panic("unreachable")
}

var (
	ErrInvalidLengthCertificateservice = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowCertificateservice   = fmt.Errorf("proto: integer overflow")
)

func init() {
	proto.RegisterFile("security/proto/providers/google/iam/certificateservice.proto", fileDescriptorCertificateservice)
}

var fileDescriptorCertificateservice = []byte{
	// 503 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x74, 0x92, 0x3d, 0x6f, 0x13, 0x4d,
	0x10, 0xc7, 0xbd, 0xf1, 0x93, 0xe8, 0xc9, 0x12, 0x24, 0xb2, 0x72, 0x71, 0xb6, 0xc8, 0x2a, 0xba,
	0x34, 0x11, 0x8a, 0xee, 0x48, 0xd2, 0x21, 0x1a, 0x82, 0x78, 0xe9, 0x10, 0x26, 0xbd, 0xb5, 0xde,
	0x1b, 0x9c, 0x85, 0x64, 0x77, 0xd9, 0x9d, 0xb3, 0xb8, 0x0e, 0xc1, 0x17, 0x40, 0xa2, 0xe3, 0x13,
	0xd0, 0xf0, 0x3d, 0x28, 0x23, 0xd1, 0x50, 0xe2, 0x83, 0x82, 0xd2, 0x25, 0x25, 0xba, 0x5d, 0x27,
	0xd8, 0x32, 0x69, 0x4e, 0x3b, 0xf3, 0xff, 0xcd, 0xeb, 0x0d, 0xbd, 0xeb, 0x41, 0x96, 0x4e, 0x61,
	0x95, 0x5b, 0x67, 0xd0, 0x34, 0xdf, 0xb1, 0x2a, 0xc0, 0xf9, 0x7c, 0x64, 0xcc, 0xe8, 0x14, 0x72,
	0x25, 0xce, 0x72, 0x09, 0x0e, 0xd5, 0x73, 0x25, 0x05, 0x82, 0x07, 0x37, 0x56, 0x12, 0xb2, 0x40,
	0xb3, 0x6e, 0x84, 0x32, 0x25, 0xce, 0x32, 0xe9, 0xa0, 0x00, 0x8d, 0x4a, 0x9c, 0xfa, 0x6c, 0xbc,
	0xdf, 0xbb, 0x39, 0x8b, 0x17, 0x56, 0xe5, 0x42, 0x6b, 0x83, 0x02, 0x95, 0xd1, 0x3e, 0x06, 0xf6,
	0xba, 0x73, 0xea, 0x09, 0xa2, 0x1d, 0x9a, 0xa2, 0x8a, 0x52, 0x3a, 0x25, 0x34, 0x79, 0x04, 0xf8,
	0x10, 0x0a, 0x70, 0x02, 0xa1, 0x38, 0x36, 0x2f, 0x41, 0xf7, 0xe1, 0x55, 0x09, 0x1e, 0xd9, 0x16,
	0xa5, 0x23, 0x27, 0x34, 0x0e, 0xb0, 0xb2, 0x90, 0x90, 0x6d, 0xb2, 0xbb, 0xde, 0x5f, 0x0f, 0x9e,
	0xe3, 0xca, 0x02, 0xeb, 0xd1, 0xff, 0x45, 0x59, 0x28, 0xd0, 0x12, 0x92, 0x95, 0x20, 0x5e, 0xda,
	0xac, 0x43, 0x57, 0xbd, 0x34, 0x16, 0x92, 0xf6, 0x76, 0x7b, 0x77, 0xbd, 0x1f, 0x0d, 0x76, 0x9b,
	0x76, 0x5c, 0xcc, 0x0d, 0xc5, 0x00, 0x9b, 0x52, 0x31, 0xf5, 0x7f, 0x21, 0x9a, 0x5d, 0x6a, 0xa1,
	0x8b, 0x50, 0x63, 0x87, 0x5e, 0xf7, 0xe5, 0xf0, 0x05, 0x48, 0x8c, 0x7c, 0xb2, 0x1a, 0xd0, 0x8d,
	0x99, 0x33, 0x80, 0x6c, 0x8f, 0xb2, 0x05, 0x28, 0x26, 0x5d, 0x0b, 0xe4, 0x8d, 0x79, 0xb2, 0x49,
	0x99, 0x7e, 0x26, 0xb4, 0xfb, 0x8f, 0x91, 0xbd, 0x35, 0xda, 0x03, 0x4b, 0xe9, 0x86, 0x90, 0x12,
	0xbc, 0x9f, 0xd5, 0x8b, 0x53, 0x2f, 0xf8, 0xd8, 0x1e, 0xdd, 0x54, 0xde, 0x97, 0x8b, 0x33, 0xc4,
	0x0d, 0x2c, 0x0b, 0x8c, 0x53, 0x3a, 0x87, 0xb5, 0x03, 0x46, 0x17, 0x75, 0x78, 0x6d, 0x95, 0x03,
	0x3f, 0x50, 0x3a, 0xac, 0xa2, 0xdd, 0x9f, 0xf3, 0xa4, 0x4f, 0xe9, 0xb5, 0x27, 0xf7, 0x4a, 0x3c,
	0x39, 0x78, 0xe0, 0x9c, 0x71, 0xcd, 0x66, 0xa1, 0x79, 0xcc, 0x3a, 0x8b, 0x46, 0xd3, 0x52, 0x78,
	0x0c, 0x0a, 0xf0, 0xd2, 0x29, 0xdb, 0xfc, 0xfe, 0x8b, 0x96, 0x96, 0x84, 0x83, 0x8f, 0x84, 0xb2,
	0xfb, 0x7f, 0xcf, 0xec, 0x59, 0x3c, 0x33, 0xf6, 0x8e, 0xd0, 0xcd, 0xa5, 0xcd, 0xb0, 0xc3, 0xec,
	0xca, 0xbb, 0xcb, 0xae, 0x3a, 0x9d, 0x5e, 0xe7, 0x22, 0x48, 0x58, 0x95, 0x3d, 0x46, 0xb4, 0x47,
	0xa6, 0xa8, 0xd2, 0x9d, 0xb7, 0x5f, 0x7f, 0x7e, 0x58, 0xd9, 0x4a, 0x93, 0x7c, 0xbc, 0x9f, 0xab,
	0x90, 0x08, 0xab, 0xa1, 0xd2, 0x85, 0xd2, 0xa3, 0xb0, 0x91, 0x3b, 0xe4, 0xd6, 0x51, 0x7e, 0x3e,
	0xe1, 0xad, 0x6f, 0x13, 0xde, 0x9a, 0x4e, 0x38, 0x79, 0x53, 0x73, 0xf2, 0xa9, 0xe6, 0xe4, 0x4b,
	0xcd, 0xc9, 0x79, 0xcd, 0xc9, 0xf7, 0x9a, 0x93, 0x5f, 0x35, 0x6f, 0x4d, 0x6b, 0x4e, 0xde, 0xff,
	0xe0, 0xad, 0xdf, 0x84, 0x0c, 0xd7, 0xc2, 0x29, 0x1f, 0xfe, 0x09, 0x00, 0x00, 0xff, 0xff, 0x45,
	0x6c, 0x19, 0x50, 0x5e, 0x03, 0x00, 0x00,
}
