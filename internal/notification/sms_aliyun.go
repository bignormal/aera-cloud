package notification

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	dysmsapi "github.com/alibabacloud-go/dysmsapi-20170525/v5/client"
	"github.com/alibabacloud-go/tea/dara"
	"github.com/bignormal/aera-cloud/internal/verification"
)

const (
	defaultAliyunSMSRegion   = "cn-hangzhou"
	defaultAliyunSMSEndpoint = "dysmsapi.aliyuncs.com"
)

var (
	aliyunSMSRegionPattern    = regexp.MustCompile(`^[a-z0-9-]{3,64}$`)
	aliyunSMSTemplatePattern  = regexp.MustCompile(`^SMS_[0-9]{6,32}$`)
	aliyunSMSCodePattern      = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
	aliyunSMSRequestIDPattern = regexp.MustCompile(
		`^[A-Za-z0-9._-]{8,128}$`,
	)
)

type AliyunSMSConfig struct {
	AccessKeyID     string
	AccessKeySecret string
	RegionID        string
	SignName        string
	TemplateCode    string
	Client          aliyunSMSClient
}

type aliyunSMSClient interface {
	SendSmsWithContext(
		ctx context.Context,
		request *dysmsapi.SendSmsRequest,
		runtime *dara.RuntimeOptions,
	) (*dysmsapi.SendSmsResponse, error)
}

type AliyunSMS struct {
	client       aliyunSMSClient
	signName     string
	templateCode string
}

type aliyunSMSDeliveryFailure struct {
	code        string
	requestID   string
	rateLimited bool
}

func (e *aliyunSMSDeliveryFailure) Error() string {
	return "Aliyun SMS provider is unavailable"
}

func (e *aliyunSMSDeliveryFailure) VerificationDeliveryFailure() verification.DeliveryFailureMetadata {
	return verification.DeliveryFailureMetadata{
		Provider:    "aliyun",
		Code:        e.code,
		RequestID:   e.requestID,
		RateLimited: e.rateLimited,
	}
}

func NewAliyunSMS(config AliyunSMSConfig) (*AliyunSMS, error) {
	accessKeyID := strings.TrimSpace(config.AccessKeyID)
	accessKeySecret := strings.TrimSpace(config.AccessKeySecret)
	signName := strings.TrimSpace(config.SignName)
	templateCode := strings.TrimSpace(config.TemplateCode)
	regionID := strings.TrimSpace(config.RegionID)
	if regionID == "" {
		regionID = defaultAliyunSMSRegion
	}
	if accessKeyID == "" || accessKeySecret == "" ||
		accessKeyID != config.AccessKeyID || accessKeySecret != config.AccessKeySecret ||
		strings.ContainsAny(accessKeyID, "\r\n") || strings.ContainsAny(accessKeySecret, "\r\n") {
		return nil, errors.New("Aliyun SMS credentials are invalid")
	}
	if signName == "" || signName != config.SignName || strings.ContainsAny(signName, "\r\n") {
		return nil, errors.New("Aliyun SMS signature is invalid")
	}
	if !aliyunSMSTemplatePattern.MatchString(templateCode) {
		return nil, errors.New("Aliyun SMS template code is invalid")
	}
	if !aliyunSMSRegionPattern.MatchString(regionID) {
		return nil, errors.New("Aliyun SMS region is invalid")
	}

	smsClient := config.Client
	if smsClient == nil {
		clientConfig := &openapi.Config{
			AccessKeyId:     dara.String(accessKeyID),
			AccessKeySecret: dara.String(accessKeySecret),
			RegionId:        dara.String(regionID),
			Endpoint:        dara.String(defaultAliyunSMSEndpoint),
		}
		var err error
		smsClient, err = dysmsapi.NewClient(clientConfig)
		if err != nil {
			return nil, errors.New("Aliyun SMS client could not be initialized")
		}
	}
	return &AliyunSMS{
		client:       smsClient,
		signName:     signName,
		templateCode: templateCode,
	}, nil
}

func (s *AliyunSMS) SendVerification(
	ctx context.Context,
	destination string,
	code string,
	purpose verification.Purpose,
) error {
	if s == nil || s.client == nil || !validMainlandDestination(destination) ||
		!validVerificationCode(code) || !validPurpose(purpose) {
		return errors.New("Aliyun SMS verification delivery request is invalid")
	}
	templateParam, err := json.Marshal(map[string]string{"code": code})
	if err != nil {
		return errors.New("Aliyun SMS verification request could not be prepared")
	}
	request := &dysmsapi.SendSmsRequest{
		PhoneNumbers:  dara.String(strings.TrimPrefix(destination, "+86")),
		SignName:      dara.String(s.signName),
		TemplateCode:  dara.String(s.templateCode),
		TemplateParam: dara.String(string(templateParam)),
	}
	response, err := s.client.SendSmsWithContext(ctx, request, &dara.RuntimeOptions{
		ConnectTimeout: dara.Int(3000),
		ReadTimeout:    dara.Int(5000),
		Autoretry:      dara.Bool(false),
	})
	if err != nil {
		return &aliyunSMSDeliveryFailure{code: "transport_error"}
	}
	if response == nil || response.Body == nil {
		return &aliyunSMSDeliveryFailure{code: "invalid_response"}
	}
	if providerCode := dara.StringValue(response.Body.Code); providerCode != "OK" {
		code := sanitizeAliyunSMSCode(providerCode)
		return &aliyunSMSDeliveryFailure{
			code:        code,
			requestID:   maskAliyunSMSRequestID(dara.StringValue(response.Body.RequestId)),
			rateLimited: isAliyunSMSRateLimitCode(code),
		}
	}
	return nil
}

func sanitizeAliyunSMSCode(value string) string {
	if !aliyunSMSCodePattern.MatchString(value) {
		return "unknown_provider_error"
	}
	return value
}

func maskAliyunSMSRequestID(value string) string {
	if !aliyunSMSRequestIDPattern.MatchString(value) {
		return ""
	}
	if len(value) <= 12 {
		return value[:2] + "..." + value[len(value)-2:]
	}
	return value[:6] + "..." + value[len(value)-4:]
}

func isAliyunSMSRateLimitCode(value string) bool {
	switch value {
	case "isv.BUSINESS_LIMIT_CONTROL", "isv.DAY_LIMIT_CONTROL", "isv.SMS_LIMIT_CONTROL":
		return true
	default:
		return false
	}
}
