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
	aliyunSMSRegionPattern   = regexp.MustCompile(`^[a-z0-9-]{3,64}$`)
	aliyunSMSTemplatePattern = regexp.MustCompile(`^SMS_[0-9]{6,32}$`)
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
	if err != nil || response == nil || response.Body == nil ||
		dara.StringValue(response.Body.Code) != "OK" {
		return errors.New("Aliyun SMS provider is unavailable")
	}
	return nil
}
