package notification

import (
	"context"
	"errors"
	"strings"
	"testing"

	dysmsapi "github.com/alibabacloud-go/dysmsapi-20170525/v5/client"
	"github.com/alibabacloud-go/tea/dara"
	"github.com/bignormal/aera-cloud/internal/verification"
)

func TestAliyunSMSSendsApprovedSignatureAndTemplate(t *testing.T) {
	client := &recordingAliyunSMSClient{
		response: &dysmsapi.SendSmsResponse{
			Body: &dysmsapi.SendSmsResponseBody{
				Code:      dara.String("OK"),
				Message:   dara.String("OK"),
				RequestId: dara.String("request-id"),
				BizId:     dara.String("biz-id"),
			},
		},
	}
	provider, err := NewAliyunSMS(AliyunSMSConfig{
		AccessKeyID:     "test-access-key-id",
		AccessKeySecret: "test-access-key-secret",
		RegionID:        "cn-hangzhou",
		SignName:        "郑州雾棠",
		TemplateCode:    "SMS_511000030",
		Client:          client,
	})
	if err != nil {
		t.Fatalf("NewAliyunSMS() error = %v", err)
	}
	if err := provider.SendVerification(
		context.Background(),
		"+8613800138000",
		"123456",
		verification.PurposeLogin,
	); err != nil {
		t.Fatalf("SendVerification() error = %v", err)
	}
	if client.request == nil {
		t.Fatal("SendSmsWithContext() was not called")
	}
	if got := dara.StringValue(client.request.PhoneNumbers); got != "13800138000" {
		t.Fatalf("PhoneNumbers = %q", got)
	}
	if got := dara.StringValue(client.request.SignName); got != "郑州雾棠" {
		t.Fatalf("SignName = %q", got)
	}
	if got := dara.StringValue(client.request.TemplateCode); got != "SMS_511000030" {
		t.Fatalf("TemplateCode = %q", got)
	}
	if got := dara.StringValue(client.request.TemplateParam); got != `{"code":"123456"}` {
		t.Fatalf("TemplateParam = %q", got)
	}
	if client.runtime == nil ||
		dara.IntValue(client.runtime.ConnectTimeout) != 3000 ||
		dara.IntValue(client.runtime.ReadTimeout) != 5000 ||
		dara.BoolValue(client.runtime.Autoretry) {
		t.Fatalf("RuntimeOptions = %+v", client.runtime)
	}
}

func TestAliyunSMSSanitizesProviderFailures(t *testing.T) {
	client := &recordingAliyunSMSClient{
		response: &dysmsapi.SendSmsResponse{
			Body: &dysmsapi.SendSmsResponseBody{
				Code:    dara.String("isv.SMS_SIGNATURE_SCENE_ILLEGAL"),
				Message: dara.String("provider-secret internal detail"),
			},
		},
	}
	provider, err := NewAliyunSMS(AliyunSMSConfig{
		AccessKeyID:     "test-access-key-id",
		AccessKeySecret: "test-access-key-secret",
		SignName:        "郑州雾棠",
		TemplateCode:    "SMS_511000030",
		Client:          client,
	})
	if err != nil {
		t.Fatalf("NewAliyunSMS() error = %v", err)
	}
	err = provider.SendVerification(
		context.Background(),
		"+8613800138000",
		"654321",
		verification.PurposeRegistration,
	)
	if err == nil {
		t.Fatal("SendVerification() accepted a failed Aliyun response")
	}
	for _, secret := range []string{
		"test-access-key-id",
		"test-access-key-secret",
		"provider-secret",
		"654321",
		"13800138000",
	} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("SendVerification() error contains sensitive value %q: %v", secret, err)
		}
	}

	client.response = nil
	client.err = errors.New("transport contained test-access-key-secret")
	if err := provider.SendVerification(
		context.Background(),
		"+8613800138000",
		"123456",
		verification.PurposeLogin,
	); err == nil || strings.Contains(err.Error(), "test-access-key-secret") {
		t.Fatalf("transport failure was not sanitized: %v", err)
	}
}

func TestAliyunSMSRejectsInvalidConfigurationAndDelivery(t *testing.T) {
	config := AliyunSMSConfig{
		AccessKeyID:     "test-access-key-id",
		AccessKeySecret: "test-access-key-secret",
		SignName:        "郑州雾棠",
		TemplateCode:    "SMS_511000030",
		Client:          &recordingAliyunSMSClient{},
	}
	tests := []struct {
		name   string
		mutate func(*AliyunSMSConfig)
	}{
		{name: "access key", mutate: func(value *AliyunSMSConfig) { value.AccessKeyID = "" }},
		{name: "secret", mutate: func(value *AliyunSMSConfig) { value.AccessKeySecret = "" }},
		{name: "signature", mutate: func(value *AliyunSMSConfig) { value.SignName = "郑州雾棠\n" }},
		{name: "template", mutate: func(value *AliyunSMSConfig) { value.TemplateCode = "invalid" }},
		{name: "region", mutate: func(value *AliyunSMSConfig) { value.RegionID = "cn hangzhou" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := config
			test.mutate(&candidate)
			if _, err := NewAliyunSMS(candidate); err == nil {
				t.Fatal("NewAliyunSMS() accepted invalid configuration")
			}
		})
	}

	provider, err := NewAliyunSMS(config)
	if err != nil {
		t.Fatalf("NewAliyunSMS() error = %v", err)
	}
	if err := provider.SendVerification(
		context.Background(),
		"13800138000",
		"123456",
		verification.PurposeLogin,
	); err == nil {
		t.Fatal("SendVerification() accepted a non-canonical phone")
	}
}

type recordingAliyunSMSClient struct {
	request  *dysmsapi.SendSmsRequest
	runtime  *dara.RuntimeOptions
	response *dysmsapi.SendSmsResponse
	err      error
}

func (c *recordingAliyunSMSClient) SendSmsWithContext(
	_ context.Context,
	request *dysmsapi.SendSmsRequest,
	runtime *dara.RuntimeOptions,
) (*dysmsapi.SendSmsResponse, error) {
	c.request = request
	c.runtime = runtime
	return c.response, c.err
}
