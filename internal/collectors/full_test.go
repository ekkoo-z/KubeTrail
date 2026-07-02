package collectors

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCloudMetadataEndpointsIncludeTencentAndHuawei(t *testing.T) {
	endpoints := cloudMetadataEndpoints()
	seen := map[string]cloudMetadataEndpoint{}
	for _, endpoint := range endpoints {
		seen[endpoint.Provider] = endpoint
	}

	for _, provider := range []string{"tencent", "tencent_cam_role_list", "huawei_openstack", "huawei_security_key", "huawei_ec2_compatible", "huawei_openstack_v2"} {
		if _, ok := seen[provider]; !ok {
			t.Fatalf("missing metadata endpoint %q in %#v", provider, endpoints)
		}
	}
	if seen["tencent"].URL != "http://metadata.tencentyun.com/latest/meta-data/" {
		t.Fatalf("unexpected tencent metadata URL: %s", seen["tencent"].URL)
	}
	if seen["huawei_openstack"].URL != "http://169.254.169.254/openstack/latest/meta_data.json" {
		t.Fatalf("unexpected huawei metadata URL: %s", seen["huawei_openstack"].URL)
	}
	if seen["huawei_security_key"].URL != "http://169.254.169.254/openstack/latest/securitykey" {
		t.Fatalf("unexpected huawei security key URL: %s", seen["huawei_security_key"].URL)
	}
	if seen["huawei_openstack_v2"].TokenURL != "http://169.254.169.254/meta-data/latest/api/token" {
		t.Fatalf("unexpected huawei token URL: %s", seen["huawei_openstack_v2"].TokenURL)
	}
}

func TestRequestCloudMetadataTokenDoesNotReturnTokenInInfo(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Fatalf("unexpected method: %s", r.Method)
		}
		if r.Header.Get("X-Metadata-Token-Ttl-Seconds") == "" {
			t.Fatal("missing token ttl header")
		}
		_, _ = w.Write([]byte("secret-metadata-token"))
	}))
	defer server.Close()

	client := &http.Client{Timeout: time.Second}
	token, info, err := requestCloudMetadataToken(context.Background(), client, server.URL)
	if err != nil {
		t.Fatalf("requestCloudMetadataToken failed: %v", err)
	}
	if token != "secret-metadata-token" {
		t.Fatalf("unexpected token: %q", token)
	}
	for key, value := range info {
		if value == "secret-metadata-token" {
			t.Fatalf("token leaked in info[%s]", key)
		}
	}
	if info["sha256"] == "" {
		t.Fatalf("expected token hash metadata, got %#v", info)
	}
}
