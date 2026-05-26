package ethawskmssigner_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const localKMSImage = "nsmithuk/local-kms:3"

// startLocalKMS spins up an `nsmithuk/local-kms` container, creates a
// fresh secp256k1 SIGN_VERIFY key in it, and returns a kms.Client
// pointed at the container plus the key ID. The container is torn
// down via t.Cleanup.
//
// Tests are skipped (not failed) when Docker is unavailable so the
// non-container unit tests still pass on machines without Docker.
func startLocalKMS(t *testing.T) (*kms.Client, string) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping container-based test in -short mode")
	}

	ctx := context.Background()
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        localKMSImage,
			ExposedPorts: []string{"8080/tcp"},
			WaitingFor:   wait.ForListeningPort("8080/tcp").WithStartupTimeout(60 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		t.Skipf("local-kms container unavailable (is Docker running?): %v", err)
	}
	t.Cleanup(func() {
		_ = container.Terminate(context.Background())
	})

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("container host: %v", err)
	}
	port, err := container.MappedPort(ctx, "8080")
	if err != nil {
		t.Fatalf("container mapped port: %v", err)
	}
	endpoint := fmt.Sprintf("http://%s:%s", host, port.Port())

	client := kms.New(kms.Options{
		Credentials:  credentials.NewStaticCredentialsProvider("test", "test", ""),
		Region:       "us-east-1",
		BaseEndpoint: aws.String(endpoint),
	})

	out, err := client.CreateKey(ctx, &kms.CreateKeyInput{
		KeySpec:  kmstypes.KeySpecEccSecgP256k1,
		KeyUsage: kmstypes.KeyUsageTypeSignVerify,
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	return client, aws.ToString(out.KeyMetadata.KeyId)
}
