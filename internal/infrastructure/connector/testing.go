//go:build integration
// +build integration

package connector

// TestCloudProvider is the default cloud provider for tests
const TestCloudProvider = "azure"

// TestConnectionString is a test connection string
const TestConnectionString = "DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;BlobEndpoint=http://127.0.0.1:10000/devstoreaccount1;"

// TestContainerName is the default test container name
const TestContainerName = "test-container"
