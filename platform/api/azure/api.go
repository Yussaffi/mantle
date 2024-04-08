// Copyright 2016 CoreOS, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package azure

import (
	"context"
	"fmt"
	"math/rand"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v5"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v5"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/service"
	"github.com/coreos/pkg/capnslog"

	internalAuth "github.com/flatcar/mantle/auth"
)

var (
	plog = capnslog.NewPackageLogger("github.com/flatcar/mantle", "platform/api/azure")
)

type API struct {
	rgClient    *armresources.ResourceGroupsClient
	depClient   *armresources.DeploymentsClient
	imgClient   *armcompute.ImagesClient
	compClient  *armcompute.VirtualMachinesClient
	vmImgClient *armcompute.VirtualMachineImagesClient
	netClient   *armnetwork.VirtualNetworksClient
	subClient   *armnetwork.SubnetsClient
	ipClient    *armnetwork.PublicIPAddressesClient
	intClient   *armnetwork.InterfacesClient
	accClient   *armstorage.AccountsClient
	Opts        *Options
}

type Network struct {
	subnet armnetwork.Subnet
}

// New creates a new Azure client. If no publish settings file is provided or
// can't be parsed, an anonymous client is created.
func New(opts *Options) (*API, error) {
	var err error

	if opts.StorageEndpointSuffix == "" {
		opts.StorageEndpointSuffix = "core.windows.net"
	}

	if !opts.UseIdentity {
		err = setOptsFromProfile(opts)
		if err != nil {
			return nil, fmt.Errorf("failed to get options from azure profile: %w", err)
		}
	} else {
		subid, err := msiGetSubscriptionID()
		if err != nil {
			return nil, fmt.Errorf("failed to query subscription id: %w", err)
		}
		opts.SubscriptionID = subid
	}

	if opts.AvailabilitySet != "" && opts.ResourceGroup == "" {
		return nil, fmt.Errorf("ResourceGroup must match AvailabilitySet")
	}

	api := &API{
		Opts: opts,
	}

	err = api.resolveImage()
	if err != nil {
		return nil, fmt.Errorf("failed to resolve image: %v", err)
	}

	return api, nil
}

func setOptsFromProfile(opts *Options) error {
	profiles, err := internalAuth.ReadAzureProfile(opts.AzureProfile)
	if err != nil {
		return fmt.Errorf("couldn't read Azure profile: %v", err)
	}
	creds, err := internalAuth.ReadAzureCredentials(opts.AzureAuthLocation)
	if err != nil {
		return fmt.Errorf("couldn't read Azure credentials: %v", err)
	}

	var subOpts *internalAuth.Options
	if opts.AzureSubscription == "" {
		subOpts = profiles.SubscriptionOptions(internalAuth.FilterByID(creds.SubscriptionID))
		if subOpts == nil {
			return fmt.Errorf("Azure subscription with ID %q taken from credentials file doesn't exist in %q", creds.SubscriptionID, opts.AzureProfile)
		}
	} else {
		subOpts = profiles.SubscriptionOptions(internalAuth.FilterByName(opts.AzureSubscription))
		if subOpts == nil {
			return fmt.Errorf("Azure subscription named %q doesn't exist in %q", opts.AzureSubscription, opts.AzureProfile)
		}
	}

	if opts.SubscriptionID == "" {
		opts.SubscriptionID = subOpts.SubscriptionID
	}

	if opts.SubscriptionName == "" {
		opts.SubscriptionName = subOpts.SubscriptionName
	}

	if opts.StorageEndpointSuffix == "" {
		opts.StorageEndpointSuffix = subOpts.StorageEndpointSuffix
	}

	return nil
}

func msiGetSubscriptionID() (string, error) {
	evn := "AZURE_SUBSCRIPTION_ID"
	subID := os.Getenv(evn)
	if subID != "" {
		return subID, nil
	}
	cred, err := azidentity.NewManagedIdentityCredential(nil)
	if err != nil {
		return "", err
	}
	// TODO: Possibly file some client option here if necessary
	client, err := armsubscriptions.NewClient(cred, nil)
	if err != nil {
		return "", err
	}
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(context.TODO())
		if err != nil {
			return "", err
		}
		for _, sub := range page.Value {
			// this should never happen
			if sub.SubscriptionID == nil {
				continue
			}
			if subID != "" {
				return "", fmt.Errorf("multiple subscriptions found; pass one explicitly using the %s environment variable", evn)
			}
			subID = *sub.SubscriptionID
		}
	}
	if subID == "" {
		return "", fmt.Errorf("no subscriptions found; pass one explicitly using the %s environment variable", evn)
	}
	plog.Infof("Using subscription %s", subID)
	return subID, nil
}

func (a *API) SetupClients() error {
	cred, err := a.newCredential()
	if err != nil {
		return err
	}
	subID := a.Opts.SubscriptionID

	// TODO: Should we specify options to use
	// ActiveDirectoryEndpointURL from azure credentials?
	var opts *arm.ClientOptions

	rcf, err := armresources.NewClientFactory(subID, cred, opts)
	if err != nil {
		return err
	}
	a.rgClient = rcf.NewResourceGroupsClient()
	a.depClient = rcf.NewDeploymentsClient()

	ccf, err := armcompute.NewClientFactory(subID, cred, opts)
	if err != nil {
		return err
	}
	a.imgClient = ccf.NewImagesClient()
	a.compClient = ccf.NewVirtualMachinesClient()
	a.vmImgClient = ccf.NewVirtualMachineImagesClient()

	ncf, err := armnetwork.NewClientFactory(subID, cred, opts)
	if err != nil {
		return err
	}
	a.netClient = ncf.NewVirtualNetworksClient()
	a.subClient = ncf.NewSubnetsClient()
	a.ipClient = ncf.NewPublicIPAddressesClient()
	a.intClient = ncf.NewInterfacesClient()

	scf, err := armstorage.NewClientFactory(subID, cred, opts)
	if err != nil {
		return err
	}
	a.accClient = scf.NewAccountsClient()

	return nil
}

func (a *API) GetBlobServiceClient(storageAccount string) (*service.Client, error) {
	accountURL := fmt.Sprintf("https://%s.blob.%s", url.PathEscape(storageAccount), url.PathEscape(a.Opts.StorageEndpointSuffix))
	if _, err := url.Parse(accountURL); err != nil {
		return nil, err
	}
	creds, err := a.newCredential()
	if err != nil {
		return nil, err
	}
	return service.NewClient(accountURL, creds, nil)
}

func (a *API) newCredential() (azcore.TokenCredential, error) {
	if !a.Opts.UseIdentity {
		creds, err := internalAuth.ReadAzureCredentials(a.Opts.AzureAuthLocation)
		if err != nil {
			return nil, fmt.Errorf("couldn't read Azure credentials: %v", err)
		}
		var opts *azidentity.ClientSecretCredentialOptions
		if creds.ActiveDirectoryEndpointURL != "" {
			opts = &azidentity.ClientSecretCredentialOptions{}
			opts.Cloud.ActiveDirectoryAuthorityHost = creds.ActiveDirectoryEndpointURL
		}
		cred, err := azidentity.NewClientSecretCredential(creds.TenantID, creds.ClientID, creds.ClientSecret, opts)
		if err != nil {
			return nil, err
		}
		return cred, nil
	}
	cred, err := azidentity.NewManagedIdentityCredential(nil)
	if err != nil {
		return nil, err
	}
	return cred, err
}

func randomNameEx(prefix, separator string) string {
	b := make([]byte, 5)
	rand.Read(b)
	return fmt.Sprintf("%s%s%x", prefix, separator, b)
}

func randomName(prefix string) string {
	return randomNameEx(prefix, "-")
}

func (a *API) GetOpts() *Options {
	return a.Opts
}

func (a *API) GC(gracePeriod time.Duration) error {
	durationAgo := time.Now().Add(-1 * gracePeriod)

	listGroups, err := a.ListResourceGroups("")
	if err != nil {
		return fmt.Errorf("listing resource groups: %v", err)
	}

	for _, l := range listGroups {
		if strings.HasPrefix(*l.Name, "kola-cluster") {
			createdAt := *l.Tags["createdAt"]
			timeCreated, err := time.Parse(time.RFC3339, createdAt)
			if err != nil {
				return fmt.Errorf("error parsing time: %v", err)
			}
			if !timeCreated.After(durationAgo) {
				if err = a.TerminateResourceGroup(*l.Name); err != nil {
					return err
				}
			}
		}
	}

	return nil
}
