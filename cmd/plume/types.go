// Copyright The Mantle Authors
// SPDX-License-Identifier: Apache-2.0

package main

type storageSpec struct {
	BaseURL        string
	BasePrivateURL string
	Title          string // Replace the bucket name in index page titles
	NamedPath      string // Copy to $BaseURL/$Board/$NamedPath
	VersionPath    bool   // Copy to $BaseURL/$Board/$Version
	DirectoryHTML  bool
	IndexHTML      bool
}

type gceSpec struct {
	Project     string   // GCE project name
	Family      string   // A group name, also used as name prefix
	Description string   // Human readable-ish description
	Licenses    []string // Identifiers for tracking usage
	Image       string   // File name of image source
	Publish     string   // Write published image name to given file
	Limit       int      // Limit on # of old images to keep
}

type azureEnvironmentSpec struct {
	SubscriptionName string // Name of subscription in Azure profile
}

type azureSpec struct {
	Offer          string                 // Azure offer name
	Image          string                 // File name of image source
	StorageAccount string                 // Storage account to use for image uploads in each environment
	ResourceGroup  string                 // Resource Group to use for blobs in each environment
	Container      string                 // Container to hold the disk image in each environment
	Environments   []azureEnvironmentSpec // Azure environments to upload to

	// Fields for azure.OSImage
	Label             string
	Description       string // Description of an image in this channel
	RecommendedVMSize string
	IconURI           string
	SmallIconURI      string
}

type awsPartitionSpec struct {
	Name              string   // Printable name for the partition
	Profile           string   // Authentication profile in ~/.aws
	Bucket            string   // S3 bucket for uploading image
	BucketRegion      string   // Region of the bucket
	LaunchPermissions []string // Other accounts to give launch permission
	Regions           []string // Regions to create the AMI in
}

type awsSpec struct {
	BaseName        string             // Prefix of image name
	BaseDescription string             // Prefix of image description
	Prefix          string             // Prefix for filenames of AMI lists
	Image           string             // File name of image source
	Partitions      []awsPartitionSpec // AWS partitions
}

type channelSpec struct {
	BaseURL        string // Copy from $BaseURL/$Board/$Version
	BasePrivateURL string
	Boards         []string
	Destinations   []storageSpec
	GCE            gceSpec
	Azure          azureSpec
	AzurePremium   azureSpec
	AWS            awsSpec
}

type ReleaseMetadata struct {
	Note     string          `json:"note"` // used to note to users not to consume the release metadata index
	Releases []BuildMetadata `json:"releases"`
	Metadata Metadata        `json:"metadata"`
	Stream   string          `json:"stream"`
}

type BuildMetadata struct {
	CommitHash []Commit `json:"commits"`
	Version    string   `json:"version"`
	Endpoint   string   `json:"metadata"`
}

type Metadata struct {
	LastModified string `json:"last-modified"`
}

type IndividualReleaseMetadata struct {
	Architectures map[string]Architecture `json:"architectures"`
}

type Architecture struct {
	Commit string           `json:"commit"`
	Media  map[string]Media `json:"media"`
}

type Media struct {
	Images map[string]AMI `json:"images"`
}

type AMI struct {
	Image string `json:"image"`
}

type Commit struct {
	Architecture string `json:"architecture"`
	Checksum     string `json:"checksum"`
}
