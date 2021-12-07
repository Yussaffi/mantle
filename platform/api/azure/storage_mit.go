// Copyright The Mantle Authors
// SPDX-License-Identifier: Apache-2.0

// Azure VHD Utilities for Go
package azure

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"time"

	"github.com/Azure/azure-sdk-for-go/storage"
	"github.com/Microsoft/azure-vhd-utils/upload"
	"github.com/Microsoft/azure-vhd-utils/upload/metadata"
	"github.com/Microsoft/azure-vhd-utils/vhdcore/common"
	"github.com/Microsoft/azure-vhd-utils/vhdcore/diskstream"
	"github.com/coreos/pkg/multierror"
)

const pageBlobPageSize int64 = 2 * 1024 * 1024

type BlobExistsError string

func (a *API) ListStorageContainers(storageaccount, storagekey, prefix string) (*storage.ContainerListResponse, error) {
	sc, err := storage.NewClient(storageaccount, storagekey, a.opts.StorageEndpointSuffix, storage.DefaultAPIVersion, true)
	if err != nil {
		return nil, err
	}

	bsc := sc.GetBlobService()

	return bsc.ListContainers(storage.ListContainersParameters{
		Prefix: prefix,
	})
}

func (a *API) TerminateStorageContainer(storageaccount, storagekey, name string) error {
	sc, err := storage.NewClient(storageaccount, storagekey, a.opts.StorageEndpointSuffix, storage.DefaultAPIVersion, true)
	if err != nil {
		return err
	}

	bsc := sc.GetBlobService()
	return bsc.GetContainerReference(name).Delete(nil)
}

func (be BlobExistsError) Error() string {
	return fmt.Sprintf("blob %q already exists", string(be))
}

func (a *API) BlobExists(storageaccount, storagekey, container, blob string) (bool, error) {
	sc, err := storage.NewClient(storageaccount, storagekey, a.opts.StorageEndpointSuffix, storage.DefaultAPIVersion, true)
	if err != nil {
		return false, err
	}

	bsc := sc.GetBlobService()
	cont := bsc.GetContainerReference(container)
	return cont.GetBlobReference(blob).Exists()
}

func (a *API) ListBlobs(storageaccount, storagekey, container string, params storage.ListBlobsParameters) ([]storage.Blob, error) {
	sc, err := storage.NewClient(storageaccount, storagekey, a.opts.StorageEndpointSuffix, storage.DefaultAPIVersion, true)
	if err != nil {
		return nil, fmt.Errorf("failed creating storage client: %v", err)
	}

	bsc := sc.GetBlobService()
	cont := bsc.GetContainerReference(container)

	resp, err := cont.ListBlobs(params)
	if err != nil {
		return nil, fmt.Errorf("failed listing blobs for %q: %v", container, err)
	}
	var res []storage.Blob
	for _, blob := range resp.Blobs {
		b := cont.GetBlobReference(blob.Name)
		err = b.GetMetadata(nil)
		if err != nil {
			return nil, fmt.Errorf("failed getting blog metadata for %q: %v", blob.Name, err)
		}
		blob.Metadata = b.Metadata
		res = append(res, blob)
	}
	return res, nil
}

func (a *API) GetBlob(storageaccount, storagekey, container, name string) (io.ReadCloser, error) {
	sc, err := storage.NewClient(storageaccount, storagekey, a.opts.StorageEndpointSuffix, storage.DefaultAPIVersion, true)
	if err != nil {
		return nil, err
	}

	bsc := sc.GetBlobService()
	cont := bsc.GetContainerReference(container)
	if _, err = cont.CreateIfNotExists(&storage.CreateContainerOptions{Access: storage.ContainerAccessTypePrivate}); err != nil {
		return nil, err
	}

	return cont.GetBlobReference(name).Get(nil)
}

// UploadBlob uploads vhd to the given storage account, container, and blob name.
//
// It returns BlobExistsError if the blob exists and overwrite is not true.
func (a *API) UploadBlob(storageaccount, storagekey, vhd, container, blob string, overwrite bool) error {
	ds, err := diskstream.CreateNewDiskStream(vhd)
	if err != nil {
		return err
	}
	defer ds.Close()

	sc, err := storage.NewClient(storageaccount, storagekey, a.opts.StorageEndpointSuffix, storage.DefaultAPIVersion, true)
	if err != nil {
		return err
	}

	bsc := sc.GetBlobService()
	cont := bsc.GetContainerReference(container)
	if _, err = cont.CreateIfNotExists(&storage.CreateContainerOptions{Access: storage.ContainerAccessTypePrivate}); err != nil {
		return err
	}

	blobExists, err := cont.GetBlobReference(blob).Exists()
	if err != nil {
		return err
	}

	resume := false
	var blobMetaData *metadata.MetaData
	if blobExists {
		if !overwrite {
			bm, err := getBlobMetaData(bsc, container, blob)
			if err != nil {
				return err
			}
			blobMetaData = bm
			resume = true
			plog.Printf("Blob with name '%s' already exists, checking if upload can be resumed", blob)
		}
	}

	localMetaData, err := getLocalVHDMetaData(vhd)
	if err != nil {
		return err
	}
	var rangesToSkip []*common.IndexRange
	if resume {
		if errs := metadata.CompareMetaData(blobMetaData, localMetaData); len(errs) != 0 {
			return multierror.Error(errs)
		}
		ranges, err := getAlreadyUploadedBlobRanges(bsc, container, blob)
		if err != nil {
			return err
		}
		rangesToSkip = ranges
	} else {
		if err := createBlob(bsc, container, blob, ds.GetSize(), localMetaData); err != nil {
			return err
		}
	}

	uploadableRanges, err := upload.LocateUploadableRanges(ds, rangesToSkip, pageBlobPageSize)
	if err != nil {
		return err
	}

	uploadableRanges, err = upload.DetectEmptyRanges(ds, uploadableRanges)
	if err != nil {
		return err
	}

	cxt := &upload.DiskUploadContext{
		VhdStream:             ds,
		UploadableRanges:      uploadableRanges,
		AlreadyProcessedBytes: common.TotalRangeLength(rangesToSkip),
		BlobServiceClient:     bsc,
		ContainerName:         container,
		BlobName:              blob,
		Parallelism:           8,
		Resume:                resume,
		MD5Hash:               localMetaData.FileMetaData.MD5Hash,
	}

	return upload.Upload(cxt)
}

// getBlobMetaData returns the custom metadata associated with a page blob which is set by createBlob method.
// The parameter client is the Azure blob service client, parameter containerName is the name of an existing container
// in which the page blob resides, parameter blobName is name for the page blob
// This method attempt to fetch the metadata only if MD5Hash is not set for the page blob, this method panic if the
// MD5Hash is already set or if the custom metadata is absent.
//
func getBlobMetaData(client storage.BlobStorageClient, containerName, blobName string) (*metadata.MetaData, error) {
	md5Hash, err := getBlobMD5Hash(client, containerName, blobName)
	if md5Hash != "" {
		return nil, BlobExistsError(blobName)
	}

	blobMetaData, err := metadata.NewMetadataFromBlob(client, containerName, blobName)
	if err != nil {
		return nil, err
	}

	if blobMetaData == nil {
		return nil, fmt.Errorf("There is no upload metadata associated with the existing blob '%s', so upload operation cannot be resumed, use --overwrite option.", blobName)
	}

	return blobMetaData, nil
}

// getLocalVHDMetaData returns the metadata of a local VHD
//
func getLocalVHDMetaData(localVHDPath string) (*metadata.MetaData, error) {
	localMetaData, err := metadata.NewMetaDataFromLocalVHD(localVHDPath)
	if err != nil {
		return nil, err
	}
	return localMetaData, nil
}

// createBlob creates a page blob of specific size and sets custom metadata
// The parameter client is the Azure blob service client, parameter containerName is the name of an existing container
// in which the page blob needs to be created, parameter blobName is name for the new page blob, size is the size of
// the new page blob in bytes and parameter vhdMetaData is the custom metadata to be associacted with the page blob
//
func createBlob(client storage.BlobStorageClient, containerName, blobName string, size int64, vhdMetaData *metadata.MetaData) error {
	blob := client.GetContainerReference(containerName).GetBlobReference(blobName)
	blob.Properties.ContentLength = size
	if err := blob.PutPageBlob(nil); err != nil {
		return err
	}
	m, _ := vhdMetaData.ToMap()
	blob.Metadata = m
	if err := blob.SetMetadata(nil); err != nil {
		return err
	}

	return nil
}

// getAlreadyUploadedBlobRanges returns the range slice containing ranges of a page blob those are already uploaded.
// The parameter client is the Azure blob service client, parameter containerName is the name of an existing container
// in which the page blob resides, parameter blobName is name for the page blob
//
func getAlreadyUploadedBlobRanges(client storage.BlobStorageClient, containerName, blobName string) ([]*common.IndexRange, error) {
	blob := client.GetContainerReference(containerName).GetBlobReference(blobName)
	existingRanges, err := blob.GetPageRanges(nil)
	if err != nil {
		return nil, err
	}
	var rangesToSkip = make([]*common.IndexRange, len(existingRanges.PageList))
	for i, r := range existingRanges.PageList {
		rangesToSkip[i] = common.NewIndexRange(r.Start, r.End)
	}
	return rangesToSkip, nil
}

// getBlobMD5Hash returns the MD5Hash associated with a blob
// The parameter client is the Azure blob service client, parameter containerName is the name of an existing container
// in which the page blob resides, parameter blobName is name for the page blob
//
func getBlobMD5Hash(client storage.BlobStorageClient, containerName, blobName string) (string, error) {
	blob := client.GetContainerReference(containerName).GetBlobReference(blobName)
	err := blob.GetProperties(nil)
	if err != nil {
		return "", err
	}
	return blob.Properties.ContentMD5, nil
}

func (a *API) SignBlob(storageaccount, storagekey, container, blob string) (string, error) {
	sc, err := storage.NewClient(storageaccount, storagekey, a.opts.StorageEndpointSuffix, storage.DefaultAPIVersion, true)
	if err != nil {
		return "", err
	}

	// The SAS URI must use a container level token but target the blob.
	// https://docs.microsoft.com/en-us/azure/marketplace/azure-vm-get-sas-uri
	bsc := sc.GetBlobService()
	cont := bsc.GetContainerReference(container)
	containerSASOptions := storage.ContainerSASOptions{}
	containerSASOptions.Read = true
	containerSASOptions.List = true
	containerSASOptions.Expiry = time.Date(2099, time.December, 31, 23, 59, 59, 0, time.UTC)
	containerSAS, err := cont.GetSASURI(containerSASOptions)
	if err != nil {
		return "", err
	}
	sasParts, err := url.Parse(containerSAS)
	if err != nil {
		return "", err
	}
	sas := sasParts.Query().Encode()

	blobURLRaw := cont.GetBlobReference(blob).GetURL()
	blobURL, err := url.Parse(blobURLRaw)
	if err != nil {
		return "", err
	}
	blobURL.RawQuery = sas
	return blobURL.String(), nil
}

func (a *API) CopyBlob(storageaccount, storagekey, container, targetBlob, sourceBlob string) error {
	sc, err := storage.NewClient(storageaccount, storagekey, a.opts.StorageEndpointSuffix, storage.DefaultAPIVersion, true)
	if err != nil {
		return err
	}

	bsc := sc.GetBlobService()
	cont := bsc.GetContainerReference(container)
	if _, err = cont.CreateIfNotExists(&storage.CreateContainerOptions{Access: storage.ContainerAccessTypePrivate}); err != nil {
		return err
	}
	dstBlob := cont.GetBlobReference(targetBlob)

	azcopy, err := exec.LookPath("azcopy")
	if err == nil {
		sasOpts := storage.BlobSASOptions{}
		sasOpts.Read = true
		sasOpts.Write = true
		sasOpts.Create = true
		sasOpts.Expiry = time.Now().Add(15 * time.Minute)
		dstSas, err := dstBlob.GetSASURI(sasOpts)
		if err != nil {
			return err
		}
		// log-level=NONE only affects the log file - stdout is unaffected
		cmd := exec.Command(azcopy, "cp", "--blob-type=PageBlob", "--log-level=NONE", sourceBlob, dstSas)
		cmd.Stderr = os.Stderr
		cmd.Stdout = os.Stdout
		err = cmd.Run()
		// azcopy leaves behind "plan" files in case a job needs to be retried
		_ = exec.Command("azcopy", "jobs", "clean").Run()
		if err == nil {
			return nil
		}
		// try the normal copy if azcopy failed
	}

	return dstBlob.Copy(sourceBlob, nil)
}

func (a *API) DeleteBlob(storageaccount, storagekey, container, blob string) error {
	sc, err := storage.NewClient(storageaccount, storagekey, a.opts.StorageEndpointSuffix, storage.DefaultAPIVersion, true)
	if err != nil {
		return err
	}

	bsc := sc.GetBlobService()
	cont := bsc.GetContainerReference(container)
	return cont.GetBlobReference(blob).Delete(nil)
}
