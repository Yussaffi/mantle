// Code generated by go generate; DO NOT EDIT.

package brightbox

import "context"
import "path"

const (
	// databasesnapshotAPIPath returns the relative URL path to the DatabaseSnapshot endpoint
	databasesnapshotAPIPath = "database_snapshots"
)

// DatabaseSnapshots returns the collection view for DatabaseSnapshot
func (c *Client) DatabaseSnapshots(ctx context.Context) ([]DatabaseSnapshot, error) {
	return apiGetCollection[[]DatabaseSnapshot](ctx, c, databasesnapshotAPIPath)
}

// DatabaseSnapshot retrieves a detailed view of one resource
func (c *Client) DatabaseSnapshot(ctx context.Context, identifier string) (*DatabaseSnapshot, error) {
	return apiGet[DatabaseSnapshot](ctx, c, path.Join(databasesnapshotAPIPath, identifier))
}

// UpdateDatabaseSnapshot updates an existing resources's attributes. Not all
// attributes can be changed (such as ID).
//
// It takes an instance of DatabaseSnapshotOptions. Specify the resource you
// want to update using the ID field.
func (c *Client) UpdateDatabaseSnapshot(ctx context.Context, updateDatabaseSnapshot DatabaseSnapshotOptions) (*DatabaseSnapshot, error) {
	return apiPut[DatabaseSnapshot](ctx, c, path.Join(databasesnapshotAPIPath, updateDatabaseSnapshot.ID), updateDatabaseSnapshot)
}

// DestroyDatabaseSnapshot destroys an existing resource.
func (c *Client) DestroyDatabaseSnapshot(ctx context.Context, identifier string) (*DatabaseSnapshot, error) {
	return apiDelete[DatabaseSnapshot](ctx, c, path.Join(databasesnapshotAPIPath, identifier))
}

// LockDatabaseSnapshot locks a resource against destroy requests
func (c *Client) LockDatabaseSnapshot(ctx context.Context, identifier string) (*DatabaseSnapshot, error) {
	return apiPut[DatabaseSnapshot](ctx, c, path.Join(databasesnapshotAPIPath, identifier, "lock_resource"), nil)
}

// UnlockDatabaseSnapshot unlocks a resource, re-enabling destroy requests
func (c *Client) UnlockDatabaseSnapshot(ctx context.Context, identifier string) (*DatabaseSnapshot, error) {
	return apiPut[DatabaseSnapshot](ctx, c, path.Join(databasesnapshotAPIPath, identifier, "unlock_resource"), nil)
}

// CreatedAt implements the CreateDated interface for DatabaseSnapshot
func (s DatabaseSnapshot) CreatedAtUnix() int64 {
	return s.CreatedAt.Unix()
}