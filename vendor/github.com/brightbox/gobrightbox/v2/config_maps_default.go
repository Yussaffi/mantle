// Code generated by go generate; DO NOT EDIT.

package brightbox

import "context"
import "path"

const (
	// configmapAPIPath returns the relative URL path to the ConfigMap endpoint
	configmapAPIPath = "config_maps"
)

// ConfigMaps returns the collection view for ConfigMap
func (c *Client) ConfigMaps(ctx context.Context) ([]ConfigMap, error) {
	return apiGetCollection[[]ConfigMap](ctx, c, configmapAPIPath)
}

// ConfigMap retrieves a detailed view of one resource
func (c *Client) ConfigMap(ctx context.Context, identifier string) (*ConfigMap, error) {
	return apiGet[ConfigMap](ctx, c, path.Join(configmapAPIPath, identifier))
}

// CreateConfigMap creates a new resource from the supplied option map.
//
// It takes an instance of ConfigMapOptions. Not all attributes can be
// specified at create time (such as ID, which is allocated for you).
func (c *Client) CreateConfigMap(ctx context.Context, newConfigMap ConfigMapOptions) (*ConfigMap, error) {
	return apiPost[ConfigMap](ctx, c, configmapAPIPath, newConfigMap)
}

// UpdateConfigMap updates an existing resources's attributes. Not all
// attributes can be changed (such as ID).
//
// It takes an instance of ConfigMapOptions. Specify the resource you
// want to update using the ID field.
func (c *Client) UpdateConfigMap(ctx context.Context, updateConfigMap ConfigMapOptions) (*ConfigMap, error) {
	return apiPut[ConfigMap](ctx, c, path.Join(configmapAPIPath, updateConfigMap.ID), updateConfigMap)
}

// DestroyConfigMap destroys an existing resource.
func (c *Client) DestroyConfigMap(ctx context.Context, identifier string) (*ConfigMap, error) {
	return apiDelete[ConfigMap](ctx, c, path.Join(configmapAPIPath, identifier))
}