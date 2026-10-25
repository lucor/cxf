package cxf

// Shared marks an item or collection as shared with other accounts.
type Shared struct {
	// Name is always "shared".
	Name string `json:"name"`
	// Accessors lists accounts with access to the entity.
	Accessors []SharingAccessor `json:"accessors"`
}

// SharingAccessorType identifies a user or group.
type SharingAccessorType string

const (
	// SharingAccessorTypeUser identifies an individual user.
	SharingAccessorTypeUser SharingAccessorType = "user"
	// SharingAccessorTypeGroup identifies a group of users.
	SharingAccessorTypeGroup SharingAccessorType = "group"
)

// SharingAccessorPermission identifies an access permission.
type SharingAccessorPermission string

const (
	// SharingAccessorPermissionRead allows reading metadata without secrets.
	SharingAccessorPermissionRead SharingAccessorPermission = "read"
	// SharingAccessorPermissionReadSecret allows reading secrets.
	SharingAccessorPermissionReadSecret SharingAccessorPermission = "readSecret"
	// SharingAccessorPermissionUpdate allows updating the entity.
	SharingAccessorPermissionUpdate SharingAccessorPermission = "update"
	// SharingAccessorPermissionCreate allows creating child entities.
	SharingAccessorPermissionCreate SharingAccessorPermission = "create"
	// SharingAccessorPermissionDelete allows deleting child entities.
	SharingAccessorPermissionDelete SharingAccessorPermission = "delete"
	// SharingAccessorPermissionShare allows sharing child entities.
	SharingAccessorPermissionShare SharingAccessorPermission = "share"
	// SharingAccessorPermissionManage allows managing the entity.
	SharingAccessorPermissionManage SharingAccessorPermission = "manage"
)

// SharingAccessor describes an account that can access a shared entity.
type SharingAccessor struct {
	// Type identifies a user or group.
	Type SharingAccessorType `json:"type"`
	// AccountID identifies the account receiving access.
	AccountID string `json:"accountId"`
	// Name is the account or group name.
	Name string `json:"name"`
	// Permissions lists the granted permissions, including unknown future values.
	Permissions []SharingAccessorPermission `json:"permissions"`
}

// UnmarshalJSON decodes and validates a sharing accessor atomically.
func (accessor *SharingAccessor) UnmarshalJSON(data []byte) error {
	if accessor == nil {
		return invalid("sharingAccessor", "must not be nil")
	}
	type plain SharingAccessor
	var decoded plain
	if err := decodeObject(data, "sharingAccessor", []string{"type", "accountId", "name", "permissions"}, nil, &decoded); err != nil {
		return err
	}
	candidate := SharingAccessor(decoded)
	if err := candidate.Validate(); err != nil {
		return err
	}
	*accessor = candidate
	return nil
}

// Validate checks the accessor's required data and account identifier.
func (accessor *SharingAccessor) Validate() error {
	if accessor == nil {
		return invalid("sharingAccessor", "must not be nil")
	}
	if err := validateUTF8String("sharingAccessor.type", string(accessor.Type)); err != nil {
		return err
	}
	if err := validateUTF8String("sharingAccessor.name", accessor.Name); err != nil {
		return err
	}
	if _, err := decodeID(accessor.AccountID); err != nil {
		return invalid("sharingAccessor.accountId", "invalid identifier")
	}
	if accessor.Permissions == nil {
		return invalid("sharingAccessor.permissions", "required array must not be null")
	}
	return nil
}

// Validate checks the shared extension.
func (shared *Shared) Validate() error {
	if shared == nil || shared.Name != "shared" {
		return invalid("shared.name", "invalid extension name")
	}
	if shared.Accessors == nil {
		return invalid("shared.accessors", "required array must not be null")
	}
	for i := range shared.Accessors {
		if err := shared.Accessors[i].Validate(); err != nil {
			return err
		}
	}
	return nil
}

// UnmarshalJSON decodes and validates a shared extension atomically.
func (shared *Shared) UnmarshalJSON(data []byte) error {
	if shared == nil {
		return invalid("shared", "must not be nil")
	}
	type plain Shared
	var decoded plain
	if err := decodeObject(data, "shared", []string{"name", "accessors"}, nil, &decoded); err != nil {
		return err
	}
	candidate := Shared(decoded)
	if err := candidate.Validate(); err != nil {
		return err
	}
	*shared = candidate
	return nil
}
