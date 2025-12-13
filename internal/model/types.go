package model

// Release is the subset of the GitHub release payload that sfetch uses.
type Release struct {
	TagName string  `json:"tag_name"`
	Assets  []Asset `json:"assets"`
}

// Asset is the subset of the GitHub release asset payload that sfetch uses.
type Asset struct {
	Name               string `json:"name"`
	BrowserDownloadUrl string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

// AssetType describes how an asset should be handled after download.
type AssetType string

const (
	AssetTypeArchive AssetType = "archive"
	AssetTypeRaw     AssetType = "raw"
	AssetTypePackage AssetType = "package"
	AssetTypeUnknown AssetType = "unknown"
)

// ArchiveFormat specifies the extraction strategy for archive assets.
type ArchiveFormat string

const (
	ArchiveFormatTarGz  ArchiveFormat = "tar.gz"
	ArchiveFormatTarXz  ArchiveFormat = "tar.xz"
	ArchiveFormatTarBz2 ArchiveFormat = "tar.bz2"
	ArchiveFormatTar    ArchiveFormat = "tar"
	ArchiveFormatZip    ArchiveFormat = "zip"
)

// SignatureFormats maps file extensions to verification methods.
// This allows detection of signature type from filename without inspecting content.
type SignatureFormats struct {
	Minisign []string `json:"minisign"` // verified via minisign (pure-Go)
	PGP      []string `json:"pgp"`      // verified via gpg sidecar
	Ed25519  []string `json:"ed25519"`  // verified as raw ed25519 (pure-Go)
}

// RepoConfig defines how sfetch discovers and verifies release artifacts.
// Schema: schemas/repo-config.schema.json
type RepoConfig struct {
	BinaryName            string           `json:"binaryName"`
	HashAlgo              string           `json:"hashAlgo"`
	ArchiveType           string           `json:"archiveType"` // deprecated; derived from AssetType/ArchiveFormat
	ArchiveExtensions     []string         `json:"archiveExtensions"`
	AssetType             AssetType        `json:"assetType,omitempty"`
	ArchiveFormat         ArchiveFormat    `json:"archiveFormat,omitempty"`
	AssetPatterns         []string         `json:"assetPatterns"`
	ChecksumCandidates    []string         `json:"checksumCandidates"`
	ChecksumSigCandidates []string         `json:"checksumSigCandidates"` // Workflow A: sigs over checksum files
	SignatureCandidates   []string         `json:"signatureCandidates"`   // Workflow B: per-asset sigs
	SignatureFormats      SignatureFormats `json:"signatureFormats"`
	PreferChecksumSig     *bool            `json:"preferChecksumSig,omitempty"` // prefer Workflow A over B; nil = use default (true)
}
