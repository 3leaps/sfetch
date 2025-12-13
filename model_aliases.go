package main

import "github.com/3leaps/sfetch/internal/model"

type Release = model.Release
type Asset = model.Asset

type AssetType = model.AssetType

const (
	AssetTypeArchive = model.AssetTypeArchive
	AssetTypeRaw     = model.AssetTypeRaw
	AssetTypePackage = model.AssetTypePackage
	AssetTypeUnknown = model.AssetTypeUnknown
)

type ArchiveFormat = model.ArchiveFormat

const (
	ArchiveFormatTarGz  = model.ArchiveFormatTarGz
	ArchiveFormatTarXz  = model.ArchiveFormatTarXz
	ArchiveFormatTarBz2 = model.ArchiveFormatTarBz2
	ArchiveFormatTar    = model.ArchiveFormatTar
	ArchiveFormatZip    = model.ArchiveFormatZip
)

type SignatureFormats = model.SignatureFormats
type RepoConfig = model.RepoConfig
