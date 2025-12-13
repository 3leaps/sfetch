package main

import (
	"fmt"

	"github.com/3leaps/sfetch/internal/verify"
)

func detectChecksumType(filename string) string {
	return verify.DetectChecksumType(filename)
}

func detectChecksumAlgorithm(filename, defaultAlgo string) string {
	return verify.DetectChecksumAlgorithm(filename, defaultAlgo)
}

func formatSize(bytes int64) string {
	return verify.FormatSize(bytes)
}

func findChecksumSignature(assets []Asset, cfg *RepoConfig) (*Asset, string) {
	return verify.FindChecksumSignature(assets, cfg)
}

func signatureFormatFromExtension(filename string, formats SignatureFormats) string {
	switch verify.SignatureFormatFromExtension(filename, formats) {
	case verify.FormatBinary:
		return sigFormatBinary
	case verify.FormatMinisign:
		return sigFormatMinisign
	case verify.FormatPGP:
		return sigFormatPGP
	default:
		return ""
	}
}

func extractChecksum(data []byte, algo, assetName string) (string, error) {
	return verify.ExtractChecksum(data, algo, assetName)
}

func normalizeHexKey(input string) (string, error) {
	return verify.NormalizeHexKey(input)
}

func loadSignature(path string) (signatureData, error) {
	sd, err := verify.LoadSignature(path)
	if err != nil {
		return signatureData{}, err
	}
	switch sd.Format {
	case verify.FormatBinary:
		return signatureData{format: sigFormatBinary, bytes: sd.Bytes}, nil
	case verify.FormatMinisign:
		return signatureData{format: sigFormatMinisign}, nil
	case verify.FormatPGP:
		return signatureData{format: sigFormatPGP}, nil
	default:
		return signatureData{}, fmt.Errorf("unsupported signature format in %s", path)
	}
}

func verifyMinisignSignature(contentToVerify []byte, sigPath, pubKeyPath string) error {
	return verify.VerifyMinisignSignature(contentToVerify, sigPath, pubKeyPath)
}

func verifyPGPSignature(assetPath, sigPath, pubKeyPath, gpgBin string) error {
	return verify.VerifyPGPSignature(assetPath, sigPath, pubKeyPath, gpgBin)
}
