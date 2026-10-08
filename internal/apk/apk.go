// Package apk reads package declarations and signer certificates from verified
// APK archives. It does not install packages or provide Android OS services.
package apk

import (
	"archive/zip"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/avast/apkparser"
	"github.com/avast/apkverifier"
	"github.com/avast/apkverifier/apilevel"
)

// Metadata is a verified, source-derived snapshot, not installed PackageInfo.
// SDK versions and Debuggable use Android's documented manifest defaults when
// absent. They describe this APK, never the Windows host's OS or debugger state.
// No UID, installer, permission grants, install times, or device identity is
// inferred from these declarations.
//
// Attribute maps use android:name for Android attributes, plain name for
// unnamespaced attributes, and {namespace}name for other namespaces. Resource
// references in these maps remain references; no host resource selection is
// invented. ApplicationFlags contains only declared boolean attributes, not an
// ApplicationInfo.flags bitmask or evidence that their requested behavior exists.
// Callers must not modify a snapshot before using it as trusted package data.
type Metadata struct {
	ArchivePath                     string
	PackageName                     string
	VersionName                     string
	VersionCode                     uint32
	VersionCodeMajor                uint32
	LongVersionCode                 uint64
	MinSDKVersion                   int32
	TargetSDKVersion                int32
	Debuggable                      bool
	DebuggableDeclared              bool
	ManifestAttributes              map[string]string
	SDKAttributes                   map[string]string
	ApplicationAttributes           map[string]string
	ApplicationFlags                map[string]bool
	RequestedPermissions            []Permission
	DeclaredPermissions             []Permission
	NativeLibraries                 []NativeLibrary
	SigningSchemeID                 int
	SignerCertificatesDER           [][][]byte
	AdditionalSchemeCertificatesDER map[int][][][]byte
	SigningCertificateLineage       []LineageCertificate
	VerificationWarnings            []string
}

// Permission records a manifest declaration, never a granted permission.
// Element distinguishes uses-permission, uses-permission-sdk-23 and declarations
// such as permission, permission-group and permission-tree. Attributes retains
// protectionLevel and usesPermissionFlags exactly as decoded from the archive.
type Permission struct {
	Name          string
	Element       string
	MaxSDKVersion *int32
	Attributes    map[string]string
}

// LineageCertificate is a certificate in a cryptographically verified v3
// signing rotation lineage. Capabilities are Android's signed lineage flags;
// they do not grant permissions on this host.
type LineageCertificate struct {
	CertificateDER []byte
	Capabilities   uint32
}

// NativeLibrary identifies an actual signed ZIP entry. ArchivePath is a
// canonical host APK path and ArchiveEntry is its exact, slash-separated member
// name; neither claims an installed nativeLibraryDir. SHA256 covers the complete
// uncompressed member, not its compressed ZIP representation.
type NativeLibrary struct {
	ArchivePath  string
	ArchiveEntry string
	ABI          string
	Name         string
	Size         int64
	SHA256       [sha256.Size]byte

	verified bool
}

// Verify checks APK cryptographic signatures and signed content digests using
// apkverifier's Android-compatible v1/v2/v3/v3.1 verification, starting at the
// declared minimum SDK and extending through the verifier's supported range.
// SigningSchemeID is the selected verified scheme (1, 2, 3 or 31), not a claim
// that every embedded scheme was selected. Warnings and additional verified
// scheme certificates are retained rather than hidden.
//
// This proves archive integrity under its contained signer keys, not that a
// signer belongs to a particular publisher or that Play installed the APK. It
// does not validate source-stamp/Play provenance, detached v4 signatures, a
// platform trust store, device attestation, Android installation eligibility,
// or runtime Android services. An expected publisher must be pinned separately.
// The APK is opened once and is never extracted or modified.
func Verify(archivePath string) (metadata *Metadata, err error) {
	// The upstream Android-compatible parsers can panic on unsupported corrupt
	// structures. Such an archive must fail closed, never return partial data.
	defer func() {
		if failure := recover(); failure != nil {
			metadata = nil
			err = fmt.Errorf("inspect APK: malformed or unsupported archive: %v", failure)
		}
	}()

	file, canonicalPath, before, err := openRegularFile(archivePath)
	if err != nil {
		return nil, fmt.Errorf("open APK: %w", err)
	}
	defer file.Close()

	archive, err := zip.NewReader(file, before.Size())
	if err != nil {
		return nil, fmt.Errorf("read APK ZIP: %w", err)
	}
	manifestFile, libraryFiles, err := inspectEntries(archive)
	if err != nil {
		return nil, err
	}
	metadata, err = readManifest(manifestFile)
	if err != nil {
		return nil, fmt.Errorf("read APK AndroidManifest.xml: %w", err)
	}

	verificationZIP, err := apkparser.OpenZipReader(file)
	if err != nil {
		return nil, fmt.Errorf("open APK signature ZIP: %w", err)
	}
	defer verificationZIP.Close()
	verification, err := apkverifier.VerifyWithSdkVersionReader(file, verificationZIP, metadata.MinSDKVersion, apilevel.V_AnyMax)
	if err != nil {
		return nil, fmt.Errorf("verify APK signature: %w", err)
	}
	metadata.SignerCertificatesDER, err = certificateDERs(verification.SignerCerts)
	if err != nil {
		return nil, fmt.Errorf("verify APK signer certificates: %w", err)
	}
	metadata.SigningSchemeID = verification.SigningSchemeId
	if block := verification.SigningBlockResult; block != nil {
		if block.ContainsErrors() {
			return nil, fmt.Errorf("verify APK signing block: %w", block.GetLastError())
		}
		metadata.VerificationWarnings = block.Warnings
		for scheme, result := range block.ExtraResults {
			if result == nil || result.ContainsErrors() {
				return nil, fmt.Errorf("verify APK additional signature scheme %d: invalid result", scheme)
			}
			certificates, certErr := certificateDERs(result.Certs)
			if certErr != nil {
				return nil, fmt.Errorf("verify APK additional signature scheme %d: %w", scheme, certErr)
			}
			if metadata.AdditionalSchemeCertificatesDER == nil {
				metadata.AdditionalSchemeCertificatesDER = make(map[int][][][]byte)
			}
			metadata.AdditionalSchemeCertificatesDER[scheme] = certificates
		}
		if lineage := block.SigningLineage; lineage != nil {
			for _, node := range lineage.Nodes {
				if node == nil || node.SigningCert == nil || len(node.SigningCert.Raw) == 0 {
					return nil, fmt.Errorf("verify APK signer lineage: missing certificate DER")
				}
				metadata.SigningCertificateLineage = append(metadata.SigningCertificateLineage, LineageCertificate{
					CertificateDER: node.SigningCert.Raw,
					Capabilities:   uint32(node.Flags),
				})
			}
		}
	}

	metadata.ArchivePath = canonicalPath
	var buffer []byte
	if len(libraryFiles) != 0 {
		buffer = make([]byte, 32*1024)
	}
	for _, member := range libraryFiles {
		reader, openErr := member.Open()
		if openErr != nil {
			return nil, fmt.Errorf("read APK native library %q: %w", member.Name, openErr)
		}
		hash := sha256.New()
		size, readErr := io.CopyBuffer(hash, reader, buffer)
		closeErr := reader.Close()
		if readErr != nil {
			return nil, fmt.Errorf("read APK native library %q: %w", member.Name, readErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close APK native library %q: %w", member.Name, closeErr)
		}
		if uint64(size) != member.UncompressedSize64 {
			return nil, fmt.Errorf("read APK native library %q: size mismatch", member.Name)
		}
		components := strings.Split(member.Name, "/")
		library := NativeLibrary{
			ArchivePath:  canonicalPath,
			ArchiveEntry: member.Name,
			ABI:          components[1],
			Name:         components[2],
			Size:         size,
			verified:     true,
		}
		hash.Sum(library.SHA256[:0])
		metadata.NativeLibraries = append(metadata.NativeLibraries, library)
	}
	if err := unchangedFile(file, canonicalPath, before); err != nil {
		return nil, fmt.Errorf("read APK: %w", err)
	}
	return metadata, nil
}

// VerifyFile compares an existing host library with this verified APK member
// and returns its canonical host path only on a complete size/SHA256 match. It
// does not extract, patch, install, load or create a library directory. The
// caller must keep the file unchanged between this check and loading it.
func (library NativeLibrary) VerifyFile(libraryPath string) (string, error) {
	if !library.verified {
		return "", fmt.Errorf("verify native library: entry did not originate from a verified APK")
	}
	file, canonicalPath, before, err := openRegularFile(libraryPath)
	if err != nil {
		return "", fmt.Errorf("open native library: %w", err)
	}
	defer file.Close()
	if before.Size() != library.Size {
		return "", fmt.Errorf("native library %q does not match signed APK member %q: size mismatch", canonicalPath, library.ArchiveEntry)
	}
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return "", fmt.Errorf("read native library %q: %w", canonicalPath, err)
	}
	var digest [sha256.Size]byte
	hash.Sum(digest[:0])
	if size != library.Size || digest != library.SHA256 {
		return "", fmt.Errorf("native library %q does not match signed APK member %q: SHA256 mismatch", canonicalPath, library.ArchiveEntry)
	}
	if err := unchangedFile(file, canonicalPath, before); err != nil {
		return "", fmt.Errorf("verify native library: %w", err)
	}
	return canonicalPath, nil
}

func inspectEntries(archive *zip.Reader) (*zip.File, []*zip.File, error) {
	seen := make(map[string]bool, len(archive.File))
	var manifest *zip.File
	var libraries []*zip.File
	for _, member := range archive.File {
		name := strings.TrimSuffix(member.Name, "/")
		if name == "" || name == "." || name == ".." || path.IsAbs(name) || path.Clean(name) != name || strings.HasPrefix(name, "../") || strings.ContainsAny(name, "\\\x00") {
			return nil, nil, fmt.Errorf("read APK: noncanonical ZIP member %q", member.Name)
		}
		if seen[name] {
			return nil, nil, fmt.Errorf("read APK: duplicate ZIP member %q", member.Name)
		}
		seen[name] = true
		if member.Flags&1 != 0 || (member.Method != zip.Store && member.Method != zip.Deflate) {
			return nil, nil, fmt.Errorf("read APK: encrypted or unsupported ZIP member %q", member.Name)
		}
		if member.Name == "AndroidManifest.xml" && !member.FileInfo().IsDir() {
			manifest = member
		}
		if strings.HasPrefix(member.Name, "lib/") && strings.HasSuffix(member.Name, ".so") && !member.FileInfo().IsDir() {
			if len(strings.Split(member.Name, "/")) != 3 {
				return nil, nil, fmt.Errorf("read APK: invalid native library member %q", member.Name)
			}
			libraries = append(libraries, member)
		}
	}
	if manifest == nil {
		return nil, nil, fmt.Errorf("read APK: AndroidManifest.xml is missing")
	}
	sort.Slice(libraries, func(i, j int) bool { return libraries[i].Name < libraries[j].Name })
	return manifest, libraries, nil
}

func certificateDERs(signers [][]*x509.Certificate) ([][][]byte, error) {
	if len(signers) == 0 {
		return nil, fmt.Errorf("no verified signers")
	}
	result := make([][][]byte, len(signers))
	for i, chain := range signers {
		if len(chain) == 0 {
			return nil, fmt.Errorf("signer %d has no certificate chain", i)
		}
		result[i] = make([][]byte, len(chain))
		for j, certificate := range chain {
			if certificate == nil || len(certificate.Raw) == 0 {
				return nil, fmt.Errorf("signer %d certificate %d has no DER", i, j)
			}
			// Raw retains the original, complete certificate DER; fingerprints
			// and SubjectPublicKeyInfo are not substitutes for certificates.
			result[i][j] = certificate.Raw
		}
	}
	return result, nil
}

func openRegularFile(filePath string) (*os.File, string, os.FileInfo, error) {
	if filePath == "" {
		return nil, "", nil, fmt.Errorf("file path is empty")
	}
	absolute, err := filepath.Abs(filePath)
	if err != nil {
		return nil, "", nil, err
	}
	canonical, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return nil, "", nil, err
	}
	canonical = filepath.Clean(canonical)
	file, err := os.Open(canonical)
	if err != nil {
		return nil, "", nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, "", nil, err
	}
	if !info.Mode().IsRegular() {
		file.Close()
		return nil, "", nil, fmt.Errorf("%q is not a regular file", canonical)
	}
	return file, canonical, info, nil
}

func unchangedFile(file *os.File, canonicalPath string, before os.FileInfo) error {
	after, err := file.Stat()
	if err != nil {
		return err
	}
	current, err := os.Stat(canonicalPath)
	if err != nil {
		return err
	}
	if !os.SameFile(before, after) || !os.SameFile(after, current) || before.Size() != after.Size() || after.Size() != current.Size() || !before.ModTime().Equal(after.ModTime()) || !after.ModTime().Equal(current.ModTime()) {
		return fmt.Errorf("source file %q changed during inspection", canonicalPath)
	}
	return nil
}
