package apk

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/avast/apkparser"
)

const (
	androidNamespace = "http://schemas.android.com/apk/res/android"
	maxManifestSize  = 16 * 1024 * 1024
)

// Unselected resource references are deliberately not resolved using an
// arbitrary locale/configuration. They remain in the attribute maps; a scalar
// field requiring such resolution fails explicitly instead of guessing.
func readManifest(member *zip.File) (*Metadata, error) {
	if member.UncompressedSize64 > maxManifestSize {
		return nil, fmt.Errorf("binary manifest exceeds supported size of %d bytes", maxManifestSize)
	}
	reader, err := member.Open()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(reader, maxManifestSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxManifestSize || uint64(len(data)) != member.UncompressedSize64 {
		return nil, fmt.Errorf("binary manifest size mismatch")
	}
	overrides, err := validateBinaryManifest(data)
	if err != nil {
		return nil, err
	}
	encoder := manifestEncoder{
		metadata: &Metadata{
			MinSDKVersion:    1,
			SDKAttributes:    make(map[string]string),
			ApplicationFlags: make(map[string]bool),
		},
		stringOverrides: overrides,
	}
	if err := apkparser.ParseXml(bytes.NewReader(data), &encoder, nil); err != nil {
		return nil, err
	}
	if len(encoder.stack) != 0 || !encoder.rootClosed || !encoder.applicationSeen {
		return nil, fmt.Errorf("incomplete manifest or missing application element")
	}
	metadata := encoder.metadata
	if metadata.PackageName == "" || strings.HasPrefix(metadata.PackageName, "@") {
		return nil, fmt.Errorf("manifest package name is missing or unresolved")
	}
	if strings.HasPrefix(metadata.VersionName, "@") {
		return nil, fmt.Errorf("resource-referenced versionName requires Android resource configuration")
	}
	// Android uses minSdkVersion=1 when absent and targetSdkVersion=minSdkVersion
	// when absent. These are declaration defaults, never a host API-level claim.
	if _, declared := metadata.SDKAttributes["android:targetSdkVersion"]; !declared {
		metadata.TargetSDKVersion = metadata.MinSDKVersion
	}
	metadata.LongVersionCode = uint64(metadata.VersionCodeMajor)<<32 | uint64(metadata.VersionCode)
	metadata.Debuggable, metadata.DebuggableDeclared = metadata.ApplicationFlags["debuggable"]
	return metadata, nil
}

type attributeLocation struct {
	element   int
	attribute int
}

type manifestEncoder struct {
	metadata        *Metadata
	stack           []xml.Name
	rootClosed      bool
	applicationSeen bool
	sdkSeen         bool
	elementCount    int
	stringOverrides map[attributeLocation]string
}

func (encoder *manifestEncoder) EncodeToken(token xml.Token) error {
	switch element := token.(type) {
	case xml.StartElement:
		for i := range element.Attr {
			if value, exists := encoder.stringOverrides[attributeLocation{encoder.elementCount, i}]; exists {
				// Android's typed string index is authoritative. apkparser normally
				// uses the raw string index; a missing/different raw index must not
				// turn genuine typed string data into an empty or unrelated value.
				// Both indices come from the signed manifest; no APK bytes change.
				element.Attr[i].Value = value
			}
			for j := range i {
				if element.Attr[j].Name == element.Attr[i].Name {
					return fmt.Errorf("duplicate attribute %q on %q", attributeKey(element.Attr[i].Name), element.Name.Local)
				}
			}
		}
		encoder.elementCount++
		depth := len(encoder.stack)
		if depth == 0 {
			if encoder.rootClosed || element.Name != (xml.Name{Local: "manifest"}) {
				return fmt.Errorf("expected a single unnamespaced manifest root")
			}
			attributes := attributesOf(element)
			encoder.metadata.ManifestAttributes = attributes
			encoder.metadata.PackageName = attributes["package"]
			encoder.metadata.VersionName = attributes["android:versionName"]
			var err error
			if value, exists := attributes["android:versionCode"]; exists {
				encoder.metadata.VersionCode, err = manifestUint32(value)
				if err != nil {
					return fmt.Errorf("invalid versionCode: %w", err)
				}
			}
			if value, exists := attributes["android:versionCodeMajor"]; exists {
				encoder.metadata.VersionCodeMajor, err = manifestUint32(value)
				if err != nil {
					return fmt.Errorf("invalid versionCodeMajor: %w", err)
				}
			}
		} else if depth == 1 && element.Name.Space == "" {
			if err := encoder.manifestChild(element); err != nil {
				return err
			}
		}
		encoder.stack = append(encoder.stack, element.Name)
	case xml.EndElement:
		depth := len(encoder.stack)
		if depth == 0 || encoder.stack[depth-1] != element.Name {
			return fmt.Errorf("unbalanced manifest end element %q", element.Name.Local)
		}
		encoder.stack = encoder.stack[:depth-1]
		if depth == 1 {
			encoder.rootClosed = true
		}
	case xml.CharData:
		if strings.TrimSpace(string(element)) != "" {
			return fmt.Errorf("unexpected text in Android manifest")
		}
	}
	return nil
}

func (encoder *manifestEncoder) Flush() error {
	return nil
}

func (encoder *manifestEncoder) manifestChild(element xml.StartElement) error {
	switch element.Name.Local {
	case "uses-sdk":
		if encoder.sdkSeen {
			return fmt.Errorf("duplicate uses-sdk element")
		}
		encoder.sdkSeen = true
		attributes := attributesOf(element)
		encoder.metadata.SDKAttributes = attributes
		var err error
		if value, declared := attributes["android:minSdkVersion"]; declared {
			encoder.metadata.MinSDKVersion, err = sdkVersion(value)
			if err != nil {
				return fmt.Errorf("invalid minSdkVersion: %w", err)
			}
		}
		if value, declared := attributes["android:targetSdkVersion"]; declared {
			encoder.metadata.TargetSDKVersion, err = sdkVersion(value)
			if err != nil {
				return fmt.Errorf("invalid targetSdkVersion: %w", err)
			}
		}
	case "application":
		if encoder.applicationSeen {
			return fmt.Errorf("duplicate application element")
		}
		encoder.applicationSeen = true
		encoder.metadata.ApplicationAttributes = attributesOf(element)
		for _, attribute := range element.Attr {
			if attribute.Name.Space != androidNamespace || !applicationBoolean(attribute.Name.Local) {
				continue
			}
			value, err := manifestBool(attribute.Value)
			if err != nil {
				return fmt.Errorf("invalid application %s: %w", attribute.Name.Local, err)
			}
			encoder.metadata.ApplicationFlags[attribute.Name.Local] = value
		}
	case "uses-permission", "uses-permission-sdk-23", "uses-permission-sdk-m", "permission", "permission-group", "permission-tree":
		attributes := attributesOf(element)
		permission := Permission{
			Name:       attributes["android:name"],
			Element:    element.Name.Local,
			Attributes: attributes,
		}
		if permission.Name == "" || strings.HasPrefix(permission.Name, "@") {
			return fmt.Errorf("%s name is missing or unresolved", permission.Element)
		}
		if strings.HasPrefix(permission.Element, "uses-permission") {
			if value, declared := attributes["android:maxSdkVersion"]; declared {
				version, err := sdkVersion(value)
				if err != nil {
					return fmt.Errorf("invalid permission %q maxSdkVersion: %w", permission.Name, err)
				}
				permission.MaxSDKVersion = &version
			}
			encoder.metadata.RequestedPermissions = append(encoder.metadata.RequestedPermissions, permission)
		} else {
			encoder.metadata.DeclaredPermissions = append(encoder.metadata.DeclaredPermissions, permission)
		}
	}
	return nil
}

func attributesOf(element xml.StartElement) map[string]string {
	attributes := make(map[string]string, len(element.Attr))
	for _, attribute := range element.Attr {
		attributes[attributeKey(attribute.Name)] = attribute.Value
	}
	return attributes
}

func attributeKey(name xml.Name) string {
	switch name.Space {
	case "":
		return name.Local
	case androidNamespace:
		return "android:" + name.Local
	default:
		return "{" + name.Space + "}" + name.Local
	}
}

func manifestUint32(value string) (uint32, error) {
	base := 10
	if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
		base = 0
	}
	if strings.HasPrefix(value, "-") {
		// Binary Android integer values have 32 bits; retain those bits when
		// apkparser renders them as signed decimal numbers.
		integer, err := strconv.ParseInt(value, base, 32)
		return uint32(integer), err
	}
	integer, err := strconv.ParseUint(value, base, 32)
	return uint32(integer), err
}

func sdkVersion(value string) (int32, error) {
	integer, err := manifestUint32(value)
	if err != nil || integer == 0 || integer > 1<<31-1 {
		return 0, fmt.Errorf("expected a positive numeric API level, got %q", value)
	}
	return int32(integer), nil
}

func manifestBool(value string) (bool, error) {
	switch value {
	case "true", "1":
		return true, nil
	case "false", "0":
		return false, nil
	default:
		return false, fmt.Errorf("expected a resolved boolean declaration, got %q", value)
	}
}

func applicationBoolean(name string) bool {
	switch name {
	case "allowAudioPlaybackCapture", "allowBackup", "allowClearUserData",
		"allowCrossUidActivitySwitchFromBelow", "allowNativeHeapPointerTagging",
		"allowTaskReparenting", "backupInForeground", "cantSaveState",
		"debuggable", "defaultToDeviceProtectedStorage", "directBootAware",
		"enabled", "enableOnBackInvokedCallback", "extractNativeLibs",
		"forceQueryable", "fullBackupOnly", "hasCode", "hasFragileUserData",
		"hardwareAccelerated", "isGame", "killAfterRestore", "largeHeap",
		"multiArch", "persistent", "preserveLegacyExternalStorage",
		"requestLegacyExternalStorage", "resizeableActivity", "restoreAnyVersion",
		"supportsRtl", "supportsSizeChanges", "testOnly", "use32bitAbi",
		"usesCleartextTraffic", "vmSafeMode":
		return true
	default:
		return false
	}
}
