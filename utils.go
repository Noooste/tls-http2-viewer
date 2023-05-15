package main

import (
	"bytes"
	http "github.com/Noooste/fhttp"
	tls "github.com/Noooste/utls"
	"math"
	"strconv"
	"strings"
)

func isGrease(e uint16) bool {
	i := (e & 0xf0) | 0x0a
	i |= i << 8
	return i == e
}

const GreasePlaceholder = "GREASE_PLACEHOLDER"

func getHTTP1Headers(req *http.Request) []string {
	header := make([]string, len(req.RawHeader))
	for i, element := range req.RawHeader {
		header[i] = element.Name + ": " + element.Value
	}
	return header
}

func parseHTTP2Frames(req *http.Request) ([]interface{}, string) {
	var frames []interface{}
	var fingerprint []string
	var tmp string

	settings, tmp := getSettings(req)
	fingerprint = append(fingerprint, tmp)
	frames = append(frames, settings)

	wUpdate, tmp := getWindowsUpdate(req)
	if wUpdate != nil {
		frames = append(frames, wUpdate)
	}
	fingerprint = append(fingerprint, tmp)

	priorities, tmp := getPriorities(req)
	if len(priorities) == 0 {
		fingerprint = append(fingerprint, "0")
	} else {
		for _, p := range priorities {
			frames = append(frames, p)
		}
		fingerprint = append(fingerprint, tmp)
	}

	headers, tmp := getHTT2Headers(req)
	fingerprint = append(fingerprint, tmp)
	frames = append(frames, headers)

	return frames, strings.Join(fingerprint, "|")
}

func getSettings(req *http.Request) (*Settings, string) {
	settings := req.SettingsKeyValue
	lengthSettings := req.Settings.NumSettings()

	settingInformation := &Settings{
		Type:     req.Settings.Type.String(),
		Length:   int(req.Settings.Length),
		ID:       int(req.Settings.StreamID),
		Settings: make([]string, lengthSettings),
	}

	fingerprint := ""

	for i, setting := range settings {
		id := setting.ID
		value := int(setting.Val)

		fingerprint += strconv.Itoa(int(id)) + ":" + strconv.Itoa(value)
		if i < lengthSettings-1 {
			fingerprint += ","
		}
		settingInformation.Settings[i] = http2settingName[http2SettingID(id)] + " = " + strconv.Itoa(value)
	}

	return settingInformation, fingerprint
}

func getWindowsUpdate(req *http.Request) (*WindowsUpdate, string) {
	if req.WindowsUpdate == nil {
		return nil, "00"
	}

	information := &WindowsUpdate{
		Type:      req.WindowsUpdate.Type.String(),
		Length:    int(req.WindowsUpdate.Length),
		ID:        int(req.WindowsUpdate.StreamID),
		Increment: int(req.WindowsUpdate.Increment),
	}

	return information, strconv.Itoa(information.Increment)
}

func getPriorities(req *http.Request) ([]*Priorities, string) {
	priorities := req.PriorityFrames
	fingerprint := ""
	lengthPriorities := len(priorities)
	returnFrames := make([]*Priorities, lengthPriorities)

	for i, frame := range priorities {
		returnFrames[i] = &Priorities{
			Type:      frame.Type.String(),
			ID:        int(frame.StreamID),
			Length:    int(frame.Length),
			Weight:    int(frame.Weight + 1),
			StreamDep: int(frame.StreamDep),
			Exclusive: frame.Exclusive,
		}

		exclusiveValue := 0
		if returnFrames[i].Exclusive {
			exclusiveValue = 1
		}
		fingerprint += strconv.Itoa(returnFrames[i].ID) + ":" + strconv.Itoa(exclusiveValue) + ":" + strconv.Itoa(returnFrames[i].StreamDep) + ":" + strconv.Itoa(returnFrames[i].Weight)

		if i < lengthPriorities-1 {
			fingerprint += ","
		}
	}

	return returnFrames, fingerprint
}

func getHTT2Headers(req *http.Request) (*HTTP2Headers, string) {
	header := req.HeaderFrame
	fingerprint := ""

	http2Headers := &HTTP2Headers{
		Type:    header.Type.String(),
		Length:  int(header.Length),
		ID:      int(req.HeaderFrame.StreamID),
		Headers: make([]string, len(header.Fields)),
	}

	for i, element := range req.RawHeader {
		http2Headers.Headers[i] = element.Name + ": " + element.Value
		if element.IsPseudo() {
			fingerprint += string(element.Name[1]) + ","
		}
	}

	return http2Headers, fingerprint[:len(fingerprint)-1]
}

func getCiphersString(ciphers []uint16) []string {
	stringCiphers := make([]string, len(ciphers))
	for i, cipher := range ciphers {
		if isGrease(cipher) {
			stringCiphers[i] = GreasePlaceholder
		} else {
			stringCiphers[i] = ciphersSuite[cipher]
		}
	}
	return stringCiphers
}

func getExtensionsString(raw []byte) ([]string, []uint16) {
	var extensionsString []string
	var extensionsValues []uint16
	var index = 38 //skip type (1), length (3), version (2), random (32)

	index += 1 + int(raw[index])                       //skip session id
	index += 2 + getIntValue(raw[index], raw[index+1]) //skip ciphers
	index += 1 + int(raw[index])                       //skip compression

	extensionFinalIndex := getIntValue(raw[index], raw[index+1]) //get extension length

	index += 2 //skip extensions length

	for index < extensionFinalIndex {
		id := getIntValue(raw[index], raw[index+1])
		if isGrease(uint16(id)) {
			extensionsString = append(extensionsString, GreasePlaceholder)
		} else {
			if value, ok := extensions[id]; ok {
				extensionsString = append(extensionsString, strconv.Itoa(id)+": "+value)
			} else {
				extensionsString = append(extensionsString, strconv.Itoa(id)+": unknown")
			}
		}

		extensionsValues = append(extensionsValues, uint16(id))

		index += 2
		index += getIntValue(raw[index], raw[index+1])
		index += 2
	}

	return extensionsString, extensionsValues
}

func getCurvesValues(curves []tls.CurveID) []string {
	intCurves := make([]string, len(curves))
	for i, curve := range curves {
		if isGrease(uint16(curve)) {
			intCurves[i] = GreasePlaceholder
		} else {
			intCurves[i] = curveName[CurveID(curve)]
		}
	}
	return intCurves
}

func getPointsValues(points []uint8) []int {
	intPoints := make([]int, len(points))
	for i, point := range points {
		intPoints[i] = int(point)
	}
	return intPoints
}

type SignatureStruct struct {
	Value    tls.SignatureScheme `json:"value"`
	HexValue string              `json:"hexValue"`
	Name     string              `json:"name"`
}

func getAlgoString(schemes []tls.SignatureScheme) []SignatureStruct {
	intSchemes := make([]SignatureStruct, len(schemes))
	for i, scheme := range schemes {
		intSchemes[i] = SignatureStruct{
			Value:    scheme,
			HexValue: "0x" + strconv.FormatUint(uint64(scheme), 16),
			Name:     signatureSchemeName[SignatureScheme(scheme)],
		}
	}
	return intSchemes
}

func getVersionsValues(versions []uint16) []string {
	stringVersions := make([]string, len(versions))
	var ok bool
	for i, version := range versions {
		if isGrease(version) {
			stringVersions[i] = GreasePlaceholder
		} else {
			stringVersions[i], ok = versionName[int(version)]
			if !ok {
				stringVersions[i] = "unknown (" + strconv.Itoa(int(version)) + ")"
			}
		}
	}
	return stringVersions
}

func getJA3(version uint16, ciphers []uint16, extensions []uint16, curves []tls.CurveID, points []uint8) string {
	var builder = bytes.Buffer{}

	builder.WriteString(strconv.Itoa(int(version)) + ",")

	for _, cipher := range ciphers {
		if !isGrease(cipher) {
			builder.WriteString(strconv.Itoa(int(cipher)) + "-")
		}
	}
	builder.Truncate(builder.Len() - 1)
	builder.WriteString(",")

	for _, extension := range extensions {
		if !isGrease(extension) {
			builder.WriteString(strconv.Itoa(int(extension)) + "-")
		}
	}
	builder.Truncate(builder.Len() - 1)
	builder.WriteString(",")

	for _, curve := range curves {
		if !isGrease(uint16(curve)) {
			builder.WriteString(strconv.Itoa(int(curve)) + "-")
		}
	}
	builder.Truncate(builder.Len() - 1)
	builder.WriteString(",")

	for _, point := range points {
		if !isGrease(uint16(point)) {
			builder.WriteString(strconv.Itoa(int(point)) + "-")
		}
	}
	builder.Truncate(builder.Len() - 1)

	return builder.String()
}
func getIntValue(left byte, right byte) int {
	return int(float64(int(left))*math.Pow(16, 2) + float64(int(right)))
}
