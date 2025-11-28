// Ortelius v11 Vulnerability Microservice that handles creating Vulnerability from OSV.dev
// Runs as a cronjob
package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/ortelius/cve2release-tracker/database"
	"github.com/ortelius/cve2release-tracker/util"

	// CVSS libraries
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"
)

type vulnID struct {
	ID       string `json:"id"`
	Modified string `json:"modified"`
}

type cveText struct {
	Description string `json:"cvetext"`
}

// SimplifiedRange represents a flattened version range for fast querying
type SimplifiedRange struct {
	Ecosystem          string  `json:"ecosystem"`
	Type               string  `json:"type"`
	Introduced         *string `json:"introduced,omitempty"`
	Fixed              *string `json:"fixed,omitempty"`
	LastAffected       *string `json:"last_affected,omitempty"`
	IntroducedPadded   *string `json:"introduced_padded,omitempty"`
	FixedPadded        *string `json:"fixed_padded,omitempty"`
	LastAffectedPadded *string `json:"last_affected_padded,omitempty"`
}

// AffectedVersions groups all version information for a specific package
type AffectedVersions struct {
	ExactVersions       []string          `json:"exact_versions,omitempty"`
	ExactVersionsPadded []string          `json:"exact_versions_padded,omitempty"`
	Ranges              []SimplifiedRange `json:"ranges,omitempty"`
}

var logger = database.InitLogger()
var dbconn = database.InitializeDatabase()

func getMitreURL() string {
	// Get the environment variable value for MITER_MAPPING_URL
	mitreURL := os.Getenv("MITRE_MAPPING_URL")
	return mitreURL
}

// calculateCVSSScore calculates numeric base score from CVSS vector string
// Returns 0 if unable to parse
func calculateCVSSScore(vectorStr string) float64 {
	if vectorStr == "" || !strings.HasPrefix(vectorStr, "CVSS:") {
		return 0
	}

	// Try CVSS v3.1 first (most common in OSV data)
	if strings.HasPrefix(vectorStr, "CVSS:3.1") || strings.HasPrefix(vectorStr, "CVSS:3.0") {
		cvss31, err := gocvss31.ParseVector(vectorStr)
		if err == nil {
			return cvss31.BaseScore()
		}
		logger.Sugar().Debugf("Failed to parse CVSS v3 vector %s: %v", vectorStr, err)
	}

	// Try CVSS v4.0
	if strings.HasPrefix(vectorStr, "CVSS:4.0") {
		cvss40, err := gocvss40.ParseVector(vectorStr)
		if err == nil {
			return cvss40.Score()
		}
		logger.Sugar().Debugf("Failed to parse CVSS v4 vector %s: %v", vectorStr, err)
	}

	return 0
}

// addCVSSScoresToContent adds calculated base scores to CVE content
// Modifies the content map in place
// If severity is null or no valid scores found, defaults to LOW (score: 0.1)
func addCVSSScoresToContent(content map[string]interface{}) {
	// Get severity array
	severity, ok := content["severity"].([]interface{})

	var baseScores []float64
	var highestScore float64
	hasValidScore := false

	// Process severity entries if they exist
	if ok && len(severity) > 0 {
		for _, sev := range severity {
			sevMap, ok := sev.(map[string]interface{})
			if !ok {
				continue
			}

			scoreStr, ok := sevMap["score"].(string)
			if !ok || scoreStr == "" {
				continue
			}

			sevType, _ := sevMap["type"].(string)

			// Only calculate for CVSS vectors
			if sevType == "CVSS_V3" || sevType == "CVSS_V4" {
				baseScore := calculateCVSSScore(scoreStr)
				if baseScore > 0 {
					baseScores = append(baseScores, baseScore)
					hasValidScore = true

					if baseScore > highestScore {
						highestScore = baseScore
					}
				}
			}
		}
	}

	// If no valid scores found (null severity, missing scores, or parse failures),
	// default to LOW severity with score 0.1
	if !hasValidScore {
		highestScore = 0.1
		baseScores = []float64{0.1}
		logger.Sugar().Debugf("CVE %s has no valid CVSS scores, defaulting to LOW (0.1)", content["_key"])
	}

	// Store calculated scores in database_specific field
	if content["database_specific"] == nil {
		content["database_specific"] = make(map[string]interface{})
	}

	dbSpecific := content["database_specific"].(map[string]interface{})
	dbSpecific["cvss_base_scores"] = baseScores
	dbSpecific["cvss_base_score"] = highestScore // Highest score for easy querying

	// Also add severity rating based on score
	dbSpecific["severity_rating"] = getSeverityRating(highestScore)

	content["database_specific"] = dbSpecific

	if hasValidScore {
		logger.Sugar().Debugf("Added CVSS scores to CVE %s: highest=%.1f", content["_key"], highestScore)
	}
}

// getSeverityRating returns CVSS severity rating based on base score
func getSeverityRating(score float64) string {
	if score == 0 {
		return "NONE"
	} else if score < 4.0 {
		return "LOW"
	} else if score < 7.0 {
		return "MEDIUM"
	} else if score < 9.0 {
		return "HIGH"
	}
	return "CRITICAL"
}

// padSemver converts a semantic version to a zero-padded string for lexicographic comparison
// Examples:
//
//	"4.1.5"        → "0004.0001.0005"
//	"4.1.5-alpha"  → "0004.0001.0005-alpha"
//	"4.1.5+build"  → "0004.0001.0005+build"
//
// Returns empty string if version cannot be padded (invalid format or complex cases)
func padSemver(version string) string {
	if version == "" {
		return ""
	}

	// Remove leading 'v'
	version = strings.TrimPrefix(version, "v")

	// Handle OSV "0" special value
	if version == "0" {
		return "0000.0000.0000"
	}

	// Split on - and + to separate core version from pre-release and build metadata
	var coreVersion, preRelease, buildMetadata string

	if plusIdx := strings.Index(version, "+"); plusIdx != -1 {
		buildMetadata = version[plusIdx:]
		version = version[:plusIdx]
	}

	if dashIdx := strings.Index(version, "-"); dashIdx != -1 {
		preRelease = version[dashIdx:]
		coreVersion = version[:dashIdx]
	} else {
		coreVersion = version
	}

	// EDGE CASE DETECTION: Pre-release with numbers that need proper ordering
	// e.g., "alpha1" vs "alpha10" - lexicographic comparison fails
	if preRelease != "" {
		// Check if pre-release contains numbers after letters
		// e.g., "alpha1", "beta10", "rc2"
		if matched, _ := regexp.MatchString(`[a-zA-Z]\d+`, preRelease); matched {
			// This needs proper semver comparison, not lexicographic
			return "" // Force Go processing
		}
	}

	// Split core version into parts
	parts := strings.Split(coreVersion, ".")
	if len(parts) < 1 || len(parts) > 3 {
		return "" // Invalid format
	}

	// Pad to 3 parts
	for len(parts) < 3 {
		parts = append(parts, "0")
	}

	// Pad each part to 4 digits
	var paddedParts []string
	for _, part := range parts {
		// Check if purely numeric
		num, err := strconv.Atoi(part)
		if err != nil || num < 0 || num > 9999 {
			return "" // Non-numeric or too large
		}
		paddedParts = append(paddedParts, fmt.Sprintf("%04d", num))
	}

	// Reconstruct version
	result := strings.Join(paddedParts, ".")
	result += preRelease + buildMetadata

	return result
}

// addDenormalizedVersionData adds pre-computed version data for fast AQL querying
// This enables database-side filtering instead of returning 10,000+ rows to Go
func addDenormalizedVersionData(content map[string]interface{}) {
	affected, ok := content["affected"].([]interface{})
	if !ok || len(affected) == 0 {
		return
	}

	affectedPurlSet := make(map[string]bool)
	affectedVersionsMap := make(map[string]AffectedVersions)

	for _, affectedItem := range affected {
		affectedObj, ok := affectedItem.(map[string]interface{})
		if !ok {
			continue
		}

		// Get package info
		packageInfo, ok := affectedObj["package"].(map[string]interface{})
		if !ok {
			continue
		}

		// Build base PURL
		basePurl := ""
		if purl, ok := packageInfo["purl"].(string); ok && purl != "" {
			// Clean and get base PURL
			cleanedPurl, err := util.CleanPURL(purl)
			if err != nil {
				logger.Sugar().Warnf("Failed to parse PURL %s: %v", purl, err)
				continue
			}
			basePurl, err = util.GetBasePURL(cleanedPurl)
			if err != nil {
				logger.Sugar().Warnf("Failed to get base PURL from %s: %v", cleanedPurl, err)
				continue
			}
		} else if ecosystem, eok := packageInfo["ecosystem"].(string); eok {
			if name, nok := packageInfo["name"].(string); nok {
				purlType := util.EcosystemToPurlType(ecosystem)
				if purlType != "" {
					basePurl = fmt.Sprintf("pkg:%s/%s", purlType, name)
				}
			}
		}

		if basePurl == "" {
			continue
		}

		affectedPurlSet[basePurl] = true

		// Get or create entry for this PURL
		affectedVersions := affectedVersionsMap[basePurl]

		// Process exact versions
		if versions, ok := affectedObj["versions"].([]interface{}); ok && len(versions) > 0 {
			for _, v := range versions {
				if vStr, ok := v.(string); ok {
					affectedVersions.ExactVersions = append(affectedVersions.ExactVersions, vStr)

					// Add padded version if possible
					if padded := padSemver(vStr); padded != "" {
						affectedVersions.ExactVersionsPadded = append(affectedVersions.ExactVersionsPadded, padded)
					}
				}
			}
		}

		// Process ranges
		if ranges, ok := affectedObj["ranges"].([]interface{}); ok && len(ranges) > 0 {
			ecosystem := ""
			if e, ok := packageInfo["ecosystem"].(string); ok {
				ecosystem = e
			}

			for _, rangeItem := range ranges {
				rangeObj, ok := rangeItem.(map[string]interface{})
				if !ok {
					continue
				}

				rangeType, _ := rangeObj["type"].(string)

				// Only process SEMVER and ECOSYSTEM types
				if rangeType != "SEMVER" && rangeType != "ECOSYSTEM" {
					continue
				}

				events, ok := rangeObj["events"].([]interface{})
				if !ok || len(events) == 0 {
					continue
				}

				var introduced, fixed, lastAffected *string
				var introducedPadded, fixedPadded, lastAffectedPadded *string

				// Parse events
				for _, eventItem := range events {
					eventObj, ok := eventItem.(map[string]interface{})
					if !ok {
						continue
					}

					if intro, ok := eventObj["introduced"].(string); ok {
						introduced = &intro
						if padded := padSemver(intro); padded != "" {
							introducedPadded = &padded
						}
					}
					if fix, ok := eventObj["fixed"].(string); ok {
						fixed = &fix
						if padded := padSemver(fix); padded != "" {
							fixedPadded = &padded
						}
					}
					if last, ok := eventObj["last_affected"].(string); ok {
						lastAffected = &last
						if padded := padSemver(last); padded != "" {
							lastAffectedPadded = &padded
						}
					}
				}

				// Only store ranges with both lower and upper bounds
				// This matches the logic in IsVersionAffected
				hasLowerBound := introduced != nil
				hasUpperBound := fixed != nil || lastAffected != nil

				if hasLowerBound && hasUpperBound {
					affectedVersions.Ranges = append(affectedVersions.Ranges, SimplifiedRange{
						Ecosystem:          ecosystem,
						Type:               rangeType,
						Introduced:         introduced,
						Fixed:              fixed,
						LastAffected:       lastAffected,
						IntroducedPadded:   introducedPadded,
						FixedPadded:        fixedPadded,
						LastAffectedPadded: lastAffectedPadded,
					})
				}
			}
		}

		affectedVersionsMap[basePurl] = affectedVersions
	}

	// Convert set to slice
	var affectedPurls []string
	for purl := range affectedPurlSet {
		affectedPurls = append(affectedPurls, purl)
	}

	// Add denormalized fields to the CVE document
	content["affected_package_purls"] = affectedPurls
	content["affected_versions_map"] = affectedVersionsMap

	logger.Sugar().Debugf("Added denormalized version data for CVE %s: %d packages",
		content["_key"], len(affectedPurls))
}

// unpackAndLoad
func unpackAndLoad(src string) error {

	fmt.Println(src)
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer func() {
		if err := r.Close(); err != nil {
			panic(err)
		}
	}()

	// Closure to address file descriptors issue with all the deferred .Close() methods
	extractAndWriteFile := func(f *zip.File) error {

		// Check for ZipSlip: https://snyk.io/research/zip-slip-vulnerability
		if strings.Contains(f.Name, "/") {
			return fmt.Errorf("%s: illegal file path", f.Name)
		}

		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer func() {
			if err := rc.Close(); err != nil {
				panic(err)
			}
		}()

		if !f.FileInfo().IsDir() {
			var vulnJSON strings.Builder

			_, err = io.Copy(&vulnJSON, rc) // #nosec G110
			if err != nil {
				return err
			}

			var vulnIDMod vulnID
			var vulnStr = vulnJSON.String()
			if err := json.Unmarshal([]byte(vulnStr), &vulnIDMod); err != nil {
				logger.Sugar().Infoln(err)
			}

			// Add json to db
			if err := newVuln(vulnStr); err != nil {
				logger.Sugar().Infoln(err)
				logger.Sugar().Infoln(vulnStr)
			}
		}
		return nil
	}

	for _, f := range r.File {
		err := extractAndWriteFile(f)
		if err != nil {
			return err
		}
	}

	return nil
}

// LoadFromOSVDev retrieves the vulns from osv.dev and adds them to the Arangodb
func LoadFromOSVDev() {

	baseURL := "https://www.googleapis.com/download/storage/v1/b/osv-vulnerabilities/o/ecosystems.txt?alt=media"

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
			MinVersion:         tls.VersionTLS12,
		},
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Get(baseURL)
	if err != nil {
		logger.Sugar().Fatal(err)
	}

	// We Read the response body on the line below.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Sugar().Fatalln(err)
	}
	resp.Body.Close()

	// Convert the body to type string
	ecosystems := strings.Split(string(body), "\n")

	for _, platform := range ecosystems {
		if len(strings.TrimSpace(platform)) == 0 {
			continue
		}

		url := fmt.Sprintf("https://www.googleapis.com/download/storage/v1/b/osv-vulnerabilities/o/%s%%2Fall.zip?alt=media", url.PathEscape(platform))

		if resp, err := client.Get(url); err == nil {
			filename := fmt.Sprintf("%s.zip", platform)
			if out, err := os.Create(filename); err == nil {
				if _, err := io.Copy(out, resp.Body); err != nil {
					logger.Sugar().Infoln(err)
				}
				out.Close()
			} else {
				logger.Sugar().Infoln(err)
			}

			if err := unpackAndLoad(filename); err != nil {
				logger.Sugar().Infoln(err)
				logger.Sugar().Fatalln(filename)
			}
			os.Remove(filename)
			resp.Body.Close()
		} else {
			logger.Sugar().Infoln(err)
		}
	}
}

// newVuln godoc
// @Summary Create a Vulnerability
// @Description Create a new Vulnerability and persist it
// @Tags vulnerability
func newVuln(vulnJSON string) error {
	var existsCursor arangodb.Cursor
	var err error
	var ctx = context.Background()

	var content map[string]interface{}

	if err = json.Unmarshal([]byte(vulnJSON), &content); err != nil {
		logger.Sugar().Errorf("Failed to unmarshal vuln JSON: %v", err)
		return err
	}

	if id, ok := content["id"].(string); ok && id != "" {
		content["_key"] = strings.ReplaceAll(id, " ", "-")
	} else {
		logger.Sugar().Errorf("Document is missing a valid 'id' field to use as _key: %v", vulnJSON)
		return nil
	}

	parameters := map[string]interface{}{
		"key": content["_key"],
	}

	aql := `FOR vuln in cve
			FILTER vuln._key == @key
			RETURN vuln.modified`

	if existsCursor, err = dbconn.Database.Query(ctx, aql, &arangodb.QueryOptions{BindVars: parameters}); err != nil {
		logger.Sugar().Errorf("Failed to run query: %v", err)
	}

	defer existsCursor.Close()

	moddate := ""

	if existsCursor.HasMore() {
		if _, err = existsCursor.ReadDocument(ctx, &moddate); err != nil {
			logger.Sugar().Errorf("Failed to read document: %v", err)
		}
	}

	if content["modified"] == moddate {
		return nil
	}

	combinedJSON := vulnJSON

	if _, exists := content["affected"]; !exists {
		return nil
	}

	summary := ""
	details := ""

	if val, ok := content["summary"]; ok {
		if s, ok := val.(string); ok {
			summary = s
		}
	}

	if val, ok := content["details"]; ok {
		if d, ok := val.(string); ok {
			details = d
		}
	}

	cve := cveText{
		Description: summary + " " + details,
	}

	jsonData, err := json.Marshal(cve)
	if err != nil {
		logger.Sugar().Errorln("Error marshaling JSON:", err)
		return err
	}

	mitreURL := getMitreURL()

	if len(mitreURL) > 0 {
		// #nosec G107
		resp, err := http.Post(mitreURL, "application/json", bytes.NewBuffer(jsonData))
		if err == nil {
			defer resp.Body.Close()

			if resp.StatusCode == 200 {
				if body, err := io.ReadAll(resp.Body); err == nil {
					techniqueJSON := ", \"techniques\":" + string(body)
					lastBraceIndex := strings.LastIndex(vulnJSON, "}")
					if lastBraceIndex != -1 {
						combinedJSON = vulnJSON[:lastBraceIndex] + techniqueJSON + "}"
					}

					combinedJSON = strings.Replace(combinedJSON, "\"id\":", "\"_key\":", 1)
				}
			}
		} else {
			logger.Sugar().Errorln("Error sending POST request:", err)
		}
	}

	if err := json.Unmarshal([]byte(combinedJSON), &content); err != nil {
		logger.Sugar().Infoln(err)
	}

	key := content["_key"]

	if key == "" {
		logger.Sugar().Errorf("Document is missing a `_key` field for UPSERT: %v", content)
		return nil
	}

	// Add objtype field
	content["objtype"] = "CVE"

	// CRITICAL: Add calculated CVSS scores before storing
	addCVSSScoresToContent(content)

	// CRITICAL: Add denormalized version data for fast querying
	addDenormalizedVersionData(content)

	// UPSERT the CVE document
	query := `
		UPSERT { _key: @key }
		INSERT @doc
		UPDATE @doc
		IN cve
	`

	bindVars := map[string]interface{}{
		"key": key,
		"doc": content,
	}

	cursor, err := dbconn.Database.Query(ctx, query, &arangodb.QueryOptions{BindVars: bindVars})
	if err != nil {
		logger.Sugar().Errorf("AQL UPSERT failed for key '%s': %v", key, err)
		return err
	}
	cursor.Close()

	// Extract and process PURLs - use base PURLs (without version) for hub-and-spoke
	var basePurls []string
	if affected, ok := content["affected"].([]interface{}); ok {
		purlSet := make(map[string]bool) // Use map to ensure uniqueness

		for _, aff := range affected {
			if affMap, ok := aff.(map[string]interface{}); ok {
				if pkg, ok := affMap["package"].(map[string]interface{}); ok {
					// First try to get PURL directly from package
					if purlStr, ok := pkg["purl"].(string); ok && purlStr != "" {
						// Clean the PURL
						cleanedPurl, err := util.CleanPURL(purlStr)
						if err != nil {
							logger.Sugar().Warnf("Failed to parse PURL %s: %v", purlStr, err)
							continue
						}
						// Get base PURL (without version)
						basePurl, err := util.GetBasePURL(cleanedPurl)
						if err != nil {
							logger.Sugar().Warnf("Failed to get base PURL from %s: %v", cleanedPurl, err)
							continue
						}
						purlSet[basePurl] = true
					} else {
						// Construct PURL from ecosystem and name if purl field is missing
						if ecosystem, ok := pkg["ecosystem"].(string); ok {
							if name, ok := pkg["name"].(string); ok {
								purlType := util.EcosystemToPurlType(ecosystem)
								if purlType != "" {
									basePurl := fmt.Sprintf("pkg:%s/%s", purlType, name)
									purlSet[basePurl] = true
								}
							}
						}
					}
				}
			}
		}

		// Convert map to slice
		for purl := range purlSet {
			basePurls = append(basePurls, purl)
		}
	}

	// Only execute AQL if we have base PURLs
	if len(basePurls) > 0 {
		aql = `
			FOR purl IN @purls
				// Upsert the purl with objtype (using base PURL without version)
				LET upsertedPurl = FIRST(
					UPSERT { purl: purl }
					INSERT { purl: purl, objtype: "PURL" }
					UPDATE {} IN purl
					RETURN NEW
				)
				
				LET purlKey = upsertedPurl._key
				
				// Check for existing edge
				LET existingEdge = FIRST(
					FOR edge IN cve2purl
						FILTER edge._from == @cveId
						   AND edge._to == CONCAT("purl/", purlKey)
						RETURN edge
				)
				
				// Insert edge if it doesn't exist (CVE -> PURL)
				FILTER existingEdge == NULL
				INSERT { 
					_from: @cveId, 
					_to: CONCAT("purl/", purlKey) 
				} INTO cve2purl
		`

		parameters = map[string]interface{}{
			"purls": basePurls,
			"cveId": fmt.Sprintf("cve/%s", content["_key"]),
		}

		cursor, err = dbconn.Database.Query(ctx, aql, &arangodb.QueryOptions{BindVars: parameters})
		if err != nil {
			logger.Sugar().Errorf("Failed to execute PURL edge query: %v", err)
			return err
		}
		cursor.Close()
	}

	return nil
}

// @title Ortelius v12 OSV Loader
// @version 12.0.0
// @description Vulnerabilities from osv.dev
// @description ![Release](https://img.shields.io/github/v/release/ortelius/cve2release-tracker?sort=semver)
// @description ![license](https://img.shields.io/github/license/ortelius/.github)
// @description
// @description ![Build](https://img.shields.io/github/actions/workflow/status/ortelius/cve2release-tracker/build-push-chart.yml)
// @description [![MegaLinter](https://github.com/ortelius/cve2release-tracker/workflows/MegaLinter/badge.svg?branch=main)](https://github.com/ortelius/cve2release-tracker/actions?query=workflow%3AMegaLinter+branch%3Amain)
// @description ![CodeQL](https://github.com/ortelius/cve2release-tracker/workflows/CodeQL/badge.svg)
// @description [![OpenSSF-Scorecard](https://api.securityscorecards.dev/projects/github.com/ortelius/cve2release-tracker/badge)](https://api.securityscorecards.dev/projects/github.com/ortelius/cve2release-tracker)
// @description
// @description ![Discord](https://img.shields.io/discord/722468819091849316)

// @termsOfService http://swagger.io/terms/
// @contact.name Ortelius Google Group
// @contact.email ortelius-dev@googlegroups.com
// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html
// @host localhost:8080
func main() {
	LoadFromOSVDev()
}
