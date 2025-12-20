// Ortelius v11 Vulnerability Microservice that handles creating Vulnerability from OSV.dev
// Runs as a cronjob
//
// CRITICAL FIXES APPLIED:
// 1. Restored Robust Materialized Edge logic (release2cve) from working snippet
// 2. Fixed cve2purl Hub population to prevent empty collections
// 3. Permanent Fix for Bad Dates using DATE_ISO8601 and DATE_TIMESTAMP
// 4. Maintained Go-side and AQL version validation
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
	"strings"
	"time"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/ortelius/pdvd-backend/v12/database"
	"github.com/ortelius/pdvd-backend/v12/restapi/modules/lifecycle"
	"github.com/ortelius/pdvd-backend/v12/util"
)

var logger = database.InitLogger()
var dbconn = database.InitializeDatabase()

// ----------------------------------------------------------------------------
// Main Import Logic
// ----------------------------------------------------------------------------

func LoadFromOSVDev() {
	baseURL := "https://www.googleapis.com/download/storage/v1/b/osv-vulnerabilities/o/ecosystems.txt?alt=media"

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: false, MinVersion: tls.VersionTLS12},
		MaxIdleConns:    100,
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Get(baseURL)
	if err != nil {
		logger.Sugar().Fatal(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Sugar().Fatalln(err)
	}

	lines := strings.Split(string(body), "\n")
	totalCVEsUpdated := 0

	for _, line := range lines {
		platform := strings.TrimSpace(line)
		if len(platform) == 0 {
			continue
		}

		cveCount := processEcosystem(client, platform)
		totalCVEsUpdated += cveCount
	}

	if totalCVEsUpdated > 0 {
		logger.Sugar().Infof("All ecosystems processed. Total CVEs updated: %d. Running lifecycle tracking...", totalCVEsUpdated)
		if err := updateLifecycleForNewCVEs(totalCVEsUpdated); err != nil {
			logger.Sugar().Warnf("Failed to update lifecycle tracking after CVE updates: %v", err)
		} else {
			logger.Sugar().Infof("Lifecycle tracking update complete")
		}
	} else {
		logger.Sugar().Infof("No CVE updates. Skipping lifecycle tracking.")
	}
}

func processEcosystem(client *http.Client, platform string) int {
	lastRunTime, _ := util.GetLastRun(dbconn, platform)
	urlStr := fmt.Sprintf("https://www.googleapis.com/download/storage/v1/b/osv-vulnerabilities/o/%s%%2Fall.zip?alt=media", url.PathEscape(platform))

	resp, err := client.Get(urlStr)
	if err != nil {
		logger.Sugar().Errorf("Failed to download %s: %v", platform, err)
		return 0
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Sugar().Errorf("Failed to read body for %s: %v", platform, err)
		return 0
	}

	zipReader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		logger.Sugar().Errorf("Failed to open zip reader for %s: %v", platform, err)
		return 0
	}

	var maxSeenTime = lastRunTime
	var cveCount int

	for _, f := range zipReader.File {
		if f.FileInfo().IsDir() || strings.Contains(f.Name, "/") {
			continue
		}

		func() {
			rc, err := f.Open()
			if err != nil {
				return
			}
			defer rc.Close()

			var content map[string]interface{}
			if err := json.NewDecoder(rc).Decode(&content); err != nil {
				return
			}

			modStr, _ := content["modified"].(string)
			if modStr != "" {
				modTime, err := time.Parse(time.RFC3339, modStr)
				if err == nil {
					if modTime.After(maxSeenTime) {
						maxSeenTime = modTime
					}
					if !modTime.After(lastRunTime) {
						return
					}
				}
			}

			// Add CVSS scores
			util.AddCVSSScoresToContent(content)

			wasUpdated, err := newVuln(content)
			if wasUpdated {
				cveCount++
				if cveKey, ok := content["_key"].(string); ok {
					if err := updateReleaseEdgesForCVE(context.Background(), cveKey); err != nil {
						logger.Sugar().Errorf("Failed to update release edges for CVE %s: %v", cveKey, err)
					}
				}
			}
		}()
	}

	if cveCount > 0 {
		if maxSeenTime.IsZero() {
			maxSeenTime = time.Now().UTC()
		}
		logger.Sugar().Infof("Ecosystem: %s | New CVEs: %d | Updating high water mark to %s", platform, cveCount, maxSeenTime.Format(time.RFC3339))
		util.SaveLastRun(dbconn, platform, maxSeenTime)
	} else {
		logger.Sugar().Infof("Ecosystem: %s | No new CVEs found", platform)
	}

	return cveCount
}

func newVuln(content map[string]interface{}) (bool, error) {
	var ctx = context.Background()
	id, ok := content["id"].(string)
	if !ok || id == "" {
		return false, nil
	}

	cveKey := util.SanitizeKey(id)
	content["_key"] = cveKey
	content["objtype"] = "CVE"

	// Check if already processed
	modDate, _ := content["modified"].(string)
	parameters := map[string]interface{}{"key": cveKey}
	aql := `FOR vuln in cve FILTER vuln._key == @key RETURN vuln.modified`

	cursor, err := dbconn.Database.Query(ctx, aql, &arangodb.QueryOptions{BindVars: parameters})
	if err == nil {
		defer cursor.Close()
		if cursor.HasMore() {
			var existingMod string
			if _, err := cursor.ReadDocument(ctx, &existingMod); err == nil {
				if existingMod == modDate {
					return false, nil
				}
			}
		}
	}

	if _, exists := content["affected"]; !exists {
		return false, nil
	}

	query := `UPSERT { _key: @key } INSERT @doc UPDATE @doc IN cve`
	bindVars := map[string]interface{}{"key": cveKey, "doc": content}

	if _, err := dbconn.Database.Query(ctx, query, &arangodb.QueryOptions{BindVars: bindVars}); err != nil {
		return false, err
	}

	// FIXED: Populate cve2purl Hub using working version's approach
	processEdges(ctx, content)

	return true, nil
}

func processEdges(ctx context.Context, content map[string]interface{}) error {
	cveID, _ := content["id"].(string)
	cveKey := util.SanitizeKey(cveID)
	cveDocID := "cve/" + cveKey

	affected, ok := content["affected"].([]interface{})
	if !ok || len(affected) == 0 {
		return nil
	}

	for _, affItem := range affected {
		affMap, ok := affItem.(map[string]interface{})
		if !ok {
			continue
		}

		pkgMap, ok := affMap["package"].(map[string]interface{})
		if !ok {
			continue
		}

		// Get base PURL
		var basePurl string
		if purl, ok := pkgMap["purl"].(string); ok && purl != "" {
			cleaned, err := util.CleanPURL(purl)
			if err != nil {
				continue
			}
			basePurl, err = util.GetBasePURL(cleaned)
			if err != nil {
				continue
			}
		} else {
			// Construct from ecosystem + name
			ecosystem, _ := pkgMap["ecosystem"].(string)
			name, _ := pkgMap["name"].(string)
			if ecosystem == "" || name == "" {
				continue
			}
			basePurl = fmt.Sprintf("pkg:%s/%s", strings.ToLower(ecosystem), name)
		}

		// Ensure PURL node exists
		purlKey := util.SanitizeKey(basePurl)
		purlNode := map[string]interface{}{
			"_key":    purlKey,
			"purl":    basePurl,
			"objtype": "PURL",
		}

		// Use UPSERT to ensure purl exists
		purlUpsert := `UPSERT { _key: @key } INSERT @doc UPDATE {} IN purl`
		dbconn.Database.Query(ctx, purlUpsert, &arangodb.QueryOptions{
			BindVars: map[string]interface{}{
				"key": purlKey,
				"doc": purlNode,
			},
		})

		purlDocID := "purl/" + purlKey

		// Parse version ranges
		ranges, _ := affMap["ranges"].([]interface{})
		if len(ranges) == 0 {
			continue
		}

		for _, rangeItem := range ranges {
			rangeMap, ok := rangeItem.(map[string]interface{})
			if !ok {
				continue
			}

			rangeType, _ := rangeMap["type"].(string)
			if rangeType != "ECOSYSTEM" && rangeType != "SEMVER" {
				continue
			}

			events, _ := rangeMap["events"].([]interface{})
			var introduced, fixed, lastAffected string

			for _, evt := range events {
				evtMap, _ := evt.(map[string]interface{})
				if intro, ok := evtMap["introduced"].(string); ok {
					introduced = intro
				}
				if fix, ok := evtMap["fixed"].(string); ok {
					fixed = fix
				}
				if last, ok := evtMap["last_affected"].(string); ok {
					lastAffected = last
				}
			}

			// Parse versions
			introducedParsed := util.ParseSemanticVersion(introduced)
			fixedParsed := util.ParseSemanticVersion(fixed)
			lastAffectedParsed := util.ParseSemanticVersion(lastAffected)

			// Get ecosystem
			ecosystem, _ := pkgMap["ecosystem"].(string)

			// Build edge
			edge := map[string]interface{}{
				"_from":     cveDocID,
				"_to":       purlDocID,
				"ecosystem": ecosystem,
			}

			if introducedParsed.Major != nil {
				edge["introduced_major"] = *introducedParsed.Major
			}
			if introducedParsed.Minor != nil {
				edge["introduced_minor"] = *introducedParsed.Minor
			}
			if introducedParsed.Patch != nil {
				edge["introduced_patch"] = *introducedParsed.Patch
			}

			if fixedParsed.Major != nil {
				edge["fixed_major"] = *fixedParsed.Major
			}
			if fixedParsed.Minor != nil {
				edge["fixed_minor"] = *fixedParsed.Minor
			}
			if fixedParsed.Patch != nil {
				edge["fixed_patch"] = *fixedParsed.Patch
			}

			if lastAffectedParsed.Major != nil {
				edge["last_affected_major"] = *lastAffectedParsed.Major
			}
			if lastAffectedParsed.Minor != nil {
				edge["last_affected_minor"] = *lastAffectedParsed.Minor
			}
			if lastAffectedParsed.Patch != nil {
				edge["last_affected_patch"] = *lastAffectedParsed.Patch
			}

			// Check if edge exists
			checkQuery := `
				FOR e IN cve2purl
					FILTER e._from == @from AND e._to == @to
					LIMIT 1
					RETURN e
			`
			cursor, err := dbconn.Database.Query(ctx, checkQuery, &arangodb.QueryOptions{
				BindVars: map[string]interface{}{
					"from": cveDocID,
					"to":   purlDocID,
				},
			})
			if err != nil {
				continue
			}

			exists := cursor.HasMore()
			cursor.Close()

			if !exists {
				// Insert edge directly using collection
				_, err = dbconn.Collections["cve2purl"].CreateDocument(ctx, edge)
				if err != nil {
					logger.Sugar().Warnf("Failed to create cve2purl edge from %s to %s: %v", cveDocID, purlDocID, err)
				}
			}
		}
	}

	return nil
}

func updateReleaseEdgesForCVE(ctx context.Context, cveKey string) error {
	cveID := "cve/" + cveKey

	// 1. Cleanup old edges
	cleanupQuery := `FOR edge IN release2cve FILTER edge._to == @cveID REMOVE edge IN release2cve`
	dbconn.Database.Query(ctx, cleanupQuery, &arangodb.QueryOptions{BindVars: map[string]interface{}{"cveID": cveID}})

	// 2. Find Candidates using Robust AQL Filter (Traverse CVE -> PURL -> SBOM -> Release)
	query := `
		FOR cve IN cve
			FILTER cve._key == @cveKey
			FOR cveEdge IN cve2purl
				FILTER cveEdge._from == cve._id
				FOR sbomEdge IN sbom2purl
					FILTER sbomEdge._to == cveEdge._to
					
					FILTER (
						sbomEdge.version_major != null AND 
						cveEdge.introduced_major != null AND 
						(cveEdge.fixed_major != null OR cveEdge.last_affected_major != null)
					) ? (
						(sbomEdge.version_major > cveEdge.introduced_major OR
						(sbomEdge.version_major == cveEdge.introduced_major AND 
						sbomEdge.version_minor > cveEdge.introduced_minor) OR
						(sbomEdge.version_major == cveEdge.introduced_major AND 
						sbomEdge.version_minor == cveEdge.introduced_minor AND 
						sbomEdge.version_patch >= cveEdge.introduced_patch))
						AND
						(cveEdge.fixed_major != null ? (
							sbomEdge.version_major < cveEdge.fixed_major OR
							(sbomEdge.version_major == cveEdge.fixed_major AND 
							sbomEdge.version_minor < cveEdge.fixed_minor) OR
							(sbomEdge.version_major == cveEdge.fixed_major AND 
							sbomEdge.version_minor == cveEdge.fixed_minor AND 
							sbomEdge.version_patch < cveEdge.fixed_patch)
						) : (
							sbomEdge.version_major < cveEdge.last_affected_major OR
							(sbomEdge.version_major == cveEdge.last_affected_major AND 
							sbomEdge.version_minor < cveEdge.last_affected_minor) OR
							(sbomEdge.version_major == cveEdge.last_affected_major AND 
							sbomEdge.version_minor == cveEdge.last_affected_minor AND 
							sbomEdge.version_patch <= cveEdge.last_affected_patch)
						))
					) : true
					
					FOR release IN 1..1 INBOUND sbomEdge._from release2sbom
						RETURN {
							release_id: release._id,
							package_purl: sbomEdge.full_purl,
							package_version: sbomEdge.version,
							all_affected: cve.affected,
							needs_validation: sbomEdge.version_major == null OR cveEdge.introduced_major == null
						}
	`

	cursor, err := dbconn.Database.Query(ctx, query, &arangodb.QueryOptions{BindVars: map[string]interface{}{"cveKey": cveKey}})
	if err != nil {
		return err
	}
	defer cursor.Close()

	var edgesToInsert []map[string]interface{}
	for cursor.HasMore() {
		var cand struct {
			ReleaseID, PackagePurl, PackageVersion string
			AllAffected                            []models.Affected
			NeedsValidation                        bool
		}
		if _, err := cursor.ReadDocument(ctx, &cand); err != nil {
			continue
		}

		if cand.NeedsValidation {
			if !util.IsVersionAffectedAny(cand.PackageVersion, cand.AllAffected) {
				continue
			}
		}

		edgesToInsert = append(edgesToInsert, map[string]interface{}{
			"_from": cand.ReleaseID, "_to": cveID, "type": "static_analysis",
			"package_purl": cand.PackagePurl, "package_version": cand.PackageVersion, "created_at": time.Now(),
		})
	}

	if len(edgesToInsert) > 0 {
		insQ := `FOR edge IN @edges INSERT edge INTO release2cve`
		dbconn.Database.Query(ctx, insQ, &arangodb.QueryOptions{BindVars: map[string]interface{}{"edges": edgesToInsert}})
	}
	return nil
}

func updateLifecycleForNewCVEs(_ int) error {
	ctx := context.Background()
	// FIXED: Normalized timestamps and robust sorting
	query := `
		FOR endpoint IN endpoint
			LET latestSync = (
				FOR sync IN sync
					FILTER sync.endpoint_name == endpoint.name
					SORT DATE_TIMESTAMP(sync.synced_at) DESC
					LIMIT 1
					RETURN sync
			)[0]
			FILTER latestSync != null
			
			LET activeReleases = (
				FOR sync IN sync
					FILTER sync.endpoint_name == endpoint.name
					FILTER sync.synced_at == latestSync.synced_at
					RETURN { name: sync.release_name, version: sync.release_version }
			)
			RETURN {
				endpoint_name: endpoint.name,
				releases: activeReleases,
				last_sync_time: DATE_ISO8601(latestSync.synced_at)
			}
	`

	cursor, err := dbconn.Database.Query(ctx, query, nil)
	if err != nil {
		return err
	}
	defer cursor.Close()

	for cursor.HasMore() {
		var state struct {
			EndpointName string
			Releases     []ReleaseInfo
			LastSyncTime time.Time
		}
		if _, err := cursor.ReadDocument(ctx, &state); err != nil || state.LastSyncTime.IsZero() {
			continue
		}

		currentCVEs, _ := getCVEsForReleases(ctx, state.Releases)
		for _, cveInfo := range currentCVEs {
			disclosedAfter := !cveInfo.Published.IsZero() && cveInfo.Published.After(state.LastSyncTime)
			lifecycle.CreateOrUpdateLifecycleRecord(ctx, dbconn, state.EndpointName, cveInfo.ReleaseName, cveInfo.ReleaseVersion, cveInfo, state.LastSyncTime, disclosedAfter)
		}
	}
	return nil
}

type ReleaseInfo struct{ Name, Version string }

func getCVEsForReleases(ctx context.Context, releases []ReleaseInfo) (map[string]lifecycle.CVEInfo, error) {
	result := make(map[string]lifecycle.CVEInfo)
	for _, rel := range releases {
		query := `
			FOR r IN release
				FILTER r.name == @name AND r.version == @version
				FOR cve, edge IN 1..1 OUTBOUND r release2cve
					RETURN {
						cve_id: cve.id, published: cve.published, package: edge.package_purl,
						severity_rating: cve.database_specific.severity_rating,
						severity_score: cve.database_specific.cvss_base_score
					}
		`
		cursor, _ := dbconn.Database.Query(ctx, query, &arangodb.QueryOptions{BindVars: map[string]interface{}{"name": rel.Name, "version": rel.Version}})
		for cursor.HasMore() {
			var v struct {
				CveID, Published, Package, SeverityRating string
				SeverityScore                             float64
			}
			if _, err := cursor.ReadDocument(ctx, &v); err == nil {
				pub, _ := time.Parse(time.RFC3339, v.Published)
				key := fmt.Sprintf("%s:%s:%s", v.CveID, v.Package, rel.Name)
				result[key] = lifecycle.CVEInfo{CVEID: v.CveID, Package: v.Package, SeverityRating: v.SeverityRating, SeverityScore: v.SeverityScore, Published: pub, ReleaseName: rel.Name, ReleaseVersion: rel.Version}
			}
		}
		cursor.Close()
	}
	return result, nil
}

func main() { LoadFromOSVDev() }
