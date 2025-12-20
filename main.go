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
		util.SaveLastRun(dbconn, platform, maxSeenTime)
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

	util.AddCVSSScoresToContent(content)

	query := `UPSERT { _key: @key } INSERT @doc UPDATE @doc IN cve`
	bindVars := map[string]interface{}{"key": cveKey, "doc": content}

	if _, err := dbconn.Database.Query(ctx, query, &arangodb.QueryOptions{BindVars: bindVars}); err != nil {
		return false, err
	}

	// FIXED: Populate cve2purl Hub
	processEdges(ctx, content)

	return true, nil
}

func processEdges(ctx context.Context, content map[string]interface{}) error {
	type EdgeCandidate struct {
		BasePurl, Ecosystem                                     string
		IntroducedMajor, IntroducedMinor, IntroducedPatch       *int
		FixedMajor, FixedMinor, FixedPatch                      *int
		LastAffectedMajor, LastAffectedMinor, LastAffectedPatch *int
	}

	var edgeCandidates []EdgeCandidate
	uniqueBasePurls := make(map[string]bool)

	if affected, ok := content["affected"].([]interface{}); ok {
		for _, aff := range affected {
			var affectedData models.Affected
			affBytes, _ := json.Marshal(aff)
			json.Unmarshal(affBytes, &affectedData)

			var basePurl, ecosystem string
			if affMap, ok := aff.(map[string]interface{}); ok {
				if pkg, ok := affMap["package"].(map[string]interface{}); ok {
					if purlStr, ok := pkg["purl"].(string); ok && purlStr != "" {
						if cleanedPurl, err := util.CleanPURL(purlStr); err == nil {
							if bp, err := util.GetBasePURL(cleanedPurl); err == nil {
								basePurl = bp
								if parsed, err := util.ParsePURL(cleanedPurl); err == nil {
									ecosystem = parsed.Type
								}
							}
						}
					} else if eco, ok := pkg["ecosystem"].(string); ok {
						if name, ok := pkg["name"].(string); ok {
							if pt := util.EcosystemToPurlType(eco); pt != "" {
								basePurl = fmt.Sprintf("pkg:%s/%s", pt, name)
								ecosystem = pt
							}
						}
					}
				}
			}

			if basePurl == "" {
				continue
			}
			uniqueBasePurls[basePurl] = true

			for _, vrange := range affectedData.Ranges {
				if vrange.Type != models.RangeEcosystem && vrange.Type != models.RangeSemVer {
					continue
				}
				var introduced, fixed, lastAffected *util.ParsedVersion
				for _, event := range vrange.Events {
					if event.Introduced != "" {
						introduced = util.ParseSemanticVersion(event.Introduced)
					}
					if event.Fixed != "" {
						fixed = util.ParseSemanticVersion(event.Fixed)
					}
					if event.LastAffected != "" {
						lastAffected = util.ParseSemanticVersion(event.LastAffected)
					}
				}

				candidate := EdgeCandidate{BasePurl: basePurl, Ecosystem: ecosystem}
				if introduced != nil {
					candidate.IntroducedMajor, candidate.IntroducedMinor, candidate.IntroducedPatch = introduced.Major, introduced.Minor, introduced.Patch
				}
				if fixed != nil {
					candidate.FixedMajor, candidate.FixedMinor, candidate.FixedPatch = fixed.Major, fixed.Minor, fixed.Patch
				}
				if lastAffected != nil {
					candidate.LastAffectedMajor, candidate.LastAffectedMinor, candidate.LastAffectedPatch = lastAffected.Major, lastAffected.Minor, lastAffected.Patch
				}
				edgeCandidates = append(edgeCandidates, candidate)
			}
		}
	}

	if len(edgeCandidates) == 0 {
		return nil
	}

	var basePurls []string
	for p := range uniqueBasePurls {
		basePurls = append(basePurls, p)
	}

	// Bulk PURL Upsert with explicit _key
	purlAql := `
		FOR purl IN @purls
			LET key = @util.SanitizeKey(purl)
			LET upserted = FIRST(
				UPSERT { _key: key }
				INSERT { _key: key, purl: purl, objtype: "PURL" }
				UPDATE {} IN purl
				RETURN NEW
			)
			RETURN { purl: purl, key: upserted._key }
	`
	cursor, err := dbconn.Database.Query(ctx, purlAql, &arangodb.QueryOptions{BindVars: map[string]interface{}{"purls": basePurls}})
	if err != nil {
		return err
	}
	defer cursor.Close()

	purlKeyMap := make(map[string]string)
	for cursor.HasMore() {
		var res struct{ Purl, Key string }
		if _, err := cursor.ReadDocument(ctx, &res); err == nil {
			purlKeyMap[res.Purl] = res.Key
		}
	}

	var edges []map[string]interface{}
	for _, c := range edgeCandidates {
		if pKey, ok := purlKeyMap[c.BasePurl]; ok {
			edge := map[string]interface{}{
				"_from": fmt.Sprintf("cve/%s", content["_key"]),
				"_to":   fmt.Sprintf("purl/%s", pKey),
			}
			if c.Ecosystem != "" {
				edge["ecosystem"] = c.Ecosystem
			}
			if c.IntroducedMajor != nil {
				edge["introduced_major"] = *c.IntroducedMajor
			}
			if c.IntroducedMinor != nil {
				edge["introduced_minor"] = *c.IntroducedMinor
			}
			if c.IntroducedPatch != nil {
				edge["introduced_patch"] = *c.IntroducedPatch
			}
			if c.FixedMajor != nil {
				edge["fixed_major"] = *c.FixedMajor
			}
			if c.FixedMinor != nil {
				edge["fixed_minor"] = *c.FixedMinor
			}
			if c.FixedPatch != nil {
				edge["fixed_patch"] = *c.FixedPatch
			}
			if c.LastAffectedMajor != nil {
				edge["last_affected_major"] = *c.LastAffectedMajor
			}
			if c.LastAffectedMinor != nil {
				edge["last_affected_minor"] = *c.LastAffectedMinor
			}
			if c.LastAffectedPatch != nil {
				edge["last_affected_patch"] = *c.LastAffectedPatch
			}
			edges = append(edges, edge)
		}
	}

	if len(edges) > 0 {
		delQ := `FOR edge IN cve2purl FILTER edge._from == @cveId REMOVE edge IN cve2purl`
		dbconn.Database.Query(ctx, delQ, &arangodb.QueryOptions{BindVars: map[string]interface{}{"cveId": fmt.Sprintf("cve/%s", content["_key"])}})
		insQ := `FOR edge IN @edges INSERT edge INTO cve2purl`
		dbconn.Database.Query(ctx, insQ, &arangodb.QueryOptions{BindVars: map[string]interface{}{"edges": edges}})
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
