package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/fatih/color"
	"gopkg.in/ini.v1"
)

const (
	// Default values for SSO configuration
	defaultSSOSessionConfigName = "default"
	defaultSSORegion            = "us-east-1"
)

// Configuration variables populated by flags
var (
	ssoRoleNames         []string
	profilePrefix        string
	useAutoPrefix        bool
	ssoStartURL          string
	ssoSessionConfigName string
	ssoRegion            string
	ssoConfigFile        string
	dryRun               bool
	openBrowser          bool
	profileOutput        string
)

// Custom flag type for multiple strings
type stringSliceFlag []string

func (s *stringSliceFlag) String() string {
	return strings.Join(*s, ",")
}

func (s *stringSliceFlag) Set(value string) error {
	*s = append(*s, value)
	return nil
}

var (
	green  = color.New(color.FgGreen).SprintFunc()
	yellow = color.New(color.FgYellow).SprintFunc()
	cyan   = color.New(color.FgCyan).SprintFunc()
	red    = color.New(color.FgRed).SprintFunc()
	bold   = color.New(color.Bold).SprintFunc()
)

// Injectable hooks for easier testing
var (
	// runAwsSsoLogin performs the interactive SSO OIDC device authorization
	// flow using the AWS SDK (no shell-out). Tests can override this to avoid
	// actually contacting AWS.
	runAwsSsoLogin = func(session string) error {
		// Use sso-oidc for device authorization
		cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(ssoRegion))
		if err != nil {
			return err
		}
		client := ssooidc.NewFromConfig(cfg)

		// Register a client for the device authorization flow
		regIn := &ssooidc.RegisterClientInput{
			ClientName: aws.String("aws-sso-profile-sync"),
			ClientType: aws.String("public"),
		}
		regOut, err := client.RegisterClient(context.TODO(), regIn)
		if err != nil {
			return err
		}

		// Start device authorization
		devIn := &ssooidc.StartDeviceAuthorizationInput{
			ClientId:     regOut.ClientId,
			ClientSecret: regOut.ClientSecret,
			StartUrl:     aws.String(strings.TrimRight(ssoStartURL, "/")),
		}
		devOut, err := client.StartDeviceAuthorization(context.TODO(), devIn)
		if err != nil {
			return err
		}

		// Show the verification URL and optionally open it in the default
		// browser when the user passed --open. If --open is set we do not
		// require the user to press Enter; polling starts immediately.
		verificationURL := aws.ToString(devOut.VerificationUriComplete)
		userCode := aws.ToString(devOut.UserCode)
		if openBrowser {
			// Attempt to open the URL in the default browser; fall back to
			// printing the URL if this fails.
			if err := openBrowserURL(verificationURL); err != nil {
				fmt.Printf("%s Failed to open browser automatically, please open this URL manually:\n%s\n", yellow("⚠️"), verificationURL)
				fmt.Printf("And enter this code if prompted: %s\n", userCode)
			} else {
				fmt.Printf("%s Opened default browser to: %s\n", cyan("🔗"), verificationURL)
				fmt.Printf("If prompted, enter this code: %s\n", userCode)
			}
		} else {
			// Do not open the browser for the user; show the URL and proceed
			// immediately to polling. This avoids blocking on an Enter press
			// and works well in non-interactive or scripted environments.
			fmt.Printf("To authenticate, open this URL in your browser:\n%s\nAnd enter this code if prompted: %s\n", verificationURL, userCode)
			fmt.Printf("Starting background polling for authorization; open the URL to complete authorization.\n")
		}

		// Poll for token
		interval := int64(5)
		if devOut.Interval > 0 {
			interval = int64(devOut.Interval)
		}
		deadline := time.Now().Add(time.Duration(devOut.ExpiresIn) * time.Second)
		var tokenOut *ssooidc.CreateTokenOutput
		for time.Now().Before(deadline) {
			tokIn := &ssooidc.CreateTokenInput{
				ClientId:     regOut.ClientId,
				ClientSecret: regOut.ClientSecret,
				GrantType:    aws.String("urn:ietf:params:oauth:grant-type:device_code"),
				DeviceCode:   devOut.DeviceCode,
			}
			tokenOut, err = client.CreateToken(context.TODO(), tokIn)
			if err == nil {
				break
			}
			// Check for authorization pending or slow down; if so, wait and retry
			// Fallback: examine error string for common tokens
			es := err.Error()
			if strings.Contains(es, "authorization_pending") || strings.Contains(es, "AuthorizationPending") || strings.Contains(es, "slow_down") || strings.Contains(es, "SlowDown") {
				time.Sleep(time.Duration(interval) * time.Second)
				continue
			}
			return err
		}
		if tokenOut == nil || tokenOut.AccessToken == nil {
			return fmt.Errorf("failed to obtain access token via device authorization")
		}

		// Build the cache file and write it under ~/.aws/sso/cache
		homeDir, _ := os.UserHomeDir()
		cacheDir := filepath.Join(homeDir, ".aws", "sso", "cache")
		if err := os.MkdirAll(cacheDir, 0o700); err != nil {
			return err
		}

		// Create a simple temporary filename using timestamp to avoid
		// overengineering token compatibility with the AWS CLI. This keeps
		// behavior local to this tool and avoids creating multiple session
		// name symlinks or deterministic hashed filenames.
		ts := time.Now().UnixNano()
		filename := fmt.Sprintf("sso_token_%d.json", ts)
		outPath := filepath.Join(cacheDir, filename)

		expiresAt := time.Now().Add(time.Duration(tokenOut.ExpiresIn) * time.Second).UTC().Format(time.RFC3339)
		m := map[string]interface{}{
			"startUrl":    strings.TrimRight(ssoStartURL, "/"),
			"region":      ssoRegion,
			"accessToken": aws.ToString(tokenOut.AccessToken),
			"expiresAt":   expiresAt,
		}

		b, err := json.MarshalIndent(m, "", "  ")
		if err != nil {
			return err
		}

		// Write atomically: write to a temp file then rename.
		tmpPath := outPath + ".tmp"
		if err := os.WriteFile(tmpPath, b, 0o600); err != nil {
			return err
		}
		if err := os.Rename(tmpPath, outPath); err != nil {
			// Best-effort cleanup if rename fails
			_ = os.Remove(tmpPath)
			return err
		}

		return nil
	}

	// getAccessTokenFunc is an indirection to fetch the SSO access token from
	// the local SSO cache. Tests can override this to simulate token presence
	// or absence.
	getAccessTokenFunc = func() (string, string, error) {
		return getAccessTokenFromSsoSessionWithPath()
	}

	// isSsoTokenValidFunc allows tests to stub token validation without
	// calling AWS. By default it calls the real discovery function.
	isSsoTokenValidFunc = func(accessToken string) bool {
		_, err := getListOfSsoAccounts(accessToken)
		return err == nil
	}

	// Allow configureSsoProfiles to be stubbed in tests to avoid AWS calls.
	configureSsoProfilesFunc = func(accessToken string) error { return configureSsoProfiles(accessToken) }
)

// Get the newest valid SSO access token and its file path
func getAccessTokenFromSsoSessionWithPath() (string, string, error) {
	homeDir, _ := os.UserHomeDir()
	ssoCacheDir := filepath.Join(homeDir, ".aws", "sso", "cache")
	files, err := os.ReadDir(ssoCacheDir)
	if err != nil {
		return "", "", err
	}
	type candidate struct {
		path     string
		startUrl string
		token    string
		modTime  int64
	}
	var candidates []candidate
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".json") {
			fullPath := filepath.Join(ssoCacheDir, f.Name())
			data, err := os.ReadFile(fullPath)
			if err != nil {
				continue
			}
			var cache map[string]interface{}
			if err := json.Unmarshal(data, &cache); err != nil {
				continue
			}
			startUrl, ok := cache["startUrl"].(string)
			accessToken, tokenOk := cache["accessToken"].(string)
			if ok && (startUrl == ssoStartURL || startUrl == strings.TrimRight(ssoStartURL, "/")) && tokenOk {
				info, err := f.Info()
				if err != nil {
					continue
				}
				modTime := info.ModTime().Unix()
				candidates = append(candidates, candidate{
					path:     fullPath,
					startUrl: startUrl,
					token:    accessToken,
					modTime:  modTime,
				})
			}
		}
	}
	if len(candidates) == 0 {
		return "", "", fmt.Errorf("no valid SSO accessToken found for startUrl %s", ssoStartURL)
	}
	latest := candidates[0]
	for _, c := range candidates {
		if c.modTime > latest.modTime {
			latest = c
		}
	}
	return latest.token, latest.path, nil
}

type ssoTypesAccount struct {
	AccountId   string
	AccountName string
}

type ssoTypesRole struct {
	RoleName string
}

type CombinedRole struct {
	AccountId   string
	RoleName    string
	AccountName string
}

// Get all accounts for the SSO session
func getListOfSsoAccounts(accessToken string) ([]ssoTypesAccount, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(ssoRegion))
	if err != nil {
		return nil, err
	}
	client := sso.NewFromConfig(cfg)
	input := &sso.ListAccountsInput{
		AccessToken: aws.String(accessToken),
		MaxResults:  aws.Int32(100),
	}
	var accounts []ssoTypesAccount
	paginator := sso.NewListAccountsPaginator(client, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.TODO())
		if err != nil {
			return nil, err
		}
		for _, acct := range page.AccountList {
			accounts = append(accounts, ssoTypesAccount{
				AccountId:   aws.ToString(acct.AccountId),
				AccountName: aws.ToString(acct.AccountName),
			})
		}
	}
	return accounts, nil
}

// Get all roles for a given account
func getListOfSsoAccountRolesForAccount(accessToken, accountId string) ([]ssoTypesRole, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(ssoRegion))
	if err != nil {
		return nil, err
	}
	client := sso.NewFromConfig(cfg)
	input := &sso.ListAccountRolesInput{
		AccessToken: aws.String(accessToken),
		AccountId:   aws.String(accountId),
		MaxResults:  aws.Int32(100),
	}
	var roles []ssoTypesRole
	paginator := sso.NewListAccountRolesPaginator(client, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.TODO())
		if err != nil {
			return nil, err
		}
		for _, role := range page.RoleList {
			roles = append(roles, ssoTypesRole{
				RoleName: aws.ToString(role.RoleName),
			})
		}
	}
	return roles, nil
}

// Get all accounts with any of the desired roles
func getCombinedListOfSsoAccountsAndRoles(accessToken string, roleNames []string) ([]CombinedRole, error) {
	accounts, err := getListOfSsoAccounts(accessToken)
	if err != nil {
		return nil, err
	}

	// Create a map for fast role lookup
	roleMap := make(map[string]bool)
	for _, roleName := range roleNames {
		roleMap[roleName] = true
	}

	var combined []CombinedRole
	for _, account := range accounts {
		roles, err := getListOfSsoAccountRolesForAccount(accessToken, account.AccountId)
		if err != nil {
			return nil, err
		}
		for _, role := range roles {
			if roleMap[role.RoleName] {
				combined = append(combined, CombinedRole{
					AccountId:   account.AccountId,
					RoleName:    role.RoleName,
					AccountName: account.AccountName,
				})
			}
		}
	}
	return combined, nil
}

// listAllRolesPerAccount prints all roles available per account (used in dry-run)
func listAllRolesPerAccount(accessToken string) error {
	accounts, err := getListOfSsoAccounts(accessToken)
	if err != nil {
		return err
	}
	for _, account := range accounts {
		roles, err := getListOfSsoAccountRolesForAccount(accessToken, account.AccountId)
		if err != nil {
			return err
		}
		// Collect raw role names and sort them so output is deterministic
		var raw []string
		for _, r := range roles {
			raw = append(raw, r.RoleName)
		}
		if len(raw) == 0 {
			fmt.Printf("    %s %s: (no roles)\n", cyan("🔐"), account.AccountName)
			continue
		}
		// Sort alphabetically
		sort.Strings(raw)

		// Build display strings, highlighting any roles that were requested
		wanted := make(map[string]bool)
		for _, w := range ssoRoleNames {
			wanted[w] = true
		}
		var display []string
		for _, name := range raw {
			if wanted[name] {
				display = append(display, green(bold(name)))
			} else {
				display = append(display, name)
			}
		}
		fmt.Printf("    %s %s: %s\n", cyan("🔐"), account.AccountName, strings.Join(display, ", "))
	}
	return nil
}

// Generate profile prefix from role name by stripping AWS and Access
func generatePrefixFromRole(roleName string) string {
	// Remove "AWS" prefix and "Access" suffix, then add underscore
	cleaned := strings.TrimPrefix(roleName, "AWS")
	cleaned = strings.TrimSuffix(cleaned, "Access")

	if cleaned != "" {
		return cleaned + "_"
	}
	return ""
}

// Format profile name
func getProfileNameFromRole(role CombinedRole) string {
	re := regexp.MustCompile(`[_\s]+`)
	safeAccountName := re.ReplaceAllString(role.AccountName, "-")

	// Determine the prefix to use
	var prefix string
	if profilePrefix != "" {
		// Use custom prefix if provided
		prefix = profilePrefix
	} else if useAutoPrefix {
		// Auto-generate prefix from role name
		prefix = generatePrefixFromRole(role.RoleName)
	}
	// If prefix is empty (either by choice or no auto-prefix), use no prefix

	if prefix != "" {
		return fmt.Sprintf("%s%s_%s", prefix, safeAccountName, role.AccountId)
	}
	return fmt.Sprintf("%s_%s", safeAccountName, role.AccountId)
}

// Ensure SSO session config block is present in ~/.aws/config
func ensureSsoSessionConfigPresent() (bool, error) {
	awsConfigPath := ssoConfigFile
	sessionHeader := fmt.Sprintf("[sso-session %s]", ssoSessionConfigName)
	sessionBlock := fmt.Sprintf(
		`[sso-session %s]
sso_start_url = %s
sso_region = %s
sso_registration_scopes = sso:account:access
`, ssoSessionConfigName, strings.TrimRight(ssoStartURL, "/"), ssoRegion)

	// Read the config file if it exists. If it doesn't exist, we'll create
	// a new one below.
	data, err := os.ReadFile(awsConfigPath)
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}

	// If the exact named session header already exists, nothing to do.
	if strings.Contains(string(data), sessionHeader) {
		return false, nil // Already present
	}

	// If the caller didn't explicitly set a session name (i.e. we're using
	// the default), check whether the config already contains an sso-session
	// with the same startUrl and region. If exactly one match exists, reuse
	// it instead of adding a new block. If multiple matches exist, return an
	// error and ask the user to disambiguate.
	if ssoSessionConfigName == defaultSSOSessionConfigName || ssoSessionConfigName == "" {
		// Only attempt to discover matches if the config file exists; if it
		// doesn't exist, findAllMatchingSsoSessionNames would fail.
		if _, statErr := os.Stat(awsConfigPath); statErr == nil {
			if matches, mErr := findAllMatchingSsoSessionNames(ssoStartURL, ssoRegion, awsConfigPath); mErr == nil {
				if len(matches) == 1 {
					// Reuse the existing session name instead of creating a new
					// default block.
					ssoSessionConfigName = matches[0]
					if dryRun {
						fmt.Printf("    %s Would reuse existing SSO session configuration: %s\n", cyan("📝"), bold(ssoSessionConfigName))
					}
					return false, nil
				} else if len(matches) > 1 {
					return false, fmt.Errorf("multiple matching sso-session blocks found for startUrl %s and region %s", ssoStartURL, ssoRegion)
				}
			}
		}
	}

	if dryRun {
		// In dry-run mode, show what would be written
		fmt.Printf("    %s Would add SSO session configuration:\n", cyan("📝"))
		printBlockIndented("      ", sessionBlock)
		return true, nil // Pretend it would be added
	}

	needsNewline := len(data) > 0 && data[len(data)-1] != '\n'
	toWrite := sessionBlock
	if needsNewline {
		toWrite = "\n" + sessionBlock
	}
	f, err := os.OpenFile(awsConfigPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return false, err
	}
	defer f.Close()
	if _, err := f.WriteString(toWrite); err != nil {
		return false, err
	}
	return true, nil // Added
}

// findMatchingSsoSessionName looks for an existing [sso-session <name>] in the
// AWS config file whose sso_start_url and sso_region match the provided values.
// If found it returns the session name and true, otherwise "" and false.
func findMatchingSsoSessionName(startURL, region, configPath string) (string, bool) {
	// Normalize startURL for comparison (no trailing slash)
	normStart := strings.TrimRight(startURL, "/")

	// Load the config file; if it doesn't exist, nothing to match
	cfg, err := ini.Load(configPath)
	if err != nil {
		return "", false
	}

	for _, section := range cfg.Sections() {
		name := section.Name()
		// Look for sections named like "sso-session <name>"
		if strings.HasPrefix(name, "sso-session ") {
			// Read keys
			ssoStart := strings.TrimRight(section.Key("sso_start_url").String(), "/")
			ssoRegion := section.Key("sso_region").String()
			if ssoStart == normStart && ssoRegion == region {
				// extract the session label (the part after the space)
				parts := strings.SplitN(name, " ", 2)
				if len(parts) == 2 {
					return parts[1], true
				}
			}
		}
	}
	return "", false
}

// findAllMatchingSsoSessionNames returns all sso-session names in the config
// whose sso_start_url and sso_region match the provided values. This lets
// callers detect duplicates and fail with a helpful message when there are
// multiple matching sessions.
func findAllMatchingSsoSessionNames(startURL, region, configPath string) ([]string, error) {
	normStart := strings.TrimRight(startURL, "/")
	cfg, err := ini.Load(configPath)
	if err != nil {
		return nil, err
	}
	var matches []string
	for _, section := range cfg.Sections() {
		name := section.Name()
		if strings.HasPrefix(name, "sso-session ") {
			ssoStart := strings.TrimRight(section.Key("sso_start_url").String(), "/")
			ssoRegion := section.Key("sso_region").String()
			if ssoStart == normStart && ssoRegion == region {
				parts := strings.SplitN(name, " ", 2)
				if len(parts) == 2 {
					matches = append(matches, parts[1])
				}
			}
		}
	}
	return matches, nil
}

// getExistingSsoSessionBlock returns the textual block for an existing
// sso-session <name> from the config file (same format used when we would add one).
func getExistingSsoSessionBlock(sessionName, configPath string) (string, error) {
	cfg, err := ini.Load(configPath)
	if err != nil {
		return "", err
	}

	sectionName := "sso-session " + sessionName
	section := cfg.Section(sectionName)
	if section == nil {
		return "", fmt.Errorf("sso-session %s not found", sessionName)
	}

	ssoStart := strings.TrimRight(section.Key("sso_start_url").String(), "/")
	ssoRegion := section.Key("sso_region").String()
	ssoScopes := section.Key("sso_registration_scopes").String()
	if ssoScopes == "" {
		ssoScopes = "sso:account:access"
	}

	block := fmt.Sprintf("[sso-session %s]\n", sessionName)
	block += fmt.Sprintf("sso_start_url = %s\n", ssoStart)
	block += fmt.Sprintf("sso_region = %s\n", ssoRegion)
	block += fmt.Sprintf("sso_registration_scopes = %s\n", ssoScopes)
	block += "\n"
	return block, nil
}

// printBlockIndented prints a multi-line block so the first line is printed
// with the given indent string, and subsequent non-empty lines are printed
// with the indent plus two spaces (to form a nice indented code block).
func printBlockIndented(indent, block string) {
	lines := strings.Split(block, "\n")
	for i, l := range lines {
		// skip printing a trailing empty line at EOF to avoid double newlines
		if i == len(lines)-1 && l == "" {
			break
		}
		if i == 0 {
			fmt.Printf("%s%s\n", indent, l)
		} else {
			fmt.Printf("%s  %s\n", indent, l)
		}
	}
}

// openBrowserURL attempts to open the provided URL in the user's default
// browser. It's a convenience for the device authorization flow.
func openBrowserURL(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}

// Add SSO session config if needed
func configureSsoSessionConfig() error {
	added, err := ensureSsoSessionConfigPresent()
	if err != nil {
		fmt.Printf("%s %s %v\n", red("❌"), bold("Error adding SSO session config:"), err)
		return err
	}
	if added {
		if dryRun {
			fmt.Printf("%s %s [%s] to %s\n", green("✅"), bold("Would add SSO session config block for"), ssoSessionConfigName, ssoConfigFile)
		} else {
			fmt.Printf("%s %s [%s] to %s\n", green("✅"), bold("Added SSO session config block for"), ssoSessionConfigName, ssoConfigFile)
		}
	}
	return nil
}

// Write profile configuration directly to AWS config file using ini package
func writeProfileToConfig(profileName string, role CombinedRole) error {
	if dryRun {
		// In dry-run mode, show what would be written
		fmt.Printf("    %s Would write profile configuration:\n", cyan("📝"))
		block := fmt.Sprintf("[profile %s]\n", profileName)
		block += fmt.Sprintf("sso_session = %s\n", ssoSessionConfigName)
		block += fmt.Sprintf("sso_account_id = %s\n", role.AccountId)
		block += fmt.Sprintf("sso_role_name = %s\n", role.RoleName)
		block += fmt.Sprintf("region = %s\n", ssoRegion)
		block += fmt.Sprintf("output = %s\n\n", profileOutput)
		printBlockIndented("      ", block)
		return nil
	}

	// Load or create the config file
	cfg, err := ini.Load(ssoConfigFile)
	if err != nil {
		// If file doesn't exist, create a new one
		cfg = ini.Empty()
	}

	// Create the profile section name
	sectionName := fmt.Sprintf("profile %s", profileName)

	// Get or create the profile section
	section, err := cfg.NewSection(sectionName)
	if err != nil {
		// Section might already exist, get it instead
		section = cfg.Section(sectionName)
	}

	// Set the profile properties
	section.Key("sso_session").SetValue(ssoSessionConfigName)
	section.Key("sso_account_id").SetValue(role.AccountId)
	section.Key("sso_role_name").SetValue(role.RoleName)
	section.Key("region").SetValue(ssoRegion)
	section.Key("output").SetValue(profileOutput)

	// Ensure parent directory exists before saving (tests may use temp dirs).
	if err := os.MkdirAll(filepath.Dir(ssoConfigFile), 0o700); err != nil {
		return err
	}
	// Touch the file to ensure it exists (some test environments check for its
	// presence immediately after SaveTo; creating it first avoids races).
	if err := os.WriteFile(ssoConfigFile, []byte{}, 0o600); err != nil {
		return err
	}
	// Save the file
	return cfg.SaveTo(ssoConfigFile)
}

// Check if profile exists by name
func profileExists(profileName, configPath string) bool {
	// Load the config file as INI and check for a section named "profile <name>".
	cfg, err := ini.Load(configPath)
	if err != nil {
		return false
	}
	sectionName := fmt.Sprintf("profile %s", profileName)
	return cfg.Section(sectionName) != nil && cfg.Section(sectionName).HasKey("sso_session")
}

// Add profiles for all accounts with any of the desired roles
func configureSsoProfiles(accessToken string) error {
	// In dry-run, print available roles per account first so the user can see
	// what roles exist and which ones will be selected.
	if dryRun {
		fmt.Printf("%s Available roles per account:\n", cyan("🔎"))
		if err := listAllRolesPerAccount(accessToken); err != nil {
			fmt.Printf("%s %s %v\n", red("❌"), bold("Error listing roles:"), err)
			return err
		}
		fmt.Println()
	}

	roles, err := getCombinedListOfSsoAccountsAndRoles(accessToken, ssoRoleNames)
	if err != nil {
		fmt.Printf("%s %s %v\n", red("❌"), bold("Error fetching accounts:"), err)
		return err
	}
	fmt.Printf("\n%s %s %d account(s) with roles %s\n\n", cyan("🔎"), bold("Found"), len(roles), strings.Join(ssoRoleNames, ", "))
	awsConfigPath := ssoConfigFile
	added := 0
	skipped := 0
	for _, role := range roles {
		profileName := getProfileNameFromRole(role)
		if profileExists(profileName, awsConfigPath) {
			if dryRun {
				fmt.Printf("%s Would skip profile: %s %s\n", yellow("➖"), bold(profileName), "(already exists)")
			} else {
				fmt.Printf("%s Skipping profile: %s %s\n", yellow("➖"), bold(profileName), "(already exists)")
			}
			skipped++
			continue
		}
		if dryRun {
			fmt.Printf("%s Would add profile: %s (Account: %s, AccountId: %s, Role: %s)\n", green("➕"), bold(profileName), role.AccountName, role.AccountId, role.RoleName)
		} else {
			fmt.Printf("%s Adding profile: %s (Account: %s, AccountId: %s, Role: %s)\n", green("➕"), bold(profileName), role.AccountName, role.AccountId, role.RoleName)
		}

		// Write profile configuration directly to config file
		if err := writeProfileToConfig(profileName, role); err != nil {
			fmt.Printf("%s Failed to write profile %s: %v\n", red("❌"), profileName, err)
			continue
		}
		added++
	}
	if dryRun {
		fmt.Printf("\n%s %s %d profile(s) would be added, %d already configured.\n", cyan("📦"), bold("Dry-run summary:"), added, skipped)
	} else {
		fmt.Printf("\n%s %s %d new profile(s), %d already configured.\n", cyan("📦"), bold("Summary:"), added, skipped)
	}
	return nil
}

// Check if the token is valid by attempting to list accounts
func isSsoTokenValid(accessToken string) bool {
	return isSsoTokenValidFunc(accessToken)
}

// Handle login and token retrieval
func login() error {
	// Do not configure the sso-session up-front here. We only need to ensure
	// the sso-session config exists when we are about to run `aws sso login`.
	// If we already have a valid token, we prefer to detect/reuse an existing
	// sso-session block and print it in context after the token discovery.

	// dry-run header is printed in main(); avoid duplicate messages here.

	accessToken, tokenPath, err := getAccessTokenFunc()
	if err == nil {
		fmt.Printf("%s Found existing SSO token at: %s (🌐 ssoUrl: %s, 📍 ssoRegion: %s)\n",
			cyan("🔑"),
			tokenPath,
			ssoStartURL,
			ssoRegion,
		)
		if isSsoTokenValid(accessToken) {
			fmt.Printf("%s Existing token is valid, continuing...\n", green("✅"))
			// If the session name wasn't explicitly provided, try to detect a
			// matching sso-session in the config and print the block we will
			// reuse. This is printed here so it appears after the header and
			// after confirming the token is valid (in context).
			if ssoSessionConfigName == defaultSSOSessionConfigName || ssoSessionConfigName == "" {
				// Look for all matching sessions. If exactly one exists, reuse
				// it and print a concise line. If multiple exist, instruct the
				// user to disambiguate with --sso-session-name.
				if matches, err := findAllMatchingSsoSessionNames(ssoStartURL, ssoRegion, ssoConfigFile); err == nil {
					if len(matches) == 1 {
						ssoSessionConfigName = matches[0]
						fmt.Printf("\n%s Reusing SSO session configuration %s because -sso-session-name was not provided\n\n", cyan("📝"), bold(ssoSessionConfigName))
					} else if len(matches) > 1 {
						fmt.Printf("%s Multiple matching sso-session blocks found (%d). Please pass -sso-session-name to select one, or remove duplicates. Matches: %s\n", red("❌"), len(matches), strings.Join(matches, ", "))
						return fmt.Errorf("multiple matching sso-session blocks found for startUrl %s and region %s", ssoStartURL, ssoRegion)
					}
				}
			}
			if len(ssoRoleNames) == 0 {
				// No roles requested; let caller (main) handle listing available
				// roles so we don't print found/summary blocks here.
				return nil
			}
			return configureSsoProfilesFunc(accessToken)
		} else {
			fmt.Println(yellow("⚠️ Existing token is invalid or expired."))
		}
	} else {
		fmt.Printf("%s No valid SSO token found (🌐 ssoUrl: %s, 📍 ssoRegion: %s).\n",
			yellow("⚠️"),
			ssoStartURL,
			ssoRegion,
		)
	}

	if dryRun {
		// If we're in dry-run mode and there is no valid token, we still need a
		// real token to discover accounts and roles. We'll invoke the normal
		// SSO login flow to obtain a token for discovery (writes are skipped
		// elsewhere because functions respect `dryRun`). Ensure the sso-session
		// block exists right before invoking the login so any printed "Would add"
		// blocks appear in the right place in the output.
		fmt.Printf("%s %s\n", yellow("ℹ️"), bold("Dry-run: no valid token found; will invoke AWS SSO login to obtain a token for discovery (no files will be written)."))
	}

	// Ensure the sso-session config exists before invoking `aws sso login`.
	// For real runs we must create the sso-session so `aws sso login` can
	// reference it. For dry-run we skip creating/printing the session block
	// now (we'll print it after login so the output is shown in context).
	if !dryRun {
		if err := configureSsoSessionConfig(); err != nil {
			return err
		}
	}

	fmt.Printf("%s To continue, you need to authenticate with AWS SSO in your browser to retrieve a new token.\n", yellow("ℹ️"))
	// Let runAwsSsoLogin handle displaying the verification URL, opening the
	// browser (if requested), and starting polling. We avoid any blocking
	// pre-login prompts here so the flow is non-blocking and consistent.
	if err := runAwsSsoLogin(ssoSessionConfigName); err != nil {
		return err
	}

	// After login, fetch the token again and check validity. Use the
	// injectable getAccessTokenFunc so tests can simulate token arrival.
	var lastErr error
	for i := 0; i < 10; i++ {
		accessToken, tokenPath, err = getAccessTokenFunc()
		if err == nil && isSsoTokenValid(accessToken) {
			lastErr = nil
			break
		}
		lastErr = err
		time.Sleep(500 * time.Millisecond)
	}
	if lastErr != nil {
		return fmt.Errorf("SSO login did not produce a valid access token: %v", lastErr)
	}
	fmt.Printf("%s Successfully obtained access token for SSO session at: %s\n", green("✅"), tokenPath)
	// After we have a token, try to detect an existing matching sso-session
	// in the user's config and prefer reusing it if present. This makes the
	// behavior consistent whether dry-run is set or not.
	if ssoSessionConfigName == defaultSSOSessionConfigName || ssoSessionConfigName == "" {
		if matches, err := findAllMatchingSsoSessionNames(ssoStartURL, ssoRegion, ssoConfigFile); err == nil {
			if len(matches) == 1 {
				ssoSessionConfigName = matches[0]
				fmt.Printf("%s Reusing SSO session configuration %s because -sso-session-name was not provided\n\n", cyan("📝"), bold(ssoSessionConfigName))
			} else if len(matches) > 1 {
				fmt.Printf("%s Multiple matching sso-session blocks found (%d). Please pass -sso-session-name to select one, or remove duplicates. Matches: %s\n", red("❌"), len(matches), strings.Join(matches, ", "))
				return fmt.Errorf("multiple matching sso-session blocks found for startUrl %s and region %s", ssoStartURL, ssoRegion)
			}
		}
	}
	// Now ensure/print the sso-session config block (this will be a no-op
	// for non-dry-run if the block already exists; for dry-run this prints
	// the "Would add" block so it appears after the login step).
	if err := configureSsoSessionConfig(); err != nil {
		return err
	}

	if len(ssoRoleNames) == 0 {
		// Caller will list available roles; avoid printing found/summary here.
		return nil
	}

	return configureSsoProfilesFunc(accessToken)
}

func main() {
	// Parse command line flags
	var roleNames stringSliceFlag
	flag.Var(&roleNames, "role", "SSO role name to include (can be specified multiple times)")
	flag.StringVar(&profilePrefix, "prefix", "", "Custom profile prefix (leave empty for auto-generated from role name)")
	flag.BoolVar(&useAutoPrefix, "auto-prefix", true, "Auto-generate prefix from role name (strips AWS and Access)")
	flag.BoolVar(&dryRun, "dry-run", false, "Show what would be done without making any changes")
	flag.BoolVar(&openBrowser, "open", true, "Automatically open the verification URL in the default browser during device authorization")
	flag.StringVar(&profileOutput, "output", "json", "Default output format written into profiles (e.g. json, text)")

	// SSO configuration flags
	flag.StringVar(&ssoStartURL, "sso-start-url", "", "AWS SSO start URL (required)")
	flag.StringVar(&ssoSessionConfigName, "sso-session-name", defaultSSOSessionConfigName, "SSO session configuration name")
	flag.StringVar(&ssoRegion, "sso-region", defaultSSORegion, "AWS SSO region")
	flag.StringVar(&ssoConfigFile, "config-file", config.DefaultSharedConfigFilename(), "AWS config file path")

	flag.Parse()

	// Validate required flags
	if ssoStartURL == "" {
		fmt.Printf("%s %s\n", red("❌"), bold("Error: -sso-start-url is required (tenant-specific, cannot be guessed)"))
		flag.Usage()
		os.Exit(1)
	}

	// Session detection and reuse will be printed at runtime after auth so the
	// user sees the reused session block in context; moved into login().

	// If no -role flags are provided, instead of failing we will list the
	// available roles (this mirrors the dry-run behavior). This makes the
	// experience consistent between dry-run and apply: both will show the
	// available roles and exit so the user can decide which to configure.
	ssoRoleNames = roleNames

	fmt.Println(cyan("\n========== AWS SSO Profile Setup =========="))
	if dryRun {
		// Print a single concise dry-run header to avoid repetition
		fmt.Printf("%s %s — %s\n\n", yellow("🔍"), bold("DRY-RUN MODE: No changes will be made"), "This will show what would be configured without making actual changes")
	}
	// If no roles were requested, perform the login/discovery flow and
	// list available roles per account, then exit. This mirrors the dry-run
	// listing behavior so users see identical output in apply vs dry-run.
	if len(ssoRoleNames) == 0 {
		// We still need a valid token to discover accounts/roles. Reuse the
		// login() flow which will either use an existing token or prompt the
		// user to authenticate and obtain one.
		if err := login(); err != nil {
			fmt.Printf("%s %v\n", red("❌"), err)
			os.Exit(1)
		}
		// After login(), fetch the token and list available roles per account.
		accessToken, _, err := getAccessTokenFunc()
		if err != nil {
			fmt.Printf("%s %v\n", red("❌"), err)
			os.Exit(1)
		}
		// Reuse the same listing logic as dry-run
		fmt.Printf("%s Available roles per account:\n", cyan("🔎"))
		if err := listAllRolesPerAccount(accessToken); err != nil {
			fmt.Printf("%s %s %v\n", red("❌"), bold("Error listing roles:"), err)
			os.Exit(1)
		}
		// Friendly guidance: tell the user to pick role(s) and re-run the tool
		fmt.Println()
		fmt.Printf("%s No role selected. Choose the role(s) you'd like to add and re-run the command with one or more -role flags.\n", yellow("ℹ️"))
		// Show a concrete example using the current executable name. If the
		// current run was a dry-run, include the -dry-run flag so the example
		// mirrors the invocation that produced this output.
		exe := os.Args[0]
		exampleCmd := bold(exe)
		if dryRun {
			exampleCmd = fmt.Sprintf("%s %s", exampleCmd, "-dry-run")
		}
		exampleCmd = fmt.Sprintf("%s -sso-start-url \"%s\" -role AWSReadOnlyAccess", exampleCmd, ssoStartURL)
		fmt.Printf("  Example: %s\n", exampleCmd)
		fmt.Println()
		// Exit after listing so the user can re-run with -role flags
		os.Exit(0)
	}

	if err := login(); err != nil {
		fmt.Printf("%s %v\n", red("❌"), err)
		os.Exit(1)
	}
	if dryRun {
		fmt.Println(green("\n🎉 Dry-run complete! Use without -dry-run to apply these changes."))
	} else {
		fmt.Println(green("\n🎉 AWS SSO login and profile configuration complete!"))
	}
}
