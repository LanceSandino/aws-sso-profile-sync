package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/fatih/color"
)

const (
	SSOStartURL          = "https://XXXXXXX.awsapps.com/start/"
	SSOSessionConfigName = "my-sso-name"
	SSORegion            = "us-east-1"
	SSOConfigFile        = ".aws/config"
	SSOProfileOutput     = "json"
	SSORoleName          = "AWSPowerUserAccess" // "AWSAdministratorAccess", "AWSPowerUserAccess", "AWSReadOnlyAccess"
	ProfilePrefix        = "PowerUser_" // TODO
)

var (
	green  = color.New(color.FgGreen).SprintFunc()
	yellow = color.New(color.FgYellow).SprintFunc()
	cyan   = color.New(color.FgCyan).SprintFunc()
	red    = color.New(color.FgRed).SprintFunc()
	bold   = color.New(color.Bold).SprintFunc()
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
			if ok && (startUrl == SSOStartURL || startUrl == strings.TrimRight(SSOStartURL, "/")) && tokenOk {
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
		return "", "", fmt.Errorf("no valid SSO accessToken found for startUrl %s", SSOStartURL)
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
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(SSORegion))
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
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(SSORegion))
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

// Get all accounts with the desired role
func getCombinedListOfSsoAccountsAndRoles(accessToken string) ([]CombinedRole, error) {
	accounts, err := getListOfSsoAccounts(accessToken)
	if err != nil {
		return nil, err
	}
	var combined []CombinedRole
	for _, account := range accounts {
		roles, err := getListOfSsoAccountRolesForAccount(accessToken, account.AccountId)
		if err != nil {
			return nil, err
		}
		for _, role := range roles {
			if role.RoleName == SSORoleName {
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

// Format profile name
func getProfileNameFromRole(role CombinedRole) string {
	re := regexp.MustCompile(`[_\s]+`)
	safeAccountName := re.ReplaceAllString(role.AccountName, "-")
	if ProfilePrefix != "" {
		return fmt.Sprintf("%s%s_%s", ProfilePrefix, safeAccountName, role.AccountId)
	}
	return fmt.Sprintf("%s_%s", safeAccountName, role.AccountId)
}

// Ensure SSO session config block is present in ~/.aws/config
func ensureSsoSessionConfigPresent() (bool, error) {
	homeDir, _ := os.UserHomeDir()
	awsConfigPath := filepath.Join(homeDir, SSOConfigFile)
	sessionHeader := fmt.Sprintf("[sso-session %s]", SSOSessionConfigName)
	sessionBlock := fmt.Sprintf(
		`[sso-session %s]
sso_start_url = %s
sso_region = %s
sso_registration_scopes = sso:account:access
`, SSOSessionConfigName, strings.TrimRight(SSOStartURL, "/"), SSORegion)

	data, err := os.ReadFile(awsConfigPath)
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	if strings.Contains(string(data), sessionHeader) {
		return false, nil // Already present
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

// Add SSO session config if needed
func configureSsoSessionConfig() error {
	added, err := ensureSsoSessionConfigPresent()
	if err != nil {
		fmt.Printf("%s %s %v\n", red("❌"), bold("Error adding SSO session config:"), err)
		return err
	}
	if added {
		homeDir, _ := os.UserHomeDir()
		fmt.Printf("%s %s [%s] to %s\n", green("✅"), bold("Added SSO session config block for"), SSOSessionConfigName, filepath.Join(homeDir, SSOConfigFile))
	}
	return nil
}

// Check if profile exists by name
func profileExists(profileName, configPath string) bool {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), fmt.Sprintf("profile %s", profileName))
}

// Add profiles for all accounts with the desired role
func configureSsoProfiles(accessToken string) error {
	roles, err := getCombinedListOfSsoAccountsAndRoles(accessToken)
	if err != nil {
		fmt.Printf("%s %s %v\n", red("❌"), bold("Error fetching accounts:"), err)
		return err
	}
	fmt.Printf("\n%s %s %d account(s) with role %s\n\n", cyan("🔎"), bold("Found"), len(roles), SSORoleName)
	homeDir, _ := os.UserHomeDir()
	awsConfigPath := filepath.Join(homeDir, SSOConfigFile)
	added := 0
	skipped := 0
	for _, role := range roles {
		profileName := getProfileNameFromRole(role)
		if profileExists(profileName, awsConfigPath) {
			fmt.Printf("%s Skipping profile: %s %s\n", yellow("➖"), bold(profileName), "(already exists)")
			skipped++
			continue
		}
		fmt.Printf("%s Adding profile: %s (Account: %s, AccountId: %s, Role: %s)\n", green("➕"), bold(profileName), role.AccountName, role.AccountId, role.RoleName)
		// Check errors for each subprocess call
		if err := exec.Command("aws", "configure", "--profile", profileName, "set", "sso_session", SSOSessionConfigName).Run(); err != nil {
			fmt.Printf("%s Failed to set sso_session for %s: %v\n", red("❌"), profileName, err)
		}
		if err := exec.Command("aws", "configure", "--profile", profileName, "set", "sso_account_id", role.AccountId).Run(); err != nil {
			fmt.Printf("%s Failed to set sso_account_id for %s: %v\n", red("❌"), profileName, err)
		}
		if err := exec.Command("aws", "configure", "--profile", profileName, "set", "sso_role_name", role.RoleName).Run(); err != nil {
			fmt.Printf("%s Failed to set sso_role_name for %s: %v\n", red("❌"), profileName, err)
		}
		if err := exec.Command("aws", "configure", "--profile", profileName, "set", "region", SSORegion).Run(); err != nil {
			fmt.Printf("%s Failed to set region for %s: %v\n", red("❌"), profileName, err)
		}
		if err := exec.Command("aws", "configure", "--profile", profileName, "set", "output", SSOProfileOutput).Run(); err != nil {
			fmt.Printf("%s Failed to set output for %s: %v\n", red("❌"), profileName, err)
		}
		added++
	}
	fmt.Printf("\n%s %s %d new profile(s), %d already configured.\n", cyan("📦"), bold("Summary:"), added, skipped)
	return nil
}

// Check if the token is valid by attempting to list accounts
func isSsoTokenValid(accessToken string) bool {
	_, err := getListOfSsoAccounts(accessToken)
	return err == nil
}

// Handle login and token retrieval
func login() error {
	if err := configureSsoSessionConfig(); err != nil {
		return err
	}
	accessToken, tokenPath, err := getAccessTokenFromSsoSessionWithPath()
	if err == nil {
		fmt.Printf("%s Found existing SSO token at: %s (🌐 ssoUrl: %s, 📍 ssoRegion: %s)\n",
			cyan("🔑"),
			tokenPath,
			SSOStartURL,
			SSORegion,
		)
		if isSsoTokenValid(accessToken) {
			fmt.Printf("%s Existing token is valid, continuing...\n", green("✅"))
			return configureSsoProfiles(accessToken)
		} else {
			fmt.Println(yellow("⚠️ Existing token is invalid or expired."))
		}
	} else {
		fmt.Printf("%s No valid SSO token found (🌐 ssoUrl: %s, 📍 ssoRegion: %s).\n",
			yellow("⚠️"),
			SSOStartURL,
			SSORegion,
		)
	}

	fmt.Printf("%s To continue, you need to authenticate with AWS SSO in your browser to retrieve a new token.\n", yellow("ℹ️"))
	fmt.Printf("Press %s to open the AWS SSO login page...\n", bold("Enter"))
	bufio.NewReader(os.Stdin).ReadBytes('\n')
	cmd := exec.Command("aws", "sso", "login", "--sso-session", SSOSessionConfigName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		return err
	}

	// After login, fetch the token again and check validity
	var lastErr error
	for i := 0; i < 10; i++ {
		accessToken, tokenPath, err = getAccessTokenFromSsoSessionWithPath()
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
	return configureSsoProfiles(accessToken)
}

func main() {
	fmt.Println(cyan("\n========== AWS SSO Profile Setup =========="))
	if err := configureSsoSessionConfig(); err != nil {
		fmt.Printf("%s %v\n", red("❌"), err)
		os.Exit(1)
	}
	if err := login(); err != nil {
		fmt.Printf("%s %v\n", red("❌"), err)
		os.Exit(1)
	}
	fmt.Println(green("\n🎉 AWS SSO login and profile configuration complete!"))
}
