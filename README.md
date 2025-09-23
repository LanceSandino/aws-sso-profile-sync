# AWS SSO Profile Sync

A Go CLI tool that automatically configures AWS CLI profiles for all AWS accounts accessible through AWS Single Sign-On (SSO). This tool eliminates the manual process of setting up individual AWS CLI profiles for each account in your organization.

## 🚀 Features

- **Automatic Profile Discovery**: Automatically discovers all AWS accounts accessible via your AWS SSO
- **Bulk Profile Creation**: Creates AWS CLI profiles for all discovered accounts with a single command
- **Smart Token Management**: Validates existing SSO tokens and handles automatic renewal
- **Configuration Management**: Automatically manages SSO session configuration in `~/.aws/config`
- **Role-based Filtering**: Configurable to work with specific IAM roles (PowerUser, Administrator, ReadOnly)
- **Duplicate Protection**: Skips profiles that already exist to avoid conflicts
- **Colorized Output**: Beautiful, colored terminal output for better user experience
- **Interactive Login**: Seamlessly handles AWS SSO browser-based authentication

## 📋 Prerequisites

- Go 1.19+ installed on your system
- AWS SSO configured for your organization and an account with access

This tool uses the AWS SDK for Go v2 and does not require the AWS CLI to be installed. It writes profiles directly to your AWS config file (`~/.aws/config`).

## 🛠️ Installation

Build from source:

```bash
git clone https://github.com/LanceSandino/aws-sso-profile-sync.git
cd aws-sso-profile-sync
go build -o aws-sso-profile-sync main.go
```

Or install with `go install`:

```bash
go install github.com/LanceSandino/aws-sso-profile-sync@latest
```

## ⚙️ Configuration (flags)

This tool is configured via CLI flags rather than compile-time constants. Important flags implemented in the code include:

- `-sso-start-url` (required): the SSO start URL for your tenant (e.g. `https://mycompany.awsapps.com/start/`).
- `-sso-session-name` (default: `default`): name for the `sso-session` block in your AWS config.
- `-sso-region` (default: `us-east-1`): AWS SSO region.
- `-role` (repeatable): SSO role names to create profiles for (can be provided multiple times).
- `-prefix`: explicit profile prefix (overrides auto-generation).
- `-auto-prefix` (default: true): auto-generate profile prefix from role name.
- `-output` (default: `json`): value to write into the `output` key for each profile (e.g., `json` or `text`).
- `-config-file`: path to the AWS config file (defaults to SDK default, typically `~/.aws/config`).

Use `-dry-run` to preview changes without writing files, and `-open` (default true) to automatically open the device verification URL in your browser during login.

## 🚀 Usage

### Basic Usage

1. **Configure the tool** with your SSO settings (see Configuration section above)
2. **Run the tool**:
   ```bash
   ./aws-sso-profile-sync
   ```

### What the Tool Does

1. **Checks SSO Configuration**: Verifies that the SSO session is configured in `~/.aws/config`
2. **Validates Tokens**: Checks if you have a valid SSO token
3. **Interactive Login**: If needed, prompts you to authenticate via browser
4. **Discovers Accounts**: Fetches all AWS accounts accessible through SSO
5. **Creates Profiles**: Generates AWS CLI profiles for each account with the specified role
6. **Reports Results**: Shows summary of profiles created and skipped

### Example Output

```
========== AWS SSO Profile Setup ==========
✅ Added SSO session config block for [my-sso-name] to /home/user/.aws/config

🔑 Found existing SSO token at: /home/user/.aws/sso/cache/abc123.json (🌐 ssoUrl: https://your-tenant.awsapps.com/start/, 📍 ssoRegion: us-east-1)
✅ Existing token is valid, continuing...

🔎 Found 5 account(s) with role AWSPowerUserAccess

➕ Adding profile: PowerUser_ProductionAccount (Account: Production, AccountId: 123456789012, Role: AWSPowerUserAccess)
➕ Adding profile: PowerUser_StagingAccount (Account: Staging, AccountId: 123456789013, Role: AWSPowerUserAccess)
➖ Skipping profile: PowerUser_DevAccount (already exists)
➕ Adding profile: PowerUser_TestingAccount (Account: Testing, AccountId: 123456789015, Role: AWSPowerUserAccess)

📦 Summary: 3 new profile(s), 1 already configured.

🎉 AWS SSO login and profile configuration complete!
```

### Using Generated Profiles

After running the tool, you can use the generated profiles with the AWS CLI:

```bash
# List all profiles
aws configure list-profiles

# Use a specific profile
aws s3 ls --profile PowerUser_ProductionAccount

# Set default profile
export AWS_PROFILE=PowerUser_ProductionAccount
aws sts get-caller-identity
```

## 🗂️ Generated Profile Structure

Each generated profile will have the following configuration in `~/.aws/config`:

```ini
[profile PowerUser_ProductionAccount]
sso_session = my-sso-name
sso_account_id = 123456789012
sso_role_name = AWSPowerUserAccess
region = us-east-1
output = json
```

## 🔧 Troubleshooting

### Common Issues

#### "No such file or directory" Error
```
❌ Error adding SSO session config: open /home/user/.aws/config: no such file or directory
```
**Solution**: Create the AWS config directory:
```bash
mkdir -p ~/.aws
touch ~/.aws/config
```

#### Invalid SSO Token
```
⚠️ Existing token is invalid or expired.
```
**Solution**: The tool will automatically prompt you to re-authenticate via browser.

#### AWS CLI Not Found
```
exec: "aws": executable file not found in $PATH
```
**Solution**: Install AWS CLI v2:
- **macOS**: `brew install awscli`
- **Linux**: Follow [AWS CLI installation guide](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
- **Windows**: Download installer from AWS

#### SSO Authentication Issues
**Solution**: Ensure your SSO URL and region are correct in the configuration constants.

### Debug Mode

For troubleshooting, you can examine the generated AWS configuration:

```bash
# View your AWS config
cat ~/.aws/config

# List all profiles
aws configure list-profiles

# Test a specific profile
aws sts get-caller-identity --profile PowerUser_YourAccount
```

## 🏗️ Architecture

The tool consists of several key components:

- **Token Management**: Handles SSO token discovery, validation, and renewal
- **Account Discovery**: Uses AWS SSO APIs to fetch accessible accounts and roles
- **Profile Generation**: Creates AWS CLI profiles using the `aws configure` command
- **Configuration Management**: Manages SSO session configuration in AWS config files
 - **Profile Generation**: Writes AWS CLI profile sections directly to the AWS config file using the `gopkg.in/ini.v1` library
 - **Configuration Management**: Manages SSO session configuration in AWS config files (direct INI edits)

## 🤝 Contributing

Contributions are welcome! Here are some ways you can help:

1. **Report Issues**: Found a bug? Please open an issue with details
2. **Feature Requests**: Have an idea? Open an issue to discuss it
3. **Code Contributions**: 
   - Fork the repository
   - Create a feature branch (`git checkout -b feature/amazing-feature`)
   - Commit your changes (`git commit -m 'Add some amazing feature'`)
   - Push to the branch (`git push origin feature/amazing-feature`)
   - Open a Pull Request

### Development Setup

```bash
git clone https://github.com/LanceSandino/aws-sso-profile-sync.git
cd aws-sso-profile-sync
go mod download
go build .
```

## 📝 License

This project is open source. Please check the repository for license details.

## 🙏 Acknowledgments

- Built with the [AWS SDK for Go v2](https://github.com/aws/aws-sdk-go-v2)
- Uses [fatih/color](https://github.com/fatih/color) for beautiful terminal output
 - Uses [gopkg.in/ini.v1](https://gopkg.in/ini.v1) to read and write `~/.aws/config` safely

---

**Note**: This tool modifies your AWS CLI configuration. Always backup your `~/.aws/config` file before running the tool for the first time.