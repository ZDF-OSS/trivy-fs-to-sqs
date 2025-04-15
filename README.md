# Trivy Filesystem CVE Scanner to SQS

This tool uses [Trivy](https://github.com/aquasecurity/trivy) to scan a local filesystem for CVEs (Common Vulnerabilities and Exposures) and pushes the results to an AWS SQS queue for further processing or alerting.

## 🔧 Features

- Scans local directories for known vulnerabilities using **Trivy**
- Sends scan results to an **AWS SQS** queue
- Prompts user for:
  - AWS **Account ID**
  - Application Name (**appName**)
  - System Name (**systemName**)
  - **Directory** to scan (can be a mounted EFS share, etc.)

## 📦 Setup & Usage

### 1. Start the scanner

```bash
make start
```

This command will:
- Install all necessary dependencies
- Prompt you for required information (account ID, appName, systemName, and directory to scan)
- Execute the scan using Trivy
- Push the results to the configured SQS queue

### Example use case

This is particularly useful when scanning **mounted filesystems (e.g., EFS shares)** from systems that cannot be scanned using **AWS Inspector** directly, such as isolated or legacy systems.

## 📝 Requirements

- Docker installed (for Trivy, if not running natively)
- AWS CLI configured or environment variables for authentication
- Access to the relevant AWS SQS queue

## 📂 Example Directory Mounting

```bash
sudo mount -t nfs4 -o nfsvers=4.1 fs-xxxxxx.efs.eu-central-1.amazonaws.com:/ /mnt/efs
```

Then, simply provide `/mnt/efs` when prompted for the directory to scan.

