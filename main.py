import logging
import copy
from datetime import datetime
from colorama import Fore, Style
from utils import check_trivy_installed
from scan import scan_directory
from sqs import send_to_input_sqs
from enrich import enrich_payload

# Set up logging
scan_timestamp = datetime.now().strftime("%Y%m%d-%H%M")
log_filename = f"scan_log_{scan_timestamp}.log"
logging.basicConfig(filename=log_filename, level=logging.INFO,
                    format='%(asctime)s:%(levelname)s:%(message)s')


def prompt_user_metadata():
    """Prompt user for scan metadata and return as a dictionary."""
    print(f"{Fore.BLUE}Please provide the following information:{Style.RESET_ALL}")
    account_id = input("Account ID: ").strip()
    app_name = input("Application Name: ").strip()
    system_name = input("System Name: ").strip()
    directory = input("Directory to scan (leave empty for current dir): ").strip() or "."
    confirm = input(
        f"\nScan directory '{directory}' with AccountID={account_id}, AppName={app_name}, SystemName={system_name}? (yes/no): "
    ).strip().lower()
    if confirm != 'yes':
        return None
    return {
        'account_id': account_id,
        'app_name': app_name,
        'system_name': system_name,
        'directory': directory
    }

def main() -> None:
    print(f"{Fore.CYAN}FileSystem CVE Scanner by ZERODOTFIVE Hamburg GmbH - moin@zerodotfive.com")
    if not check_trivy_installed():
        print(f"{Fore.RED}Trivy is not installed or not found in PATH. Please install Trivy to proceed.{Fore.RESET}")
        return

    metadata = prompt_user_metadata()
    if not metadata:
        print("Scan aborted.")
        return

    directory = metadata['directory']
    app_name = metadata['app_name']
    system_name = metadata['system_name']
    account_id = metadata['account_id']

    try:
        logging.info(f"Scanning directory: {directory}")
        scan_result, error_message = scan_directory(directory=directory)

        if len(scan_result['Results']) > 0:
            all_vulnerabilities = []
            for result in scan_result['Results']:
                single_scan_result = copy.deepcopy(scan_result)
                single_scan_result['Results'] = [result]

                vulnerabilities = result.get('Vulnerabilities', [])

                # Enrich vulnerabilities with EPSS scores
                for vuln in vulnerabilities:
                    single_vulnerability = copy.deepcopy(single_scan_result)
                    single_vulnerability['Results'][0]['Vulnerabilities'] = [vuln]
                    single_vulnerability['Results'][0]['References'] = []

                    # Send each vulnerability to SQS
                    # Enrich the payload with additional metadata
                    enriched_payload = enrich_payload(single_vulnerability, account_id, system_name, app_name)
                    send_to_input_sqs(scan_payload=enriched_payload)

                all_vulnerabilities.extend(vulnerabilities)

            summary = {
                'image': f"directory:{directory}",
                'total': len(all_vulnerabilities),
                'high': len([v for v in all_vulnerabilities if v['Severity'].upper() == 'HIGH']),
                'critical': len([v for v in all_vulnerabilities if v['Severity'].upper() == 'CRITICAL']),
                'medium': len([v for v in all_vulnerabilities if v['Severity'].upper() == 'MEDIUM']),
                'low': len([v for v in all_vulnerabilities if v['Severity'].upper() == 'LOW']),
            }

            print(
                f"{Fore.CYAN}Summary for image: {directory}: {Fore.RESET}Total: {summary['total']}, "
                f"{Fore.LIGHTRED_EX}High: {summary['high']}, "
                f"{Fore.RED}Critical: {summary['critical']}, "
                f"{Fore.YELLOW}Medium: {summary['medium']}, "
                f"{Fore.GREEN}Low: {summary['low']}"
                )
        else:
            print(f"Scanning {directory} error")
            error_message = f"Failed to scan image: {directory}\n{error_message}\n"
            logging.error(error_message)
    except Exception as e:
        error_message = f"Exception occurred while scanning image: {directory}\n{str(e)}\n"
        print(e)


if __name__ == "__main__":
    main()
