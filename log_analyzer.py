from collections import Counter
from datetime import datetime

LOG_FILE = "sample_auth.log"
REPORT_FILE = "security_report.txt"

BRUTE_FORCE_THRESHOLD = 5


def analyze_log():

    success = 0
    failed = 0

    failed_ips = Counter()

    with open(LOG_FILE, "r") as file:

        for line in file:

            parts = line.strip().split()

            if len(parts) < 4:
                continue

            status = parts[2]
            ip = parts[3]

            if status == "SUCCESS":
                success += 1

            elif status == "FAILED":
                failed += 1
                failed_ips[ip] += 1

    print("=" * 50)
    print("          LOG FILE ANALYZER")
    print("=" * 50)

    print(f"\nSuccessful Logins : {success}")
    print(f"Failed Logins     : {failed}")

    print("\nSuspicious IP Addresses")
    print("-" * 35)

    with open(REPORT_FILE, "w") as report:

        report.write("=" * 55 + "\n")
        report.write("             SECURITY REPORT\n")
        report.write("=" * 55 + "\n\n")

        report.write(f"Generated: {datetime.now()}\n\n")
        report.write(f"Successful Logins : {success}\n")
        report.write(f"Failed Logins     : {failed}\n\n")

        if not failed_ips:
            print("No suspicious activity found.")
            report.write("No suspicious activity found.\n")

        else:

            most_targeted_ip = max(failed_ips, key=failed_ips.get)

            for ip, count in failed_ips.items():

                if count >= BRUTE_FORCE_THRESHOLD:

                    print(f"{ip} -> {count} failed attempts (Possible Brute Force)")

                    report.write(
                        f"{ip} -> {count} failed attempts (Possible Brute Force)\n"
                    )

                else:

                    print(f"{ip} -> {count} failed attempts")

                    report.write(
                        f"{ip} -> {count} failed attempts\n"
                    )

            report.write("\n")
            report.write("=" * 55 + "\n")
            report.write("SUMMARY\n")
            report.write("=" * 55 + "\n")
            report.write(
                f"Most Targeted IP : {most_targeted_ip} ({failed_ips[most_targeted_ip]} failed attempts)\n"
            )

    print("\nSecurity report saved as security_report.txt")


if __name__ == "__main__":
    analyze_log()