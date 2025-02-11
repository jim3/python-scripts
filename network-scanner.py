import sys
import re
import subprocess


def nmap_scan(cidr):
    print("Scanning network: " + cidr)
    command = ["nmap", cidr]
    try:
        result = subprocess.run(
            command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        output = result.stdout.decode()
        return output
    except subprocess.CalledProcessError as e:
        print("Error during nmap scan:", e.stderr.decode())
        sys.exit(1)


def parse_nmap_output(output):
    if not isinstance(output, str):
        print("Error: Output is not a string!")
        return

    lst = []
    portNumRegexObj = re.compile(r"\d{2,5}/")

    try:
        match = portNumRegexObj.findall(output)
        for p in match:
            portList = str(p).rstrip("/")
            lst.append(portList)
    except re.error as e:
        print(f"Regex error: {e}")
        return

    return lst


def main():
    if len(sys.argv) < 2:
        print("Usage: " + sys.argv[0] + "<base IP address> <subnet mask>")
        sys.exit(1)

    ipAddr = sys.argv[1]
    ipAddrRegex = re.compile(r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})")
    ipAddrMatch = ipAddrRegex.match(ipAddr)
    if not ipAddrMatch:
        print("Invalid IP address")
        sys.exit(1)

    subnetMask = sys.argv[2]
    subnetMaskRegex = re.compile(r"\d{1,2}")
    subnetMaskMatch = subnetMaskRegex.match(subnetMask)  # check if subnet mask is valid
    if not subnetMaskMatch:
        print("Invalid subnet mask")
        sys.exit(1)

    cidr = ipAddr + "/" + subnetMask
    output = nmap_scan(cidr)
    portLst = parse_nmap_output(output)
    print(f"{portLst}")


if __name__ == "__main__":
    main()
