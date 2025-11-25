import requests, sys, json, subprocess

def getCVEversion(name, version, ecosystem):
    url = 'https://api.osv.dev/v1/query'
    payload = {
        "version": version,
        "package": {
            "name": name,
            "ecosystem": ecosystem
        }
    }
    res = requests.post(url, json=payload).json()
    
    if 'vulns' in res:
        return res['vulns']
    return None


if sys.argv.__len__() == 1:
    print('Please add the packages language !\n\033[31mUsage\033[0m:\n\t\033[33mpython3 ./scanner.py [eg: npm, python]\033[0m')
    exit()
program = sys.argv[1].lower()
lines = []

if program == 'os':
    result = subprocess.run(
        "lsb_release -a | grep 'Distributor ID' | awk '{print $3}'",
        shell=True,
        capture_output=True,
        text=True
    )
    eco = result.stdout.strip()
    operatingSystems = ['debian', 'ubuntu']
    if eco in operatingSystems:
        result = subprocess.run(
            "dpkg-query -W -f='${binary:Package} ${Version}\n'",
            shell=True,
            capture_output=True,
            text=True
        )
        lines = result.stdout.strip().split('\n')
elif program == 'npm':
    with open('packages.json', 'r') as file:
        jsonLines = file.readlines()
    line = "".join(jsonLines)
    resp = json.loads(line)
    packages = resp['dependencies']
    for name, version in packages.items():
        lines.append(f'{name}=={version.split('^')[1]}')
    eco = 'npm'
elif program == 'python':
    with open('packages.txt', 'r') as file:
        lines = file.readlines()
    eco = 'PyPI'
else:
    print('\033[31mError\033[0m:\n\tPlease choose either \033[30mnpm/python/os\033[0m')
    exit()


print(lines)
for line in lines:
    pkg = line.strip()
    if '==' in pkg:
        name, version = line.strip().split('==')
    else:
        name, version = line.strip().split(' ')

    vulns = getCVEversion(name, version, eco)

    if not vulns:
        print(f'\033[34mPackage\033[0m: {name} {version}')
        print('\033[34m\tStatus\033[0m: Package is up to date')
    else:
        print(f'\033[34mPackage\033[0m: {name} {version}')
        for vuln in vulns:
            aliases = vuln['aliases']
            cves = [a for a in aliases if a.startswith("CVE-")]
            print(f'\033[34m\tCVE\033[0m: \033[31m⚠ {cves[0]} \033[0m')
            # if vuln['database_specific']['severity'] == 'LOW':
            #     print(f'\033[34mSeverity\033[0m: \033[32m{vuln['database_specific']['severity']}\033[0m\n')
            # if vuln['database_specific']['severity'] == 'MID':
            #     print(f'\033[34mSeverity\033[0m: \033[33m{vuln['database_specific']['severity']}\033[0m\n')
            # if vuln['database_specific']['severity'] == 'HIGH':
            #     print(f'\033[34mSeverity\033[0m: \033[31m{vuln['database_specific']['severity']}\033[0m\n')