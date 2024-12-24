import xml.etree.ElementTree as ET
import csv
import sys


def detect_encoding(file_path):
    with open(file_path, 'rb') as f:
        raw_data = f.read(4)
        if raw_data.startswith(b'\xff\xfe') or raw_data.startswith(b'\xfe\xff'):
            return 'utf-16'
        elif raw_data.startswith(b'\xef\xbb\xbf'):
            return 'utf-8-sig'
        else:
            return 'utf-8'


def main(file_path):
    print("\n###############################")
    print("# XML Event Extractor Script  #")
    print("# --------------------------  #")
    print("# Version 0.1b                #")
    print("# (c) 2024 by suuhmer         #")
    print("###############################\n")

    print(f"\n[*] Checking if the file '{file_path}' exists...")
    try:
        encoding = detect_encoding(file_path)
        with open(file_path, 'r', encoding=encoding) as f:
            xml_data = f.read()
    except FileNotFoundError:
        print(f"File '{file_path}' not found. Please check.")
        sys.exit(1)
    except UnicodeDecodeError as e:
        print(f"Error reading the file: {e}")
        sys.exit(1)

    print(f"\n[*] XML file successfully loaded (Encoding: {encoding}).")
    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError as e:
        print(f"Error parsing the XML file: {e}")
        sys.exit(1)

    print(f"Root tag of the XML file: {root.tag}")
    namespace = {'ns': 'http://schemas.microsoft.com/powershell/2004/04'}
    
    # Relevant Event IDs for Analysis
    relevant_event_ids = {
        '4624': 'Successful Logon',
        '4625': 'Failed Logon',
        '4634': 'Logoff',
        '4648': 'Logon Attempt Using Explicit Credentials',
        '4663': 'Object Access Attempt',
        '4672': 'Special Privileges Assigned to New Logon',
        '4688': 'Process Creation',
        '4697': 'Service Installed',
        '4700': 'Audit Policy Changed',
        '4720': 'New User Created',
        '4722': 'User Account Enabled',
        '4723': 'Password Change Attempt',
        '4724': 'Password Reset by Admin',
        '4725': 'User Account Disabled',
        '4726': 'User Account Deleted',
        '4732': 'User Added to Group',
        '4733': 'User Removed from Group',
        '4738': 'User Account Changed',
        '4740': 'User Account Locked Out',
        '4767': 'Account Unlocked',
        '4768': 'Kerberos Authentication Ticket Issued',
        '4776': 'Credential Validation Attempt',
        '4778': 'Session Reconnected',
        '4779': 'Session Disconnected',
        '4781': 'Group Membership Changed',
        '4798': 'User’s Group Membership Queried',
        '4799': 'A Security-enabled Global Group Membership Was Enumerated',
        '5136': 'Directory Service Object Modified',
        '5137': 'Directory Service Object Created',
        '5138': 'Directory Service Object Undeleted',
        '5140': 'Network Share Accessed',
        '5141': 'Directory Service Object Deleted',
        '5142': 'Security Policy in Group Policy Object Changed',
        '5145': 'Detailed File Share Access',
        '5156': 'Windows Filtering Platform Connection Allowed',
        '5157': 'Windows Filtering Platform Connection Blocked',
        '5379': 'Logon with Explicit Credentials',
        '7045': 'Service Installed on System'
    }

    extracted_data = []

    objs = root.findall(".//ns:Obj", namespace)
    print(f"{len(objs)} objects found in the XML file.")

    for obj in objs:
        props = obj.find("ns:Props", namespace)
        if props is None:
            continue

        # Extract Event ID
        event_id_elem = props.find("ns:I32[@N='Id']", namespace)
        event_id = event_id_elem.text if event_id_elem is not None else None

        if event_id in relevant_event_ids:
            # Extract relevant fields
            log_name_elem = props.find("ns:S[@N='LogName']", namespace)
            time_created_elem = props.find("ns:DT[@N='TimeCreated']", namespace)
            machine_name_elem = props.find("ns:S[@N='MachineName']", namespace)
            provider_name_elem = props.find("ns:S[@N='ProviderName']", namespace)

            log_name = log_name_elem.text if log_name_elem is not None else "N/A"
            time_created = time_created_elem.text if time_created_elem is not None else "N/A"
            machine_name = machine_name_elem.text if machine_name_elem is not None else "N/A"
            provider_name = provider_name_elem.text if provider_name_elem is not None else "N/A"

            # Look for User and IP in Properties
            properties_obj = props.find("ns:Obj[@N='Properties']", namespace)
            if properties_obj is not None:
                properties = properties_obj.findall(".//ns:Obj", namespace)
                user_account = "N/A"
                domain = "N/A"
                ip_address = "N/A"

                try:
                    # User and Domain information
                    user_account = properties[4].find("ns:Props/ns:S[@N='Value']", namespace).text
                    domain = properties[5].find("ns:Props/ns:S[@N='Value']", namespace).text

                    # IP Address (check the actual position in your XML!)
                    ip_address = properties[18].find("ns:Props/ns:S[@N='Value']", namespace).text
                except (IndexError, AttributeError):
                    pass

                event_data = {
                    'EventID': event_id,
                    'Description': relevant_event_ids[event_id],
                    'LogName': log_name,
                    'MachineName': machine_name,
                    'ProviderName': provider_name,
                    'TimeCreated': time_created,
                    'UserAccount': user_account,
                    'Domain': domain,
                    'IPAddress': ip_address
                }

                extracted_data.append(event_data)

    if not extracted_data:
        print("No relevant events found.")
    else:
        print(f"{len(extracted_data)} relevant events found.")
        for data in extracted_data:
            print(f"Event {data['EventID']} - {data['Description']}: User={data['UserAccount']}, "
                  f"Domain={data['Domain']}, IP={data['IPAddress']}")

    # Export to CSV
    output_file = 'ExtractedEvents.csv'
    print(f"\nExporting filtered events to '{output_file}'...")
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['EventID', 'Description', 'LogName', 'MachineName', 'ProviderName', 'TimeCreated', 'UserAccount', 'Domain', 'IPAddress']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for event in extracted_data:
            writer.writerow(event)
    print("Export completed.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python xml_event_xtractor.py <XML-file>\n")
        sys.exit(1)

    file_path = sys.argv[1]
    main(file_path)
