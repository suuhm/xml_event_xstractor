# xml_event_xtractor
export windows evtx events from xmlcli export files

# XML Event Extractor

![grafik](https://github.com/user-attachments/assets/3971461a-abee-490c-95c7-9bddba75e073)


**Version**: 0.1beta

## Overview

The XML Event Extractor is a Python script designed to parse security-related XML event logs and extract meaningful data into a structured format. It focuses on extracting relevant security event IDs from Windows Event Logs (such as login attempts, logoffs, process creation, etc.).

## Features

- Parses XML files with UTF-8 or UTF-16 encoding.
- Supports extraction of various security event IDs.
- Outputs relevant event data into a CSV file.

![grafik](https://github.com/user-attachments/assets/e8d40dda-7393-4753-a4de-8e8f13ff45b2)


## Supported Event IDs

The script handles the following event IDs:

- Successful Logon
- Failed Logon
- Logoff
- Process Creation
- Service Installation
- Directory Service Modifications, and more...

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/suuhm/xml_event_extractor.git
   ```

2. Navigate to the project directory:

   ```bash
   cd xml_event_extractor
   ```

3. Install required dependencies:

   ```bash
   pip install -r requirements.txt
   ```

## Usage

To use the XML Event Extractor, simply run the script with the XML file as an argument:

```bash
python xml_event_xtractor.py /PATH/TO/FILE(*.xml, *.evtx)
```

## Output

The script will generate a CSV file (`ExtractedEvents.csv`) containing the extracted events with their details.

## License

This project is licensed under the MIT License.
