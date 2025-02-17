PacketSniffer
---
>### **Disclaimer**: PacketSniffer is a test task. It is not intended to be used in real world.
---
**PacketSniffer** is a C++ CLI tool designed to capture and analyze network packets using `libpcap`. It also includes Python script for aggregating resulting data using `pandas`.
It classifies captured network traffic by processing captured data and generates some statistics.

## Features

- **Packet Capture**: Intercepts IPv4 network packets from network interface or reads them from `.pcap` file.
- **Flow identification**: Classifies every packet into flow, which is combination of `IP_src, IP_dest, Port_src, Port_dest`. For each flow counts total number of transmitted packets and bytes.
- **Protocol Analysis**: Captures TCP and UDP packets.
- **CSV export**: Both C++ sniffer and Python postprocessing script export their results into CSV.
- **Python Post-Processing**: Python script aggregates data from CSV made by C++ sniffer and provides statistics on sent and received packets and bytes for each IP address.

## Requirements

- **Operating System**: Linux-based systems (e.g., Ubuntu, Fedora).
- **Dependencies**:
  - `libpcap`: For C++ sniffer packet capturing.
  - `Python 3.x`: For running the post-processing script.
  - Python Libraries: `pandas`.

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/DemidSergeev/PacketSniffer.git
   cd PacketSniffer
   ```

2. **Install Dependencies**:
   - **libpcap**:
     ```bash
     sudo apt-get update
     sudo apt-get install libpcap-dev
     ```
   - **Python Libraries**:
     Use any preferred method. Simplest way:
     ```bash
     pip3 install pandas
     ```

3. **Compile the Application**:
   Use the provided `Makefile` to compile the C++ source code:
   ```bash
   make
   ```

## Usage

### 1. **C++ packet sniffer**:
   Execute the compiled C++ file:
   ```bash
   sudo ./sniff.out
   ```
   >*Note*: Root privileges are required to capture network packets. If you intend to use this for PCAP file analysis, root privileges are not needed.

  When executing sniffer without options and arguments, it captures 1000 packets from default network interface.
  #### Syntax and options:
  ```bash
  ./sniff.out [-h] [-f <filename> | -i [<interface>]] [-c <count>] [-o <filename>]
  ```
  - `-h, --help` – Display help message.
  - `-f, --file <filename>` – Read packets from the specified file.
  - `-i, --interface [<interface>]` – Listen on a network interface. If not specified, the default interface will be used.
  - `-c, --count <count>` – Set the number of packets to capture.
  - `-o, --output <filename>` – Specify an output file for saving statistics.

### 2. **Python post-processing script**:
   After capturing packets, use the `postprocess.py` script to analyze and export the data.
   
   #### Syntax and options:
   ```bash
   python3 postprocess.py captured_data.csv [output_filename.csv]
   ```
   - `captured_data.csv`: The input file generated by `PacketSniffer`.
   - `[output_filename.csv]`: (Optional) The desired name for the output file. Defaults to `postprocess.csv` if not specified.

---

Feel free to customize this README further to suit your project's specifics. 
