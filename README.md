# NATS Publisher GUI

This is a simple PyQt6 application for publishing messages to a NATS server. The application allows you to select or add new hosts, channels, and messages using dropdown menus. It also provides a graphical interface to send messages to the specified channel on the selected NATS server.

## Features

- Select NATS server address from a dropdown menu.
- Select or add new topics and messages from dropdown menus.
- Send messages to the specified channel on the selected NATS server.
- Load configuration file.
- Send message over SSH connection.

## Installation
If you are on windows machine, than download the NatsPublisher_V_V.exe from executeable/ folder.

### Prerequisites

- Python 3.7+
- `pip` package installer

### Step-by-Step Installation
```
0. You can run the installer.sh

1. Clone the repository:
   git clone https://github.com/marcidelux/NATS-Publisher-GUI.git
   cd nats-publisher-gui

2. Create virtual env:
python -m venv .venv
source .venv/bin/activate  # On Windows, use .venv\Scripts\activate

3. Install requried packages:
pip install -r requirements.txt

4. Create configuration file:
If it was not created a default file will be created at first startup:
hosts:
  - "nats://localhost:4222"
machine_serial_numbers:
- '123456789'
topic:
  - "topic1"
messages:
  - '{"type": "greeting", "message": "hello"}'

```
### Start the software:
`python main.py`
Or run the executeable.

### Setup NATS path.
Depending on the installation of the NATS on the target machine check its executeable PATH.  
On the target machine: `which nats`, copy the response and paste it to the nats_config.yaml/nats_path.