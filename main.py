import sys
import asyncio
import yaml
import os
import paramiko
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QComboBox, QLineEdit, 
    QPushButton, QMessageBox, QFileDialog, QTextEdit, QHBoxLayout, QInputDialog, QCheckBox
)
import datetime
import json
from collections import OrderedDict
import subprocess

CONFIG_FILE = 'nats_config.yaml'
nats_path = ""

def represent_ordereddict(dumper, data):
    return dumper.represent_mapping(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, data.items())

yaml.add_representer(OrderedDict, represent_ordereddict)

class NATSClient(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle('NATS Publisher')
        self.setGeometry(100, 100, 500, 450)

        self.ssh_client = None

        self.layout = QVBoxLayout()

        self.load_button = QPushButton('Load Config')
        self.load_button.clicked.connect(self.load_config_file)
        self.layout.addWidget(self.load_button)

        self.ssh_label = QLabel('SSH Address:')
        self.ssh_input = QLineEdit()
        self.layout.addWidget(self.ssh_label)
        self.layout.addWidget(self.ssh_input)

        self.ssh_user_label = QLabel('SSH Username:')
        self.ssh_user_input = QLineEdit()
        self.layout.addWidget(self.ssh_user_label)
        self.layout.addWidget(self.ssh_user_input)

        self.ssh_pass_label = QLabel('SSH Password:')
        self.ssh_pass_input = QLineEdit()
        self.ssh_pass_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.layout.addWidget(self.ssh_pass_label)
        self.layout.addWidget(self.ssh_pass_input)

        self.connect_button = QPushButton('Connect SSH')
        self.connect_button.clicked.connect(self.connect_ssh)
        self.layout.addWidget(self.connect_button)

        self.server_label = QLabel('NATS Server Address:')
        self.server_combo_layout = QHBoxLayout()
        self.server_combo = QComboBox()
        self.add_new_host_button = QPushButton('Add New')
        self.add_new_host_button.setFixedWidth(100)
        self.add_new_host_button.clicked.connect(self.check_add_new_host)
        self.server_combo_layout.addWidget(self.server_combo)
        self.server_combo_layout.addWidget(self.add_new_host_button)
        self.layout.addWidget(self.server_label)
        self.layout.addLayout(self.server_combo_layout)

        self.machine_serial_label = QLabel('Machine Serial Number:')
        self.machine_serial_combo_layout = QHBoxLayout()
        self.machine_serial_combo = QComboBox()
        self.add_new_serial_button = QPushButton('Add New')
        self.add_new_serial_button.setFixedWidth(100)
        self.add_new_serial_button.clicked.connect(self.check_add_new_serial)
        self.machine_serial_combo_layout.addWidget(self.machine_serial_combo)
        self.machine_serial_combo_layout.addWidget(self.add_new_serial_button)
        self.layout.addWidget(self.machine_serial_label)
        self.layout.addLayout(self.machine_serial_combo_layout)

        self.topic_label = QLabel('Topic:')
        self.topic_combo_layout = QHBoxLayout()
        self.topic_combo = QComboBox()
        self.datapoint_checkbox = QCheckBox("datapoint")
        self.datapoint_checkbox.setFixedWidth(70)
        self.add_new_topic_button = QPushButton('Add New')
        self.add_new_topic_button.setFixedWidth(100)
        self.add_new_topic_button.clicked.connect(self.check_add_new_topic)
        self.topic_combo_layout.addWidget(self.topic_combo)
        self.topic_combo_layout.addWidget(self.datapoint_checkbox)
        self.topic_combo_layout.addWidget(self.add_new_topic_button)
        self.layout.addWidget(self.topic_label)
        self.layout.addLayout(self.topic_combo_layout)
        
        self.open_subscription_button = QPushButton('Subscribe to Topic')
        self.layout.addWidget(self.open_subscription_button)

        self.message_label = QLabel('Message:')
        self.message_combo_layout = QHBoxLayout()
        self.message_combo = QComboBox()
        self.add_new_message_button = QPushButton('Add New')
        self.add_new_message_button.setFixedWidth(100)
        self.add_new_message_button.clicked.connect(self.check_add_new_message)
        self.message_combo_layout.addWidget(self.message_combo)
        self.message_combo_layout.addWidget(self.add_new_message_button)
        self.layout.addWidget(self.message_label)
        self.layout.addLayout(self.message_combo_layout)

        self.send_button = QPushButton('Send')
        self.send_button.clicked.connect(self.send_message)
        self.layout.addWidget(self.send_button)

        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        self.log_area.setStyleSheet("background-color: lightgrey;")
        self.layout.addWidget(self.log_area)
        
        self.setLayout(self.layout)

        if not os.path.exists(CONFIG_FILE):
            self.create_default_config()
        self.config_file = CONFIG_FILE
        self.load_config()  # Load the initial config

    def create_default_config(self):
        default_config = OrderedDict()
        default_config['ssh_address'] = '127.0.0.1'
        default_config['ssh_username'] = 'vagrant'
        default_config['nats_path'] = '/usr/bin'
        default_config['get_nats_ip_command'] = 'docker inspect nats | jq -r \'.[0].NetworkSettings.Ports."4222/tcp"[0].HostIp\''
        default_config['hosts'] = ["nats://localhost:8222"]
        default_config['topics'] = ["topic1"]
        default_config['machine_serial_numbers'] = ["123456789"]
        default_config['messages'] = [
            '{"message_name1": {"key1": "value1"}}'
        ]

        with open(CONFIG_FILE, 'w') as file:
            yaml.dump(default_config, file, default_flow_style=False)

    def load_config_file(self):
        file_dialog = QFileDialog(self)
        file_path, _ = file_dialog.getOpenFileName(self, "Open Config File", "", "YAML Files (*.yaml);;All Files (*)")
        if file_path:
            self.config_file = file_path
            self.load_config()

    def load_config(self):
        with open(self.config_file, 'r') as file:
            config = yaml.safe_load(file)
            self.hosts = config.get('hosts', [])
            self.topics = config.get('topics', [])
            self.messages = config.get('messages', [])
            self.machine_serial_numbers = config.get('machine_serial_numbers', [])
            self.ssh_address = config.get('ssh_address', '')
            self.ssh_username = config.get('ssh_username', '')
            self.nats_path = config.get('nats_path', '/usr/bin')
            self.get_nats_ip_command = config.get('get_nats_ip_command', 'docker inspect nats | jq -r \'.[0].NetworkSettings.Ports."4222/tcp"[0].HostIp\'')

        self.server_combo.clear()
        self.server_combo.addItems(self.hosts)
        self.topic_combo.clear()
        self.topic_combo.addItems(self.topics)
        self.message_combo.clear()
        self.message_names = [list(json.loads(msg).keys())[0] for msg in self.messages]
        self.message_combo.addItems(self.message_names)
        self.machine_serial_combo.clear()
        self.machine_serial_combo.addItems(self.machine_serial_numbers)
        self.ssh_input.setText(self.ssh_address)
        self.ssh_user_input.setText(self.ssh_username)

    def save_config(self):
        config = OrderedDict()
        config['hosts'] = self.hosts
        config['topics'] = self.topics
        config['messages'] = self.messages
        config['machine_serial_numbers'] = self.machine_serial_numbers
        config['ssh_address'] = self.ssh_address
        config['ssh_username'] = self.ssh_username
        config['nats_path'] = self.nats_path
        config['get_nats_ip_command'] = self.get_nats_ip_command

        with open(self.config_file, 'w') as file:
            yaml.dump(config, file, default_flow_style=False)

    def check_add_new_host(self):
        new_host, ok = QInputDialog.getText(self, 'Add New Host', 'Enter new host name:')
        if ok and new_host:
            self.hosts.append(new_host)
            self.server_combo.addItem(new_host)
            self.save_config()

    def check_add_new_serial(self):
        new_serial, ok = QInputDialog.getText(self, 'Add New Serial Number', 'Enter new serial number:')
        if ok and new_serial:
            self.machine_serial_numbers.append(new_serial)
            self.machine_serial_combo.addItem(new_serial)
            self.save_config()

    def check_add_new_topic(self):
        new_topic, ok = QInputDialog.getText(self, 'Add New Topic', 'Enter new topic name:')
        if ok and new_topic:
            self.topics.append(new_topic)
            self.topic_combo.addItem(new_topic)
            self.save_config()

    def check_add_new_message(self):
        new_message_name, ok = QInputDialog.getText(self, 'Add New Message Name', 'Enter new message name:')
        if ok and new_message_name:
            new_message_content, ok = QInputDialog.getText(self, 'Add New Message Content', 'Enter new message content as JSON:')
            if ok and new_message_content:
                try:
                    # Ensure the message content is valid JSON
                    json.loads(new_message_content)
                    new_message = json.dumps({new_message_name: json.loads(new_message_content)})
                    self.messages.append(new_message)
                    self.message_combo.addItem(new_message_name)
                    self.save_config()
                except json.JSONDecodeError:
                    QMessageBox.warning(self, 'Input Error', 'Invalid JSON content for message.')

    def connect_ssh(self):
        ssh_address = self.ssh_input.text()
        ssh_username = self.ssh_user_input.text()
        ssh_password = self.ssh_pass_input.text()

        if not ssh_address or not ssh_username or not ssh_password:
            QMessageBox.warning(self, 'Input Error', 'Please fill in all SSH fields.')
            return

        self.ssh_client = paramiko.SSHClient()
        self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.ssh_client.connect(ssh_address, port=22, username=ssh_username, password=ssh_password)
            self.log_info('SSH connection established successfully!')
            if self.get_nats_ip():
                self.connect_button.setStyleSheet("background-color: green; color: black;")
                self.connect_button.setDisabled(True)
                self.connect_button.setText(f"CONNECTED TO: {self.ssh_address}-{self.nats_host_ip}")
        except Exception as e:
            self.ssh_client = None
            QMessageBox.critical(self, 'Error', f'Failed to establish SSH connection: {e}')

    def send_message(self):
        server = self.nats_host_ip
        topic = self.topic_combo.currentText()
        message_name = self.message_combo.currentText()
        machine_serial_number = self.machine_serial_combo.currentText()
        is_datapoint = self.datapoint_checkbox.isChecked()

        if not server or not topic or not message_name:
            QMessageBox.warning(self, 'Input Error', 'Please fill in all fields.')
            return
        # Get the actual message based on the selected name
        for msg in self.messages:
            msg_dict = json.loads(msg)
            if message_name in msg_dict:
                message = json.dumps(msg_dict[message_name])
                break
    
        if self.ssh_client:
            asyncio.create_task(self.publish_message_ssh(server, topic, message, machine_serial_number, is_datapoint))
        else:
            asyncio.create_task(self.publish_message_local(server, topic, message, machine_serial_number, is_datapoint))

    def log_response(self, message):
        self.log_area.append(f'<span style="color: blue;">{message}</span>')
        self.log_area.verticalScrollBar().setValue(self.log_area.verticalScrollBar().maximum())

    def log_error(self, message):
        self.log_area.append(f'<span style="color: red;">{message}</span>')
        self.log_area.verticalScrollBar().setValue(self.log_area.verticalScrollBar().maximum())

    def log_info(self, message):
        self.log_area.append(f'<span style="color: green;">{message}</span>')
        self.log_area.verticalScrollBar().setValue(self.log_area.verticalScrollBar().maximum())

    def add_timestamp_to_message(self, message):
        message_dict = json.loads(message)
        current_time = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')
        message_dict['ts'] = current_time
        return json.dumps(message_dict)

    def get_nats_ip(self):
        if self.ssh_client:
            try:
                command = self.get_nats_ip_command
                stdin, stdout, stderr = self.ssh_client.exec_command(command)
                stdout.channel.recv_exit_status()
                response = stdout.read().decode().strip()
                error = stderr.read().decode().strip()

                self.log_info(f'Command: {command}')
                if error:
                    self.log_error(f'Error: {error}')
                    QMessageBox.critical(self, 'Error', f'Failed to get NATS IP: {error}')
                    return False
                else:
                    self.log_response(f'NATS IP: {response}')
                    self.nats_host_ip = response
                    return True

            except Exception as e:
                self.log_error(f'Exception: {e}')
                QMessageBox.critical(self, 'Error', f'Failed to get NATS IP: {e}')
                return False
        else:
            QMessageBox.warning(self, 'SSH Error', 'SSH connection not established.')
            return False

    async def publish_message_ssh(self, server, topic, message, machine_serial_number, is_datapoint):
        global nats_path
        try:
            if not nats_path:
                nats_path = self.nats_path

            message_with_timestamp = self.add_timestamp_to_message(message)
            topic_path = f"{machine_serial_number}.telemetry.{topic}" if is_datapoint else f"{machine_serial_number}.{topic}"
            escaped_json_message = message_with_timestamp.replace('"', '\\"')
            command = f'/bin/bash -c \'{nats_path} pub {topic_path} "{escaped_json_message}" -s {server}\''
            _, stdout, stderr = self.ssh_client.exec_command(command)
            stdout.channel.recv_exit_status()
            response = stdout.read().decode()
            error = stderr.read().decode()

            self.log_info(f'Command: {command}')
            if error and "Published" not in error:
                self.log_error(f'Error: {error}')
                QMessageBox.critical(self, 'Error', f'Failed to send message: {error}')
            else:
                self.log_response(f'Response: {error}')
            if response:
                self.log_response(f'Response: {response}')

        except Exception as e:
            self.log_error(f'Exception: {e}')
            QMessageBox.critical(self, 'Error', f'Failed to send message: {e}')

    async def publish_message_local(self, server, topic, message, machine_serial_number, is_datapoint):
        message_with_timestamp = self.add_timestamp_to_message(message)
        topic_path = f"{machine_serial_number}.telemetry.{topic}" if is_datapoint else f"{machine_serial_number}.{topic}"
        command = f'nats pub {topic_path} "{message_with_timestamp}" -s {server}'
        self.log_info(f'Command: {command}')
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            self.log_error(f'Error: {stderr.decode()}')
            QMessageBox.critical(self, 'Error', f'Failed to send message: {stderr.decode()}')
        else:
            self.log_response(f'Response: {stdout.decode()}')
            QMessageBox.information(self, 'Success', 'Message sent successfully!')
    
    def open_subscription_window(self):
        ssh_address = self.ssh_input.text()
        ssh_username = self.ssh_user_input.text()
        ssh_password = self.ssh_pass_input.text()
        nats_path = self.nats_path
        server = self.nats_host_ip
        topic = self.topic_combo.currentText()
        machine_serial_number = self.machine_serial_combo.currentText()

        subprocess.Popen([
            'subscriber.exe',  # Ensure subscriber.exe is in the same directory or provide the full path
            ssh_address, ssh_username, ssh_password, nats_path, server, topic, machine_serial_number
        ])

if __name__ == '__main__':
    import qasync

    app = QApplication(sys.argv)
    loop = qasync.QEventLoop(app)
    asyncio.set_event_loop(loop)

    client = NATSClient()
    client.show()

    with loop:
        loop.run_forever()
