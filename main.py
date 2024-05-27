import sys
import asyncio
import yaml
import os
import paramiko
from PyQt6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QLabel, QComboBox, QLineEdit, QPushButton, QMessageBox, QFileDialog, QTextEdit, QHBoxLayout, QInputDialog)
import datetime
import json

CONFIG_FILE = 'nats_config.yaml'
nats_path = ""

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

        self.get_nats_ip_button = QPushButton('Get NATS IP')
        self.get_nats_ip_button.clicked.connect(self.get_nats_ip)
        self.layout.addWidget(self.get_nats_ip_button)

        self.server_label = QLabel('NATS Server Address:')
        self.server_combo_layout = QHBoxLayout()
        self.server_combo = QComboBox()
        self.add_new_host_button = QPushButton('Add New')
        self.add_new_host_button.clicked.connect(self.check_add_new_host)
        self.server_combo_layout.addWidget(self.server_combo)
        self.server_combo_layout.addWidget(self.add_new_host_button)
        self.layout.addWidget(self.server_label)
        self.layout.addLayout(self.server_combo_layout)

        self.topic_label = QLabel('Topic:')
        self.topic_combo_layout = QHBoxLayout()
        self.topic_combo = QComboBox()
        self.add_new_topic_button = QPushButton('Add New')
        self.add_new_topic_button.clicked.connect(self.check_add_new_topic)
        self.topic_combo_layout.addWidget(self.topic_combo)
        self.topic_combo_layout.addWidget(self.add_new_topic_button)
        self.layout.addWidget(self.topic_label)
        self.layout.addLayout(self.topic_combo_layout)

        self.message_label = QLabel('Message:')
        self.message_combo_layout = QHBoxLayout()
        self.message_combo = QComboBox()
        self.add_new_message_button = QPushButton('Add New')
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
        default_config = {
            'hosts': ["nats://localhost:8222"],
            'topics': ["topic1"],
            'messages': [
                '{"type": "greeting", "message": "hello"}'
            ],
            'ssh_address': '127.0.0.1',
            'ssh_username': 'vagrant',
            'nats_path': '/usr/bin',
            'get_nats_ip_command': 'docker inspect nats | jq -r \'.[0].NetworkSettings.Ports."4222/tcp"[0].HostIp\''
        }
        with open(CONFIG_FILE, 'w') as file:
            yaml.dump(default_config, file)

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
            self.ssh_address = config.get('ssh_address', '')
            self.ssh_username = config.get('ssh_username', '')
            self.nats_path = config.get('nats_path', '/usr/bin')
            self.get_nats_ip_command = config.get('get_nats_ip_command', 'docker inspect nats | jq -r \'.[0].NetworkSettings.Ports."4222/tcp"[0].HostIp\'')

        self.server_combo.clear()
        self.server_combo.addItems(self.hosts)
        self.topic_combo.clear()
        self.topic_combo.addItems(self.topics)
        self.message_combo.clear()
        self.message_combo.addItems(self.messages)
        self.ssh_input.setText(self.ssh_address)
        self.ssh_user_input.setText(self.ssh_username)

    def save_config(self):
        with open(self.config_file, 'w') as file:
            yaml.dump({
                'topics': self.topics,
                'messages': self.messages,
                'ssh_address': self.ssh_address,
                'ssh_username': self.ssh_username,
                'nats_path': self.nats_path,
                'get_nats_ip_command': self.get_nats_ip_command,
            }, file)

    def check_add_new_host(self):
        new_host, ok = QInputDialog.getText(self, 'Add New Host', 'Enter new host name:')
        if ok and new_host:
            self.hosts.append(new_host)
            self.server_combo.addItem(new_host)
            self.save_config()

    def check_add_new_topic(self):
        new_topic, ok = QInputDialog.getText(self, 'Add New Topic', 'Enter new topic name:')
        if ok and new_topic:
            self.topics.append(new_topic)
            self.topic_combo.addItem(new_topic)
            self.save_config()

    def check_add_new_message(self):
        new_message, ok = QInputDialog.getText(self, 'Add New Message', 'Enter new message:')
        if ok and new_message:
            self.messages.append(new_message)
            self.message_combo.addItem(new_message)
            self.save_config()

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
        except Exception as e:
            self.ssh_client = None
            QMessageBox.critical(self, 'Error', f'Failed to establish SSH connection: {e}')

    def send_message(self):
        server = self.server_combo.currentText()
        topic = self.topic_combo.currentText()
        message = self.message_combo.currentText()

        if not server or not topic or not message:
            QMessageBox.warning(self, 'Input Error', 'Please fill in all fields.')
            return

        if self.ssh_client:
            asyncio.run(self.publish_message_ssh(server, topic, message))
        else:
            asyncio.run(self.publish_message_local(server, topic, message))

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
                else:
                    self.log_response(f'NATS IP: {response}')
                    if response and response not in self.hosts:
                        self.hosts.append(response)
                        self.server_combo.addItem(response)
                        self.save_config()

            except Exception as e:
                self.log_error(f'Exception: {e}')
                QMessageBox.critical(self, 'Error', f'Failed to get NATS IP: {e}')
        else:
            QMessageBox.warning(self, 'SSH Error', 'SSH connection not established.')

    async def publish_message_ssh(self, server, topic, message):
        global nats_path
        try:
            if not nats_path:
                nats_path = self.nats_path

            message_with_timestamp = self.add_timestamp_to_message(message)
            escaped_json_message = message_with_timestamp.replace('"', '\\"')
            command = f'/bin/bash -c \'{nats_path} pub {topic} "{escaped_json_message}" -s {server}\''
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

    async def publish_message_local(self, server, topic, message):
        message_with_timestamp = self.add_timestamp_to_message(message)
        command = f'nats pub {topic} "{message_with_timestamp}" -s {server}'
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

if __name__ == '__main__':
    app = QApplication(sys.argv)
    client = NATSClient()
    client.show()
    sys.exit(app.exec())
