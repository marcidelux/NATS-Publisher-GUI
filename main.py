import sys
import asyncio
import yaml
import os
from PyQt6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QLabel, QComboBox, QLineEdit, QPushButton, QMessageBox, QInputDialog)
from nats.aio.client import Client as NATS

DEFAULT_CONFIG = {
    'hosts': [
        'nats://localhost:4222'
    ],
    'channels': [
        'channel1'
    ],
    'messages': [
        '{"type": "greeting", "message": "hello"}'
    ]
}

class NATSClient(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle('NATS Publisher')
        self.setGeometry(100, 100, 400, 200)

        self.ensure_config_exists()
        self.load_config()

        self.layout = QVBoxLayout()

        self.server_label = QLabel('NATS Server Address:')
        self.server_combo = QComboBox()
        self.server_combo.addItems(self.hosts + ["Add New"])
        self.server_combo.currentIndexChanged.connect(self.check_add_new_host)
        self.layout.addWidget(self.server_label)
        self.layout.addWidget(self.server_combo)

        self.channel_label = QLabel('Channel:')
        self.channel_combo = QComboBox()
        self.channel_combo.addItems(self.channels + ["Add New"])
        self.channel_combo.currentIndexChanged.connect(self.check_add_new_channel)
        self.layout.addWidget(self.channel_label)
        self.layout.addWidget(self.channel_combo)

        self.message_label = QLabel('Message:')
        self.message_combo = QComboBox()
        self.message_combo.addItems(self.messages + ["Add New"])
        self.message_combo.currentIndexChanged.connect(self.check_add_new_message)
        self.layout.addWidget(self.message_label)
        self.layout.addWidget(self.message_combo)

        self.send_button = QPushButton('Send')
        self.send_button.clicked.connect(self.send_message)
        self.layout.addWidget(self.send_button)

        self.setLayout(self.layout)

    def ensure_config_exists(self):
        if not os.path.exists('nats_config.yaml'):
            with open('nats_config.yaml', 'w') as file:
                yaml.dump(DEFAULT_CONFIG, file)

    def load_config(self):
        with open('nats_config.yaml', 'r') as file:
            config = yaml.safe_load(file)
            self.hosts = config.get('hosts', [])
            self.channels = config.get('channels', [])
            self.messages = config.get('messages', [])

    def save_config(self):
        with open('nats_config.yaml', 'w') as file:
            yaml.dump({'hosts': self.hosts, 'channels': self.channels, 'messages': self.messages}, file)

    def check_add_new_host(self):
        if self.server_combo.currentText() == "Add New":
            new_host, ok = QInputDialog.getText(self, 'Add New Host', 'Enter new host name:')
            if ok and new_host:
                self.hosts.append(new_host)
                self.server_combo.insertItem(self.server_combo.count() - 1, new_host)
                self.server_combo.setCurrentText(new_host)
                self.save_config()

    def check_add_new_channel(self):
        if self.channel_combo.currentText() == "Add New":
            new_channel, ok = QInputDialog.getText(self, 'Add New Channel', 'Enter new channel name:')
            if ok and new_channel:
                self.channels.append(new_channel)
                self.channel_combo.insertItem(self.channel_combo.count() - 1, new_channel)
                self.channel_combo.setCurrentText(new_channel)
                self.save_config()

    def check_add_new_message(self):
        if self.message_combo.currentText() == "Add New":
            new_message, ok = QInputDialog.getText(self, 'Add New Message', 'Enter new message:')
            if ok and new_message:
                self.messages.append(new_message)
                self.message_combo.insertItem(self.message_combo.count() - 1, new_message)
                self.message_combo.setCurrentText(new_message)
                self.save_config()

    def send_message(self):
        server = self.server_combo.currentText()
        channel = self.channel_combo.currentText()
        message = self.message_combo.currentText()

        if not server or not channel or not message:
            QMessageBox.warning(self, 'Input Error', 'Please fill in all fields.')
            return

        asyncio.run(self.publish_message(server, channel, message))

    async def publish_message(self, server, channel, message):
        nc = NATS()

        try:
            await nc.connect(servers=[server])
            await nc.publish(channel, message.encode())
            await nc.drain()
            QMessageBox.information(self, 'Success', 'Message sent successfully!')
        except Exception as e:
            QMessageBox.critical(self, 'Error', f'Failed to send message: {e}')
        finally:
            await nc.close()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    client = NATSClient()
    client.show()
    sys.exit(app.exec())
