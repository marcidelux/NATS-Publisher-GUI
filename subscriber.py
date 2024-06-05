# subscriber.py
import sys
import asyncio
import asyncssh
import json
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QTextEdit, QMessageBox, QLabel
from PyQt6.QtCore import QTimer
from qasync import QEventLoop, asyncSlot

class SubscriptionWindow(QWidget):
    def __init__(self, ssh_address, ssh_username, ssh_password, nats_path, server, topic, machine_serial_number):
        super().__init__()
        full_topic = machine_serial_number + "." + topic
        self.setWindowTitle('NATS Subscription: ' + full_topic)
        self.setGeometry(150, 150, 500, 400)

        self.ssh_address = ssh_address
        self.ssh_username = ssh_username
        self.ssh_password = ssh_password
        self.nats_path = nats_path
        self.server = server
        self.topic = topic
        self.machine_serial_number = machine_serial_number
        self.ssh_client = None

        self.layout = QVBoxLayout()

        self.label = QLabel()
        self.label.setText(full_topic)
        self.layout.addWidget(self.label)

        self.text_area = QTextEdit()
        self.text_area.setReadOnly(True)
        self.layout.addWidget(self.text_area)

        self.setLayout(self.layout)

        # Schedule the SSH connection for the event loop
        QTimer.singleShot(0, self.schedule_ssh_connection)

    def schedule_ssh_connection(self):
        asyncio.ensure_future(self.connect_ssh())

    @asyncSlot()
    async def connect_ssh(self):
        try:
            self.ssh_client = await asyncssh.connect(
                self.ssh_address, username=self.ssh_username, password=self.ssh_password
            )
            # Now subscribe to the topic after establishing SSH connection
            self.subscribe_to_topic()
        except Exception as e:
            self.ssh_client = None
            QMessageBox.critical(self, 'Error', f'Failed to establish SSH connection: {e}')
            self.close()

    @asyncSlot()
    async def subscribe_to_nats(self, full_topic):
        async with self.ssh_client.create_process(f'{self.nats_path} sub {full_topic} -s {self.server}') as process:
            async for line in process.stdout:
                self.display_message(line.strip())

    def display_message(self, message):
        # Find the first '{' and the last '}' to extract JSON content
        start_index = message.find('{')
        end_index = message.rfind('}') + 1
        if start_index != -1 and end_index != -1:
            json_part = message[start_index:end_index]
            try:
                # Pretty print the JSON part
                json_message = json.loads(json_part)
                pretty_json_message = json.dumps(json_message, indent=2)
                self.text_area.append(pretty_json_message)
                self.text_area.append("")
            except json.JSONDecodeError:
                # If JSON parsing fails, just display the raw line
                self.text_area.append(message.strip())
                self.text_area.append("")

    def subscribe_to_topic(self):
        full_topic = f'{self.machine_serial_number}.{self.topic}'
        asyncio.ensure_future(self.subscribe_to_nats(full_topic))

if __name__ == '__main__':
    import qasync

    # Extract arguments from command line
    ssh_address = sys.argv[1]
    ssh_username = sys.argv[2]
    ssh_password = sys.argv[3]
    nats_path = sys.argv[4]
    server = sys.argv[5]
    topic = sys.argv[6]
    machine_serial_number = sys.argv[7]

    app = QApplication(sys.argv)
    loop = QEventLoop(app)
    asyncio.set_event_loop(loop)

    window = SubscriptionWindow(ssh_address, ssh_username, ssh_password, nats_path, server, topic, machine_serial_number)
    window.show()

    with loop:
        loop.run_forever()
