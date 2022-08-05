# This file is part of the ALTRepo Uploader distribution (http://git.altlinux.org/people/dshein/public/altrepodb.git).
# Copyright (c) 2021-2022 BaseALT Ltd
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import ssl
import pika
from dataclasses import dataclass
from pika import spec as pika_spec
from pika.adapters.blocking_connection import BlockingChannel
from pika.adapters import BlockingConnection
from typing import Optional, Union
from altrepodb import __version__


@dataclass
class AMQPMessage:
    method: pika_spec.Basic.Deliver
    properties: pika_spec.BasicProperties
    body_json: bytes


@dataclass
class AMQPConfig:
    host: str = "localhost"
    port: int = 5672
    vhost: str = "/"
    queue: str = "default"
    exchange: str = "amq.topic"
    username: str = "guest"
    password: str = "guest"
    cacert: str = ""
    key: str = ""
    cert: str = ""
    prefetch_count: int = 10
    product: str = "ALTRepoDB uploaderd"
    information: str = ""
    version: str = __version__

    def test_connection(self):
        credentials = pika.PlainCredentials(self.username, self.password)
        ssl_options = None
        conn = None

        if self.cacert:
            context = ssl.create_default_context(cafile=self.cacert)
            if self.key and self.cert:
                context.load_cert_chain(self.cert, self.key)
            ssl_options = pika.SSLOptions(context)

        parameters = pika.ConnectionParameters(
            host=self.host,
            port=self.port,
            virtual_host=self.vhost,
            credentials=credentials,
            ssl_options=ssl_options,
            heartbeat=0,
        )

        try:
            conn = pika.BlockingConnection(parameters)
            return True
        except Exception:
            return False
        finally:
            if conn:
                conn.close()


class BlockingAMQPClient:
    """Simple AMQP Publisher that ensures and maintains a connection"""

    def __init__(self, config: AMQPConfig):
        self.config = config
        self.connection: BlockingConnection = None  # type: ignore
        self.channel: BlockingChannel = None  # type: ignore

        credentials = pika.PlainCredentials(self.config.username, self.config.password)
        ssl_options = None

        if self.config.cacert:
            context = ssl.create_default_context(cafile=self.config.cacert)
            if self.config.key and self.config.cert:
                context.load_cert_chain(self.config.cert, self.config.key)
            ssl_options = pika.SSLOptions(context)

        self.parameters = pika.ConnectionParameters(
            host=self.config.host,
            port=self.config.port,
            virtual_host=self.config.vhost,
            credentials=credentials,
            ssl_options=ssl_options,
            heartbeat=0,
            client_properties={
                "product": self.config.product,
                "information": self.config.information,
                "version": self.config.version,
            },
        )

    def ensure_connection(self):
        if not self.connection or not self.connection.is_open:
            self.connection = BlockingConnection(self.parameters)

    def ensure_channel(self):
        self.ensure_connection()
        if not self.channel or not self.channel.is_open:
            self.channel = self.connection.channel()
            self.channel.confirm_delivery()

    def publish(
        self,
        routing_key: str,
        body: Union[bytes, str],
        properties: Optional[pika_spec.BasicProperties] = None,
        mandatory: bool = False,
    ):
        self.ensure_channel()
        self.channel.basic_publish(
            self.config.exchange, routing_key, body, properties, mandatory
        )

    def stop(self):
        if self.channel and self.channel.is_open:
            self.channel.close()

        if self.connection and self.connection.is_open:
            self.connection.close()

    def ack_message(self, delivery_tag):
        self.channel.basic_ack(delivery_tag)

    def reject_message(self, delivery_tag, requeue=False):
        self.channel.basic_reject(delivery_tag, requeue)

    def get_message(self) -> Optional[AMQPMessage]:
        method, properties, body = self.channel.basic_get(self.config.queue)
        if method is None:
            return None
        return AMQPMessage(method=method, properties=properties, body_json=body)  # type: ignore
