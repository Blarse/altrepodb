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

from __future__ import annotations

import ssl
import pika
from dataclasses import dataclass
from pika import spec as pika_spec
from pika.adapters.blocking_connection import BlockingChannel
from pika.adapters import BlockingConnection
from pika.exchange_type import ExchangeType
from typing import Optional, Union, List, NamedTuple, Any

from altrepodb import __version__


@dataclass
class AMQPMessage:
    method: pika_spec.Basic.Deliver
    properties: pika_spec.BasicProperties
    body_json: bytes


class AMQPBinding(NamedTuple):
    exchange: str
    routing_key: str


class AMQPQueueConfig(NamedTuple):
    name: str = ""
    type: str = "classic"
    durable: bool = True
    exclusive: bool = False
    auto_delete: bool = False
    bind_at_startup: List[AMQPBinding] = list()
    unbind_at_startup: List[AMQPBinding] = list()


class AMQPConfig(NamedTuple):
    host: str = "localhost"
    port: int = 5672
    vhost: str = "/"
    queue: AMQPQueueConfig = None  # type: ignore
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

    @staticmethod
    def parse_config(config: dict[str, Any], information: str) -> AMQPConfig:
        amqp_config = AMQPConfig(**config)
        queue_config = AMQPQueueConfig(**config["queue"])

        return amqp_config._replace(
            queue=queue_config._replace(
                bind_at_startup=[AMQPBinding(**b) for b in queue_config.bind_at_startup],  # type: ignore
                unbind_at_startup=[AMQPBinding(**b) for b in queue_config.unbind_at_startup],  # type: ignore
            ),
            information=information,
        )


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

        self.queue_ensured = False
        self.exchange_ensured = False

    def ensure_exchange(self):
        self.ensure_channel()
        if not self.exchange_ensured:
            self.channel.exchange_declare(
                exchange=self.config.exchange,
                exchange_type=ExchangeType.topic,
                passive=False,
                durable=True,
                auto_delete=False,
                internal=False,
            )

        self.exchange_ensured = True

    def ensure_connection(self):
        if not self.connection or not self.connection.is_open:
            self.connection = BlockingConnection(self.parameters)

    def ensure_channel(self):
        self.ensure_connection()
        if not self.channel or not self.channel.is_open:
            self.channel = self.connection.channel()
            self.channel.confirm_delivery()

    def ensure_queue(self):
        self.ensure_channel()
        if not self.queue_ensured:
            self.channel.queue_declare(
                queue=self.config.queue.name,
                durable=self.config.queue.durable,
                exclusive=self.config.queue.exclusive,
                auto_delete=self.config.queue.auto_delete,
                arguments={"x-queue-type": self.config.queue.type},
            )

            for binding in self.config.queue.bind_at_startup:
                self.channel.queue_bind(
                    self.config.queue.name, binding.exchange, binding.routing_key
                )

            for binding in self.config.queue.unbind_at_startup:
                self.channel.queue_unbind(
                    self.config.queue.name, binding.exchange, binding.routing_key
                )

        self.queue_ensured = True

    def publish(
        self,
        routing_key: str,
        body: Union[bytes, str],
        properties: Optional[pika_spec.BasicProperties] = None,
        mandatory: bool = False,
    ):
        self.ensure_exchange()

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
        self.ensure_queue()

        method, properties, body = self.channel.basic_get(self.config.queue.name)
        if method is None:
            return None

        return AMQPMessage(method=method, properties=properties, body_json=body)  # type: ignore
