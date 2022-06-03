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
import asyncio
import threading
import functools
from logging import Logger
from dataclasses import dataclass
from pika.channel import Channel
from pika.adapters.asyncio_connection import AsyncioConnection
from pika.adapters import BlockingConnection
from typing import Any, Optional


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


class AMQPClient:
    def __init__(
        self,
        logger: Logger,
        config: AMQPConfig,
        custom_loop: Optional[asyncio.AbstractEventLoop] = None,
    ):
        self.logger = logger
        self.config = config
        self.ioloop = custom_loop
        self._thread_ident = threading.get_ident()
        self._connection: AsyncioConnection = None  # type: ignore
        self._channel: Channel = None  # type: ignore
        self._consumer_tag: str = None  # type: ignore
        self._closing = False
        self._consuming = False
        self.reason: Any = None
        self.events = {
            "connection": asyncio.Event(),
            "channel": asyncio.Event(),
            "stop": asyncio.Event(),
        }

    def start(self):
        self.logger.debug("Starting")
        self._connection = self.connect()

    def stop(self):
        if not self._closing:
            self._closing = True
            self.logger.debug("Stopping")
            if self._consuming:
                self.stop_consuming()
            self.logger.debug("Stopped")

    def connect(self):
        self.logger.debug("Connecting")
        self.events["stop"].clear()
        credentials = pika.PlainCredentials(self.config.username, self.config.password)
        ssl_options = None

        if self.config.cacert:
            self.logger.debug("SSL connection")
            context = ssl.create_default_context(cafile=self.config.cacert)
            if self.config.key and self.config.cert:
                context.load_cert_chain(self.config.cert, self.config.key)
            ssl_options = pika.SSLOptions(context)

        parameters = pika.ConnectionParameters(
            host=self.config.host,
            port=self.config.port,
            virtual_host=self.config.vhost,
            credentials=credentials,
            ssl_options=ssl_options,
            heartbeat=0,
        )

        return AsyncioConnection(
            parameters=parameters,
            custom_ioloop=self.ioloop,
            on_open_callback=self.on_connection_open,
            on_open_error_callback=self.on_connection_open_error,
            on_close_callback=self.on_connection_close,
        )

    def close_connection(self):
        self._consuming = False
        self._consumer_tag = ""
        self.events["connection"].clear()
        if self._connection.is_closing or self._connection.is_closed:
            self.logger.debug("Connection is closing or already closed")
        else:
            self.logger.debug("Closing connection")
            self._connection.close()

    # def reconnect(self):
    #     if not self._closing:
    #         self.logger.debug("Reconnecting")
    #         self._connection = self.connect()

    def on_connection_open(self, _unused_connection):
        self.logger.debug("Connection opened")
        self.events["connection"].set()
        # self._reconnect_delay = 0
        self.open_channel()

    def on_connection_open_error(self, _unused_connection, error):
        self.logger.debug(f"Connection open error: {error}")
        self.reason = error
        self.events["connection"].clear()
        # self.logger.info(f"Reconnecting after {self._reconnect_delay} seconds")
        # self._connection.ioloop.call_later(self._reconnect_delay, self.reconnect)
        # if self._reconnect_delay < 10:
        #     self._reconnect_delay += 1

    def on_connection_close(self, _unused_connection, reason):
        self.logger.debug(f"Connection closed: {reason}")
        self.reason = reason
        self.events["connection"].clear()
        self._channel = None  # type: ignore
        self.events["stop"].set()
        # if self._closing:
        #     self._connection.ioloop.stop()
        # else:
        #     self.logger.info(f"Reconnecting after {self._reconnect_delay} seconds")
        #     self._connection.ioloop.call_later(self._reconnect_delay, self.reconnect)
        #     if self._reconnect_delay < 10:
        #         self._reconnect_delay += 1

    def open_channel(self):
        self.logger.debug("Openning channel")
        self._connection.channel(on_open_callback=self.on_channel_open)

    def close_channel(self):
        self.logger.debug("Closing channel")
        self._channel.close()

    def on_channel_open(self, channel):
        self.logger.debug("Channel opened")
        self._channel = channel
        self.events["channel"].set()
        self._channel.add_on_close_callback(self.on_channel_close)
        self.set_qos()

    def on_channel_close(self, channel, reason):
        self.logger.debug(f"Channel closed: {reason}")
        self.reason = reason
        self.events["channel"].clear()
        self.close_connection()

    def on_channel_cancel(self, method_frame):
        self.logger.debug("Channel canceled")
        if self._channel:
            self._channel.close()

    def set_qos(self):
        self.logger.debug("Setting qos")
        self._channel.basic_qos(
            prefetch_count=self.config.prefetch_count, callback=self.on_basic_qos_ok
        )

    def on_basic_qos_ok(self, _unused_frame):
        self.logger.debug("Qos set")

    def start_consuming(self, on_message):
        self.logger.debug("Start consuming")
        self._channel.add_on_cancel_callback(self.on_channel_cancel)
        self._consumer_tag = self._channel.basic_consume(self.config.queue, on_message)
        self._consuming = True

    def stop_consuming(self):
        self.logger.debug("Stop consuming")
        if self._channel:
            cb = functools.partial(self.on_cancelok, consumer_tag=self._consumer_tag)
            self._channel.basic_cancel(self._consumer_tag, cb)

    def on_cancelok(self, _unused_frame, consumer_tag):
        self.logger.debug("Cancel OK")
        self._consuming = False
        self._consumer_tag = ""
        self.close_channel()

    def ack_message(self, delivery_tag):
        if threading.get_ident() == self._thread_ident:
            self._channel.basic_ack(delivery_tag)
        else:
            self._connection.ioloop.call_soon_threadsafe(
                functools.partial(self.ack_message, delivery_tag)
            )

    def reject_message(self, delivery_tag, requeue=False):
        if threading.get_ident() == self._thread_ident:
            self._channel.basic_reject(delivery_tag, requeue)
        else:
            self._connection.ioloop.call_soon_threadsafe(
                functools.partial(self.reject_message, delivery_tag, requeue)
            )

    def ack_messages(self, delivery_tags):
        if threading.get_ident() == self._thread_ident:
            for tag in delivery_tags:
                self._channel.basic_ack(tag)
        else:
            self._connection.ioloop.call_soon_threadsafe(
                functools.partial(self.ack_messages, delivery_tags)
            )

    def try_ack_messages(self, consumer_tag, delivery_tags):
        if self._consumer_tag == consumer_tag:
            self.ack_messages(delivery_tags)
        else:
            self.logger.warning(
                f"Consumer tags don't match, can't acknowledge {delivery_tags}"
            )

    def try_reject_message(self, consumer_tag, delivery_tag):
        if self._consumer_tag == consumer_tag:
            self.reject_message(delivery_tag)
        else:
            self.logger.warning(
                f"Consumer tags don't match, can't reject {delivery_tag}"
            )

    def publish(self, routing_key, body, properties=None, mandatory=False):
        if threading.get_ident() == self._thread_ident:
            self._channel.basic_publish(
                self.config.exchange, routing_key, body, properties, mandatory
            )
        else:
            self._connection.ioloop.call_soon_threadsafe(
                functools.partial(
                    self.publish, routing_key, body, properties, mandatory
                )
            )


class SimplePublisher:
    """Simple AMQP Publisher that ensures and maintains a connection"""

    def __init__(self, config: AMQPConfig):
        self.config = config
        self.connection: BlockingConnection = None
        self.channel: Channel = None

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
        body: bytes,
        properties: pika.spec.BasicProperties = None,
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
