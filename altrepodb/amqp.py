
import pika
import pika.adapters.asyncio_connection
import threading
import functools

from .base import AMQPConfig
from .logger import LoggerProtocol


class AMQPConsumer(object):

    def __init__(self, logger: LoggerProtocol, config: AMQPConfig):
        self.logger = logger
        self.config = config

        self.on_message_callbacks: dict[callable] = []
        self.on_channel_close_callbacks: dict[callable] = []

        self._thread_ident = threading.get_ident()

        self._connection = None
        self._channel = None
        self._consumer_tag = None

        self._closing = False

        self._consuming = False

        self._reconnect_delay = 0

        self._prefetch_count = 200

    def run(self):
        self.logger.debug("Starting")
        self._connection = self.connect()
        self._connection.ioloop.run_forever()

    def stop(self):
        if not self._closing:
            self._closing = True
            self.logger.debug("Stopping")
            if self._consuming:
                self.stop_consuming()
                self._connection.ioloop.run_forever()
            else:
                self._connection.ioloop.stop()
            self.logger.debug("Stopped")

    # connection stuff:

    def connect(self):
        self.logger.debug("Connecting")
        credentials = pika.PlainCredentials(self.config.username, self.config.password)
        parameters = pika.ConnectionParameters(
            host=self.config.host,
            port=self.config.port,
            virtual_host=self.config.vhost,
            credentials=credentials,
            heartbeat=0
        )
        #TODO(egori): ssl

        return pika.adapters.asyncio_connection.AsyncioConnection(
            parameters=parameters,
            on_open_callback=self.on_connection_open,
            on_open_error_callback=self.on_connection_open_error,
            on_close_callback=self.on_connection_close,
        )

    def close_connection(self):
        self._consuming = False
        self._consumer_tag = ""
        if self._connection.is_closing or self._connection.is_closed:
            self.logger.info('Connection is closing or already closed')
        else:
            self.logger.info('Closing connection')
            self._connection.close()

    def reconnect(self):
        if not self._closing:
            self.logger.debug("Reconnecting")
            self._connection = self.connect()

    def on_connection_open(self, _unused_connection):
        self.logger.debug("Connection opened")
        self._reconnect_delay = 0
        self.open_channel()

    def on_connection_open_error(self, _unused_connection, error):
        self.logger.debug(f"Connection open error: {error}")
        self.logger.info(f"Reconnecting after {self._reconnect_delay} seconds")
        self._connection.ioloop.call_later(self._reconnect_delay, self.reconnect)
        if self._reconnect_delay < 10:
            self._reconnect_delay += 1

    def on_connection_close(self, _unused_connection, reason):
        self.logger.debug(f"Connection closed: {reason}")
        self._channel = None
        if self._closing:
            self._connection.ioloop.stop()
        else:
            self.logger.info(f"Reconnecting after {self._reconnect_delay} seconds")
            self._connection.ioloop.call_later(self._reconnect_delay, self.reconnect)
            if self._reconnect_delay < 10:
                self._reconnect_delay += 1

    # channel stuff:

    def open_channel(self):
        self.logger.debug("Openning channel")
        self._connection.channel(on_open_callback=self.on_channel_open)

    def close_channel(self):
        self.logger.debug("Closing channel")
        self._channel.close()

    def on_channel_open(self, channel):
        self.logger.debug("Channel opened")
        self._channel = channel
        self._channel.add_on_close_callback(self.on_channel_close)
        self.set_qos()

    def on_channel_close(self, channel, reason):
        self.logger.debug(f"Channel closed: {reason}")
        for cb in self.on_channel_close_callbacks:
            cb(self._channel)
        self.close_connection()

    def on_channel_cancel(self, method_frame):
        self.logger.debug("Channel canceled")
        if self._channel:
            self._channel.close()

    def set_qos(self):
        self.logger.debug("Setting qos")
        self._channel.basic_qos(prefetch_count=self._prefetch_count,
                                callback=self.on_basic_qos_ok)

    def on_basic_qos_ok(self, _unused_frame):
        self.logger.debug("Qos set")
        self.start_consuming()


    # consumption stuff:

    def start_consuming(self):
        self.logger.debug("Start consuming")
        self._channel.add_on_cancel_callback(self.on_channel_cancel)
        self._consumer_tag = self._channel.basic_consume(self.config.queue, self.on_message)
        self._consuming = True

    def stop_consuming(self):
        self.logger.debug("Stop consuming")
        if self._channel:
            cb = functools.partial(
                self.on_cancelok, consumer_tag=self._consumer_tag)
            self._channel.basic_cancel(self._consumer_tag, cb)

    def on_cancelok(self, _unused_frame, consumer_tag):
        self.logger.debug("Cancel OK")
        self._consuming = False
        self._consumer_tag = ""
        self.close_channel()

    def on_message(self, _unused_channel, method, properties, body):
        for cb in self.on_message_callbacks:
            cb(self._channel, method, properties, body)

    def add_on_message_callback(self, callback: callable):
        self.on_message_callbacks.append(callback)

    def add_on_channel_close_callback(self, callback: callable):
        self.on_channel_close_callbacks.append(callback)

    def ack_messages(self, delivery_tags):
        if threading.get_ident() == self._thread_ident:
            for tag in delivery_tags:
                self._channel.basic_ack(tag)
        else:
            self._connection.ioloop.call_soon_threadsafe(
                functools.partial(self.ack_messages, delivery_tags)
                )

    def reject_message(self, delivery_tag, requeue=False):
        if threading.get_ident() == self._thread_ident:
            self._channel.basic_reject(delivery_tag, requeue)
        else:
            self._connection.ioloop.call_soon_threadsafe(
                functools.partial(self.reject_message, delivery_tag, requeue)
                )

    def try_ack_messages(self, consumer_tag, delivery_tags):
        if self._consumer_tag == consumer_tag:
            self.ack_messages(delivery_tags)
        else:
            self.logger.warning(f"Consumer tags don't match, can't acknowledge {delivery_tags}")

    def try_reject_message(self, consumer_tag, delivery_tag):
        if self._consumer_tag == consumer_tag:
            self.reject_message(delivery_tag)
        else:
            self.logger.warning(f"Consumer tags don't match, can't reject {delivery_tag}")
