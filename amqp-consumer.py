import os
import sys
import time
import pika
import json
import argparse
import configparser
import threading
import functools
from datetime import datetime
from typing import Any
from copy import copy

from dataclasses import dataclass, field

from altrepodb.utils import get_logger
from altrepodb.logger import FakeLogger, ConsoleLogger
from altrepodb.task import TaskProcessor
from altrepodb.amqp import AMQPConsumer
from altrepodb.base import DatabaseConfig, TaskProcessorConfig, AMQPConfig
from altrepodb.exceptions import TaskLoaderError, TaskLoaderProcessingError

NAME="amqp-consumer"

@dataclass
class ProcessingEntry:
    delivery_tags: [int] = field(default_factory=list)
    processing: bool = False

processing_queue = dict()
processing_queue_cv = threading.Condition()

consistent_states = [
    "done", "eperm", "failed", "new", "tested"
]

inconsistent_states = [
    "awaiting", "building", "committing", "failing", "pending", "postponed", "swept"
]

def on_message(logger, amqp, method, properties, body):

    headers = properties.headers

    #NOTE(egori): Drop(ack) *very* dead messages
    if headers is not None:
        if 'x-death' in headers.keys():
            for death in headers['x-death']:
                if death['count'] >= 9:
                    logger.debug(f"Message {method.delivery_tag} is very dead, acknowledging")
                    amqp.ack_messages([method.delivery_tag])
                    return

    body_json = json.loads(body)
    if method.routing_key.startswith("task."):
        taskid = body_json['taskid']
        taskstate = body_json.get('state', 'unknown').lower()

        #if method.routing_key == "task.state":
        if method.routing_key == "task.create":
            with processing_queue_cv:
                if taskstate in consistent_states:
                    processing_queue.setdefault(taskid, ProcessingEntry()).delivery_tags.append(method.delivery_tag)
                    logger.debug(f"Schedule {taskid} for processing, "
                                 f"messages: {processing_queue[taskid].delivery_tags}")
                    processing_queue_cv.notify()
                else:
                    if taskid in processing_queue.keys():
                        if processing_queue[taskid].processing:
                            logger.debug(f"Task {taskid} is inconsistent now, but it is already "
                                         f"processing, dropping message {method.delivery_tag}")
                            amqp.ack_messages([method.delivery_tag])
                        else:
                            logger.debug(f"{taskid} is inconsistent, removing "
                                         "from processing_queue and acknowledging")
                            processing_queue[taskid].delivery_tags.append(method.delivery_tag)
                            amqp.ack_messages(processing_queue.pop(taskid).delivery_tags)
                    else:
                        logger.debug(f"{taskid} is inconsistent and not in processing_queue, "
                                     "acknowledging")
                        amqp.ack_messages([method.delivery_tag])
        elif method.routing_key == "task.delete":
            pass#
        else:
            amqp.ack_messages([method.delivery_tag])
            pass
    else:
        #TODO(egori): handle msg types other than 'task'
        logger.debug(f"unknown message type: {method.routing_key}")
        amqp.ack_messages([method.delivery_tag])
        pass

def on_channel_close(logger):
    global processing_queue

    #clear old delivery_tags
    with processing_queue_cv:
        for val in processing_queue.values():
            val.delivery_tags = []

# load full task
def hard_work(args, logger, amqp):

    def get_taskid():
        for taskid, entry in processing_queue.items():
            if not entry.processing:
                return taskid
        return None

    while True:
        with processing_queue_cv:

            taskid = get_taskid()
            while not taskid:
                processing_queue_cv.wait()
                taskid = get_taskid()

            processing_queue[taskid].processing = True

            logger.debug(f"Start loading task {taskid} : {processing_queue[taskid].delivery_tags}")

        tpconf = copy(args.tpconf)
        tpconf.id = int(taskid)
        if not tpconf.path.endswith("/"):
            tpconf.path = tpconf.path + "/"
        tpconf.path = tpconf.path + taskid

        try:
            tp = TaskProcessor(tpconf)
            tp.run()
            with processing_queue_cv:
                logger.info(f"Task {taskid} uploaded, acknowledging {processing_queue[taskid].delivery_tags}")
                amqp.ack_messages(processing_queue[taskid].delivery_tags)
        except TaskLoaderProcessingError as error:
            with processing_queue_cv:
                logger.error(f"Failed to upload task {taskid}: {error}, "
                             f"rejecting {processing_queue[taskid].delivery_tags[-1]}, "
                             f"acknowledging {processing_queue[taskid].delivery_tags[:-1]}")
                amqp.reject_message(processing_queue[taskid].delivery_tags[-1])
                amqp.ack_messages(processing_queue[taskid].delivery_tags[:-1])
        except TaskLoaderError as error:
            with processing_queue_cv:
                logger.error(f"Failed to upload task {taskid}: {error}, "
                             f"acknowledging {processing_queue[taskid].delivery_tags}")
                amqp.ack_messages(processing_queue[taskid].delivery_tags)
        except Exception as error:
            logger.error(f"Error while loading task {taskid}: {error}")
            raise error
        finally:
            with processing_queue_cv:
                processing_queue.pop(taskid)


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', type=str, required=True, help='Path to configuration file')
    parser.add_argument("-w", "--workers", type=int, help="Workers count (default: 10)")
    parser.add_argument(
        "-D", "--debug", action="store_true", help="Set logging level to debug"
    )

    args = parser.parse_args()
    args.workers = args.workers or 10

    return args


def get_config(args: Any):
    amqpconf = AMQPConfig()
    dbconf = DatabaseConfig()
    tpconf = TaskProcessorConfig(
        id = None,
        path = None,
        dbconfig = dbconf,
        logger = None,
        debug = args.debug
    )

    if args.config is not None:
        cfg = configparser.ConfigParser()
        with open(args.config) as f:
            cfg.read_file(f)

        if cfg.has_section("AMQP"):
            section_amqp = cfg["AMQP"]
            amqpconf.host = section_amqp.get("host", amqpconf.host)
            amqpconf.port = section_amqp.get("port", amqpconf.port)
            amqpconf.vhost = section_amqp.get("vhost", amqpconf.vhost)
            amqpconf.queue = section_amqp.get("queue", amqpconf.queue)
            amqpconf.username = section_amqp.get("username", amqpconf.username)
            amqpconf.password = section_amqp.get("password", amqpconf.password)
            amqpconf.cacert = section_amqp.get("cacert", amqpconf.cacert)
            amqpconf.key = section_amqp.get("key", amqpconf.key)
            amqpconf.cert = section_amqp.get("cert", amqpconf.cert)

        if cfg.has_section("DATABASE"):
            section_db = cfg["DATABASE"]
            dbconf.host = section_db.get("host", dbconf.host)
            dbconf.port = section_db.get("port", dbconf.port)
            dbconf.name = section_db.get("dbname", dbconf.name)
            dbconf.user = section_db.get("user", dbconf.user)
            dbconf.password = section_db.get("password", dbconf.password)

        if cfg.has_section("TASK_PROCESSOR"):
            section_tp = cfg["TASK_PROCESSOR"]
            tpconf.path = section_tp.get("base_path", tpconf.path)
            tpconf.flush = section_tp.get("flush", tpconf.flush)
            tpconf.force = section_tp.get("force", tpconf.force)
            tpconf.workers = section_tp.getint("workers", tpconf.workers)
            tpconf.dumpjson = section_tp.get("dumpjson", tpconf.dumpjson)

    args.tpconf = tpconf
    args.amqpconf = amqpconf

    return args

def get_amqp(args: Any, logger):
    credentials = pika.PlainCredentials(args.amqpconf.username, args.amqpconf.password)
    parameters = pika.ConnectionParameters(
        host=args.amqpconf.host,
        port=args.amqpconf.port,
        virtual_host=args.amqpconf.vhost,
        credentials=credentials,
        heartbeat=0
    )

    connection = pika.BlockingConnection(parameters)

    return connection


def main():
    assert sys.version_info >= (3, 7), "Pyhton version 3.7 or newer is required!"

    args = get_args()
    args = get_config(args)

    logger = get_logger(NAME, tag="consume")
    if args.debug:
        logger.setLevel("DEBUG")
    logger.info(f"run with args: {args}")
    args.tpconf.logger=FakeLogger("")
    args.tpconf.logger=logger

    amqp = AMQPConsumer(logger, args.amqpconf)

    threads = []
    for i in range(args.workers):
        threads.append(
            threading.Thread(
                target=hard_work,
                args=(args, logger, amqp,),
                daemon=True
            )
        )
        threads[i].start()

    amqp.add_on_message_callback(lambda channel, method, properties, body: on_message(
             logger, amqp, method, properties, body
         ))

    amqp.add_on_channel_close_callback(lambda channel: on_channel_close(logger))

    try:
        amqp.run()
    except KeyboardInterrupt:
        amqp.stop()
    except Exception as error:
        logger.error(str(error), exc_info=True)

if __name__ == "__main__":
    main()
