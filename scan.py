#!/usr/bin/env python3

import monocle.sanitized as conf

from asyncio import gather, set_event_loop_policy, Task, wait_for, TimeoutError
try:
    if conf.UVLOOP:
        from uvloop import EventLoopPolicy
        set_event_loop_policy(EventLoopPolicy())
except ImportError:
    pass

from multiprocessing.managers import BaseManager, DictProxy
from queue import Queue, Full
from argparse import ArgumentParser
from signal import signal, SIGINT, SIGTERM, SIG_IGN
from logging import getLogger, basicConfig, WARNING, INFO
from logging.handlers import RotatingFileHandler
from os.path import exists, join
from sys import platform
from time import monotonic, sleep

from sqlalchemy.exc import DBAPIError
from aiopogo import close_sessions, activate_hash_server

from monocle.shared import LOOP, get_logger, SessionManager
from monocle.utils import get_address, dump_pickle
from monocle.worker import Worker
from monocle.overseer import Overseer
from monocle.db import FORT_CACHE, RAID_CACHE, SIGHTING_CACHE
from monocle.accounts import AccountQueue, CaptchaAccountQueue, Lv30AccountQueue, get_accounts, get_accounts30
from monocle import altitudes, db_proc, spawns


class AccountManager(BaseManager):
    pass

_captcha_queue = CaptchaAccountQueue()
_extra_queue = AccountQueue()
_worker_dict = {}
_lv30_captcha_queue = CaptchaAccountQueue()
_lv30_account_queue = Lv30AccountQueue()
_lv30_worker_dict = {}

def get_captchas():
    return _captcha_queue

def get_extras():
    return _extra_queue

def get_workers():
    return _worker_dict

def get_lv30_captchas():
    return _captcha_queue

def get_lv30_accounts():
    return _lv30_account_queue 

def get_lv30_workers():
    return _lv30_worker_dict

def mgr_init():
    signal(SIGINT, SIG_IGN)


def parse_args():
    parser = ArgumentParser()
    parser.add_argument(
        '--no-status-bar',
        dest='status_bar',
        help='Log to console instead of displaying status bar',
        action='store_false'
    )
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default=INFO
    )
    parser.add_argument(
        '--bootstrap',
        dest='bootstrap',
        help='Bootstrap even if spawns are known.',
        action='store_true'
    )
    parser.add_argument(
        '--no-pickle',
        dest='pickle',
        help='Do not load spawns from pickle',
        action='store_false'
    )
    parser.add_argument(
        '--signature',
        dest='signature',
        help='This flag does nothing. Only serves for easy monitoring of processes.',
        default=''
    )
    return parser.parse_args()


def configure_logger(filename='scan.log'):
    if filename:
        handlers = (RotatingFileHandler(filename, maxBytes=500000, backupCount=conf.LOGGED_FILES),)
    else:
        handlers = None
    basicConfig(
        format='[{asctime}][{levelname:>8s}][{name}] {message}',
        datefmt='%Y-%m-%d %X',
        style='{',
        level=INFO,
        handlers=handlers
    )


def exception_handler(loop, context):
    try:
        log = getLogger('eventloop')
        log.error('A wild exception appeared!')
        log.error(context)
    except Exception:
        print('Exception in exception handler.')


def cleanup(overseer, manager):
    try:
        if hasattr(overseer, 'print_handle'):
            overseer.print_handle.cancel()
        overseer.running = False
        print('Exiting, please wait until all tasks finish')

        log = get_logger('cleanup')
        print('Finishing tasks...')

        LOOP.create_task(overseer.exit_progress())
        pending = gather(*Task.all_tasks(loop=LOOP), return_exceptions=True)
        try:
            LOOP.run_until_complete(wait_for(pending, 40))
        except TimeoutError as e:
            print('Coroutine completion timed out, moving on.')
        except Exception as e:
            log = get_logger('cleanup')
            log.exception('A wild {} appeared during exit!', e.__class__.__name__)

        db_proc.stop()
        overseer.refresh_dict()

        print('Dumping pickles...')
        dump_pickle('accounts', get_accounts())
        dump_pickle('accounts30', get_accounts30())
        FORT_CACHE.pickle()
        RAID_CACHE.preload()
        altitudes.pickle()
        if conf.CACHE_CELLS:
            dump_pickle('cells', Worker.cells)

        spawns.pickle()
        while not db_proc.queue.empty():
            pending = db_proc.queue.qsize()
            # Spaces at the end are important, as they clear previously printed
            # output - \r doesn't clean whole line
            print('{} DB items pending     '.format(pending), end='\r')
            sleep(.5)
    finally:
        print('Closing pipes, sessions, and event loop...')
        manager.shutdown()
        SessionManager.close()
        close_sessions()
        LOOP.close()
        print('Done.')


def main():
    args = parse_args()
    log = get_logger()
    if args.status_bar:
        configure_logger(filename=join(conf.DIRECTORY, 'scan.log'))
        log.info('-' * 37)
        log.info('Starting up!')
    else:
        configure_logger(filename=None)
    log.setLevel(args.log_level)

    AccountManager.register('captcha_queue', callable=get_captchas)
    AccountManager.register('extra_queue', callable=get_extras)
    AccountManager.register('lv30_captcha_queue', callable=get_lv30_captchas)
    AccountManager.register('lv30_account_queue', callable=get_lv30_accounts)
    if conf.MAP_WORKERS:
        AccountManager.register('worker_dict', callable=get_workers,
                                proxytype=DictProxy)
        AccountManager.register('lv30_worker_dict', callable=get_lv30_workers,
                                proxytype=DictProxy)
    address = get_address()
    manager = AccountManager(address=address, authkey=conf.AUTHKEY)
    try:
        manager.start(mgr_init)
    except (OSError, EOFError) as e:
        if platform == 'win32' or not isinstance(address, str):
            raise OSError('Another instance is running with the same manager address. Stop that process or change your MANAGER_ADDRESS.') from e
        else:
            raise OSError('Another instance is running with the same socket. Stop that process or: rm {}'.format(address)) from e

    LOOP.set_exception_handler(exception_handler)

    overseer = Overseer(manager)
    overseer.start(args.status_bar)
    launcher = LOOP.create_task(overseer.launch(args.bootstrap, args.pickle))
    
    if conf.GO_HASH:
        hashkey = conf.GO_HASH_KEY
    else:
        hashkey = conf.HASH_KEY
    activate_hash_server(hashkey, go_hash=conf.GO_HASH)
    if platform != 'win32':
        LOOP.add_signal_handler(SIGINT, launcher.cancel)
        LOOP.add_signal_handler(SIGTERM, launcher.cancel)

    try:
        SIGHTING_CACHE.preload()
    except Exception as e:
        log.error("SightingCahe preload error: {}", e)

    try:
        LOOP.run_until_complete(launcher)
    except (KeyboardInterrupt, SystemExit):
        launcher.cancel()
    finally:
        cleanup(overseer, manager)


if __name__ == '__main__':
    main()
