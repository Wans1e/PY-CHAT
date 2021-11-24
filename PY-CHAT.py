import subprocess
import threading
import getpass
import base64
import curses
import queue
import uuid
import sys
import os

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

from typing import Callable
from typing import Dict
from typing import Any

from protocol import DEFAULT_PORT
from protocol import DEFAULT_ENCODING
from protocol import STRICT_ENCODING_ERRORS
from protocol import LIBERAL_ENCODING_ERRORS
from protocol import Platform
from protocol import AsymmetricSocket

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

class Wrap:

    @staticmethod
    def quiet_exit(callback: Callable[..., Any]) -> Callable[..., Any]:
        def wrapper(*args, **kwargs):
            try:
                return callback(*args, **kwargs)
            except Exception:
                sys.exit()
        
        return wrapper

    @staticmethod
    def thread_call(callback: Callable[..., None]) -> Callable[..., None]:
        def wrapper(*args, **kwargs):
            threading.Thread(target=callback,
                             args=args,
                             kwargs=kwargs,
                             daemon=True).start()

        return wrapper

    @staticmethod
    def secure_input(callback: Callable[..., None]) -> Callable[..., Any]:
        def wrapper(*args, **kwargs):
            try:
                return callback(*args, **kwargs)
            except (KeyboardInterrupt, EOFError):
                sys.exit()
            except Exception:
                print('Failed Creating/Joining Chatroom.')
                sys.exit()

        return wrapper

class Console:

    history = []

    @classmethod
    def init(cls) -> None:
        cls.NOTICE           = '[NOTICE]'
        cls.MAX_USERNAME_LEN = 16
        cls._HR_CHAR         = '_'
        cls.PRINT_PREFIX     = '  '
        cls.INPUT_PREFIX     = '  : '
        cls.PRINT_SUFFIX     = ': '
        cls.PRINT_PREFIX_LEN = len(cls.PRINT_PREFIX)
        cls.INPUT_PREFIX_LEN = len(cls.INPUT_PREFIX)
        cls.PRINT_SUFFIX_LEN = len(cls.PRINT_SUFFIX)
        cls._SIZE            = os.get_terminal_size()
        cls.MAX_LINES        = cls._SIZE.lines
        cls.MAX_COLS         = cls._SIZE.columns
        cls.PRINT_LINES      = cls.MAX_LINES - 4
        cls.INPUT_LINES      = cls.MAX_LINES - 2
        cls.WINDOW           = curses.initscr()
        curses.curs_set(0)
        cls.WINDOW.clear()
        cls.WINDOW.addstr(cls.PRINT_LINES, 0, cls._HR_CHAR * cls.MAX_COLS)
        cls.WINDOW.refresh()

    @staticmethod
    def write_msg(obj: Dict[str, Any]) -> None:
        username, msg = (obj['username'], obj['msg'])

        Console.history.append((username, msg, (Console.MAX_COLS
                                                - Console.PRINT_PREFIX_LEN
                                                - Console.PRINT_SUFFIX_LEN
                                                - len(username))))

        if len(Console.history) == Console.PRINT_LINES:
            Console.history.pop(0)

        cursor_y, cursor_x = Console.WINDOW.getyx()

        for index, (username, msg, max_msg_len) in enumerate(Console.history, 1):
            Console.WINDOW.addstr(index, 0, Console.PRINT_PREFIX)
            Console.WINDOW.addstr(index,
                                  Console.PRINT_PREFIX_LEN,
                                  username,
                                  curses.A_UNDERLINE)
            Console.WINDOW.addstr(index,
                                  Console.PRINT_PREFIX_LEN + len(username),
                                  Console.PRINT_SUFFIX + msg[:max_msg_len])
            Console.WINDOW.clrtoeol()

        Console.WINDOW.move(cursor_y, cursor_x)
        Console.WINDOW.clrtoeol()
        Console.WINDOW.refresh()

class Server:

    def __init__(self, *args, **kwargs) -> None:
        self.args    = args
        self.kwargs  = kwargs
        self.clients = {}
        self.queue   = queue.Queue()
        self.server  = AsymmetricSocket(*self.args,
                                        server_side=True,
                                        is_host=True,
                                        **self.kwargs)
        self.server.set_conn()
        self.server.set_context()
        self.server.set_middleware()

    @Wrap.thread_call
    @Wrap.quiet_exit
    def listen(self) -> None:
        while True:
            conn, (ip, port) = self.server.conn.accept()
            client = AsymmetricSocket(ip,
                                      port,
                                      conn=conn,
                                      server_side=True,
                                      **self.kwargs)
            client.set_context()
            id = uuid.uuid4()
            self.clients[id] = client
            self.pull(id, client)
            self.push({'username': Console.NOTICE,
                       'msg': 'User Connected'})

    @Wrap.thread_call
    @Wrap.quiet_exit
    def pull(self, id: str, client: AsymmetricSocket) -> None:
        try:
            while True:
                obj = client.recv()

                assert isinstance(obj, dict), f'Wrong type: {obj=}'

                msg, username = (obj.get('msg'), obj.get('username'))

                assert isinstance(msg, str), f'Wrong type: {obj=}'
                assert isinstance(username, str), f'Wrong type: {obj=}'

                obj['username'] = username[:Console.MAX_USERNAME_LEN]
                self.push(obj)
        except Exception:
            self._disconnect(id)

    def push(self, obj: Dict[str, str]) -> None:
        self._employ_workers()
        self._create_jobs(obj)

    def _employ_workers(self) -> None:
        for _ in self.clients:
            self._worker()

    @Wrap.thread_call
    @Wrap.quiet_exit
    def _worker(self) -> None:
        (id, client), obj = self.queue.get()

        try:
            client.send(obj)
        except Exception:
            self._disconnect(id)
        finally:
            self.queue.task_done()

    def _create_jobs(self, obj: Dict[str, str]) -> None:
        for id, client in self.clients.items():
            self.queue.put(((id, client), obj))
        else:
            self.queue.join()

    def _disconnect(self, id: str) -> None:
        try:
            del self.clients[id]
        except KeyError:
            pass
        else:
            self.push({'username': Console.NOTICE,
                       'msg': 'User Disconnected'})
        finally:
            raise

class Client:

    def __init__(self, *args, **kwargs) -> None:
        self.client = AsymmetricSocket(*args, **kwargs)
        self.client.set_conn()
        self.client.set_middleware()

    @Wrap.thread_call
    @Wrap.quiet_exit
    def connect(self) -> None:
        try:
            while True:
                obj = self.client.recv()
                Console.write_msg(obj)
        except Exception:
            Console.write_msg({'username': Console.NOTICE,
                               'msg': 'You\'ve disconnected, press enter to exit.'})
            raise

    @Wrap.quiet_exit
    def send(self, obj: Dict[str, str]) -> None:
        self.client.send(obj)

class Main:

    _SALT = '66a64d07-4b49-4fb4-979c-be60b970f480'
    _SALT = _SALT.encode(DEFAULT_ENCODING,
                         errors=STRICT_ENCODING_ERRORS)

    @Wrap.secure_input
    def __init__(self, lines: int, cols: int, theme: str) -> None:
        if Platform.WINDOWS:
            os.system(f'mode con lines={lines} cols={cols} && color {theme}')
        else:
            print(f'\x1b[8;{lines};{cols}t', end='', flush=True)

        while True:
            category = self._ask('Create/Join Chatroom: ')
            category = category.lower()

            if category in ('create', 'join'):
                break

        if category == 'create':
            address = self._ask('Chatroom Address: ').split(':')[:2]

            if len(address) == 2:
                hostname, port = (address[0], int(address[1]))
            else:
                hostname, port = (address[0], DEFAULT_PORT)

            link_address = input('Chatroom Link Address (Optional Forwarded Port Address): ').split(':')[:2]

            if len(link_address) == 2:
                link_hostname, link_port = (link_address[0], int(link_address[1]))
            else:
                link_hostname, link_port = (hostname, port)

            password = self._ask('Chatroom Password: ', secret=True)
            password = password.encode(DEFAULT_ENCODING, errors=STRICT_ENCODING_ERRORS)

            pubk_filepath  = os.path.join(ROOT_DIR, 'Certificates', 'public_key.pem')
            privk_filepath = os.path.join(ROOT_DIR, 'Certificates', 'private_key.pem')

            try:
                subprocess.run(('openssl',
                                'req',
                                '-newkey',
                                'rsa:2048',
                                '-nodes',
                                '-keyout',
                                privk_filepath,
                                '-x509',
                                '-days',
                                '36500',
                                '-out',
                                pubk_filepath,
                                '-batch'),
                               encoding=DEFAULT_ENCODING,
                               errors=STRICT_ENCODING_ERRORS,
                               stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
            except Exception:
                print('\nWARNING: OpenSSL not found in path, falling back on old certificates.', end='')

            with open(pubk_filepath,
                      'r',
                      encoding=DEFAULT_ENCODING,
                      errors=STRICT_ENCODING_ERRORS) as fh:
                pubk_data = fh.read()

            link = f'{link_hostname}:{link_port}@{pubk_data}'
            link = link.encode(DEFAULT_ENCODING, errors=STRICT_ENCODING_ERRORS)
            link = self._secret(password).encrypt(link)
            link = link.decode(DEFAULT_ENCODING, errors=STRICT_ENCODING_ERRORS)
            print(f'\nWARNING: Before continuing, save the generated link.\n\n{link}\n')
        else:
            link     = self._ask('Chatroom Link: ')
            link     = link.encode(DEFAULT_ENCODING, errors=STRICT_ENCODING_ERRORS)
            password = self._ask('Chatroom Link Password: ', secret=True)
            password = password.encode(DEFAULT_ENCODING, errors=STRICT_ENCODING_ERRORS)
            link     = self._secret(password).decrypt(link)
            link     = link.decode(DEFAULT_ENCODING, errors=STRICT_ENCODING_ERRORS)

            address, pubk_data = link.split('@')[:2]
            address            = address.split(':')[:2]
            hostname, port     = (address[0], int(address[1]))

        self.username = self._ask('Your Chatroom Username: ')

        if category == 'create':
            Server(hostname, port, public_key=pubk_filepath, private_key=privk_filepath).listen()

        Console.init()

        prefix_print_len = (len(self.username)
                            + Console.PRINT_PREFIX_LEN
                            + Console.PRINT_SUFFIX_LEN)
        prefix_input_len = Console.INPUT_PREFIX_LEN

        if prefix_print_len > prefix_input_len:
            max_input_len = prefix_print_len
        else:
            max_input_len = prefix_input_len

        self.max_input_len = Console.MAX_COLS - max_input_len
        self.client = Client(hostname, port, public_key_data=pubk_data)
        self.client.connect()

    def _secret(self, password: bytes) -> Fernet:
        secret = PBKDF2HMAC(algorithm=hashes.SHA256(),
                            length=32,
                            salt=self._SALT,
                            iterations=320000,
                            backend=default_backend())
        secret = secret.derive(password)
        secret = Fernet(base64.urlsafe_b64encode(secret))

        return secret

    def _ask(self, question: str='', *, secret: bool=False) -> str:
        while True:
            if secret:
                answer = getpass.getpass(question)
            else:
                answer = input(question)

            if answer:
                return answer

    def run(self) -> None:
        while True:
            Console.WINDOW.addstr(Console.INPUT_LINES, 0, Console.INPUT_PREFIX)
            msg = Console.WINDOW.getstr(Console.INPUT_LINES,
                                        Console.INPUT_PREFIX_LEN,
                                        self.max_input_len)
            msg = msg.decode(DEFAULT_ENCODING, errors=LIBERAL_ENCODING_ERRORS)
            Console.WINDOW.refresh()
            self.client.send({'username': self.username, 'msg': msg})

if __name__ == '__main__':
    Main(40, 140, '02').run()
