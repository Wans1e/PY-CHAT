# Modified Source From: https://raw.githubusercontent.com/Wans1e/PY-NET/main/shared.py

import ipaddress
import platform
import base64
import socket
# import uuid
import zlib
import json
import ssl
import re

from typing import Callable
from typing import Optional
from typing import Union
from typing import Tuple
from typing import Dict
from typing import Any

DEFAULT_HOSTNAME        = 'localhost'
DEFAULT_PORT            = 38567 # 38568
DEFAULT_ENCODING        = 'utf-8'
DEFAULT_LANGUAGE_CODE   = 65001
STRICT_ENCODING_ERRORS  = 'strict'
LIBERAL_ENCODING_ERRORS = 'replace'

class Platform:

    PLATFORM = platform.system()
    WINDOWS  = PLATFORM == 'Windows'
    LINUX    = PLATFORM == 'Linux'
    MAC      = PLATFORM == 'Mac'
    UNIX     = LINUX or MAC

class ExtendedEncoder(json.JSONEncoder):

    def default(self, obj: Any) -> Any:
        if isinstance(obj, bytes):
            return base64.b64encode(obj).decode(DEFAULT_ENCODING,
                                                errors=STRICT_ENCODING_ERRORS)

        return json.JSONEncoder.default(self, obj)

class ExtendedDecoder(json.JSONDecoder):

    def default(self, obj: Any) -> Any:
        if isinstance(obj, bytes):
            return base64.b64decode(obj.encode(DEFAULT_ENCODING,
                                               errors=STRICT_ENCODING_ERRORS))

        return json.JSONDecoder.default(self, obj)

class Bytes:

    LABELS           = ('B', 'kB', 'MB', 'GB')
    LAST_LABEL       = LABELS[-1]
    UNIT_STEP        = 1024
    UNIT_STEP_THRESH = UNIT_STEP - 0.005

    @staticmethod
    def format(num: Union[int, float]) -> str:
        assert isinstance(num, (int, float)), f'Wrong type: {num=}'
        assert num >= 0, f'Wrong value: {num=}'

        for unit in Bytes.LABELS:
            if num < Bytes.UNIT_STEP_THRESH:
                break

            if unit != Bytes.LAST_LABEL:
                num /= Bytes.UNIT_STEP

        return f'{num:.2f} {unit}'

class Socket:

    def __init__(
        self,
        hostname: str,
        port: int,
        *,
        conn: Optional[Union[socket.socket, ssl.SSLSocket]]=None,
        server_side: bool=False,
        is_host: bool=False
    ) -> None:
        assert isinstance(hostname, str), f'Wrong type: {hostname=}'
        assert isinstance(port, int), f'Wrong type: {port=}'
        assert port >= 1024 and port <= 65535, f'Wrong value: {port=}'
        assert isinstance(conn, (socket.socket, ssl.SSLSocket)) or conn is None, f'Wrong type: {conn=}'
        assert isinstance(server_side, bool), f'Wrong type: {server_side=}'
        assert isinstance(is_host, bool), f'Wrong type: {is_host=}'

        dns_resolved_ip  = socket.gethostbyname(hostname)
        self.ip          = ipaddress.ip_address(dns_resolved_ip)
        self.port        = port
        self.conn        = conn
        self.server_side = server_side
        self.is_host     = is_host

        if self.server_side:
            self.hostname        = hostname if hostname != dns_resolved_ip else None
            self.data_wrap       = None
            self.data_wrap_notes = None

            if self.is_host:
                self.in_session = None
                self.ENCODING   = None
            else:
                self.in_session = False
        else:
            assert not self.is_host, f'Wrong value: {self.is_host=}'

        if not self.is_host:
            UUID_REGEX               = r'^[\da-f]{8}-([\da-f]{4}-){3}[\da-f]{12}$'
            self.UUID_PATTERN        = re.compile(UUID_REGEX, re.IGNORECASE)
            self.ENCODING            = DEFAULT_ENCODING
            self.DEFAULT_BUFFER_SIZE = self.BUFFER_SIZE = 1024
            self.MAX_BUFFER_SIZE     = 65536
            self.SEND_HEADER_SIZE    = 10
            self.RECV_HEADER_SIZE    = 10 # 46

            self.header_send_callback = None
            self.header_recv_callback = None
            self.send_callback        = None
            self.recv_callback        = None
            # self.uuid_token           = None

    def __enter__(self) -> Union[socket.socket, ssl.SSLSocket]:
        assert self.conn, f'Missing attribute: {self.conn=}'
        return self.conn

    def __exit__(self, *_) -> None:
        self.close()

    def __str__(self) -> str:
        if self.server_side:
            return f'tcp://{self.ip}:{self.port}'
        else:
            return super().__str__()

    def address(self) -> Tuple[str, ...]:
        assert self.server_side, f'Wrong value: {self.server_side=}'
        return (self.data_wrap, self.in_session, str(self), self.hostname, self.ENCODING, self.data_wrap_notes)

    def address_headers(self) -> Tuple[str, ...]:
        assert self.server_side, f'Wrong value: {self.server_side=}'
        return ('ID', 'Type', 'In Session', 'Address', 'Hostname', 'Encoding',  'Type Notes')

    def detailed_address(self) -> Tuple[Tuple[Tuple[str, Any], ...], Tuple[str, str]]:
        assert self.server_side, f'Wrong value: {self.server_side=}'
        return ((('Type', self.data_wrap),
                ('In Session', self.in_session),
                ('Address', str(self)),
                ('Hostname', self.hostname),
                ('Encoding', self.ENCODING),
                ('Type Notes', self.data_wrap_notes),
                ('Address Type', f'{self.ip.max_prefixlen}-bit IPv{self.ip.version}'),
                ('Reverse Pointer', self.ip.reverse_pointer),
                ('Global Address', self.ip.is_global),
                ('Link Local Address', self.ip.is_link_local),
                ('Loopback Address', self.ip.is_loopback),
                ('Multicast Address', self.ip.is_multicast),
                ('Private Address', self.ip.is_private),
                ('Reserved Address', self.ip.is_reserved),
                ('Unspecified Address', self.ip.is_unspecified)),
                ('Key', 'Value'))

    def close(self) -> None:
        assert self.conn, f'Missing attribute: {self.conn=}'

        try:
            self.conn.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        finally:
            self.conn.close()

    def set_conn(self, **kwargs) -> socket.socket:
        if self.server_side:
            assert self.is_host, f'Wrong value: {self.is_host=}'

            self.conn = socket.create_server((str(self.ip), self.port), **kwargs)
        else:
            self.conn = socket.create_connection((str(self.ip), self.port), **kwargs)

    def set_context(self) -> None:
        assert self.server_side, f'Wrong value: {self.server_side=}'

        if self.is_host:
            self.data_wrap = 'HOSTING :: COMP'
        else:
            self.data_wrap = 'CONNECTING :: COMP'

    def set_middleware(self) -> None:
        assert not self.is_host, f'Wrong value: {self.is_host=}'

        self.send_callback = lambda body: zlib.compress(body)
        self.recv_callback = lambda body: zlib.decompress(body)

    def send(self, obj: Dict[str, Any], callback: Callable[[str, str], None]=None) -> None:
        assert not self.is_host, f'Wrong value: {self.is_host=}'
        assert self.conn, f'Missing attribute: {self.conn=}'
        assert isinstance(obj, dict), f'Wrong type: {obj=}'
        assert callable(callback) or callback is None, f'Wrong type: {callback=}'

        body = json.dumps(obj, cls=ExtendedEncoder)
        body = body.encode(self.ENCODING, errors=LIBERAL_ENCODING_ERRORS)

        if self.send_callback:
            body = self.send_callback(body)

        # if self.server_side:
        #     self.uuid_token = str(uuid.uuid4())

        body_size = len(body)
        header = str(body_size).ljust(self.SEND_HEADER_SIZE)
        header = header.encode(DEFAULT_ENCODING, errors=STRICT_ENCODING_ERRORS)
        # header = (header + self.uuid_token).encode(DEFAULT_ENCODING,
        #                                            errors=STRICT_ENCODING_ERRORS)

        if self.header_send_callback:
            header = self.header_send_callback(header)

        if callback:
            header_size = len(header)
            callback(Bytes.format(header_size),
                     Bytes.format(body_size),
                     Bytes.format(header_size + body_size))

        self.conn.sendall(header + body)

    def recv(self, callback: Callable[[str, str], None]=None) -> Dict[str, Any]:
        assert not self.is_host, f'Wrong value: {self.is_host=}'
        assert self.conn, f'Missing attribute: {self.conn=}'
        assert callable(callback) or callback is None, f'Wrong type: {callback=}'

        position = 0

        if callback:
            history = []

        if self.BUFFER_SIZE != self.DEFAULT_BUFFER_SIZE:
            self.BUFFER_SIZE = self.DEFAULT_BUFFER_SIZE

        while True:
            buffer = self.conn.recv(self.BUFFER_SIZE)

            assert buffer, f'Missing attribute: {buffer=}'

            buffer_size = len(buffer)

            if position > 0:
                body[position:position + buffer_size] = buffer
                position += buffer_size
            else:
                header = buffer[:self.RECV_HEADER_SIZE]

                if self.header_recv_callback:
                    header = self.header_recv_callback(header)

                    assert isinstance(header, bytes), f'Wrong type: {header=}'

                header = header.decode(DEFAULT_ENCODING, errors=STRICT_ENCODING_ERRORS)
                # uuid_token = header[self.SEND_HEADER_SIZE:self.RECV_HEADER_SIZE]

                # assert self.UUID_PATTERN.match(uuid_token), f'Wrong value: {uuid_token=}'

                # if self.server_side:
                #     assert uuid_token == self.uuid_token, f'Wrong value: {uuid_token} != {self.uuid_token}'
                # else:
                #     self.uuid_token = uuid_token

                body_size = int(header[:self.SEND_HEADER_SIZE])

                if body_size >= self.MAX_BUFFER_SIZE:
                    self.BUFFER_SIZE = self.MAX_BUFFER_SIZE

                if callback:
                    bytes_to_recieve = Bytes.format(body_size + self.RECV_HEADER_SIZE)

                body_buffer_size   = buffer_size - self.RECV_HEADER_SIZE
                body               = bytearray(body_size)
                body[:buffer_size] = buffer[self.RECV_HEADER_SIZE:]
                position += body_buffer_size

            assert position <= body_size, f'Wrong value: {position} > {body_size}'

            if callback:
                history.append((Bytes.format(buffer_size),
                                Bytes.format(position + self.RECV_HEADER_SIZE),
                                bytes_to_recieve))

            if position == body_size:
                body = bytes(body)

                if self.recv_callback:
                    body = self.recv_callback(body)

                    assert isinstance(body, bytes), f'Wrong type: {body=}'

                body = body.decode(self.ENCODING, errors=LIBERAL_ENCODING_ERRORS)
                body = json.loads(body, cls=ExtendedDecoder)

                assert isinstance(body, dict), f'Wrong type: {body=}'

                if callback:
                    callback(history)

                return body

class SymmetricSocket(Socket):

    def __init__(
        self,
        *args,
        password: str=None,
        salt: str=None,
        **kwargs
    ) -> None:
        super().__init__(*args, **kwargs)

        assert isinstance(password, str) or password is None, f'Wrong type: {password=}'
        assert isinstance(salt, str) or salt is None, f'Wrong type: {salt=}'

        self.password = password
        self.salt     = salt

    def set_context(self) -> None:
        assert self.server_side, f'Wrong value: {self.server_side=}'

        if self.is_host:
            self.data_wrap       = 'HOSTING :: AES'
            self.data_wrap_notes = f'{self.password} :: {self.salt}'
        else:
            self.data_wrap       = 'CONNECTING :: AES'
            self.data_wrap_notes = 'AES_128_CBC_PKCS7_HMAC_SHA256'

    def set_middleware(self) -> None:
        assert not self.is_host, f'Wrong value: {self.is_host=}'
        assert self.password, f'Missing attribute: {self.password=}'
        assert self.salt, f'Missing attribute: {self.salt=}'

        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        from cryptography.fernet import Fernet

        secret = PBKDF2HMAC(algorithm=hashes.SHA256(),
                            length=32,
                            salt=self.salt.encode(DEFAULT_ENCODING,
                                                  errors=STRICT_ENCODING_ERRORS),
                            iterations=320000,
                            backend=default_backend())
        secret = secret.derive(self.password.encode(DEFAULT_ENCODING,
                                                    errors=STRICT_ENCODING_ERRORS))
        secret = Fernet(base64.urlsafe_b64encode(secret))

        recv_header_size          = ''.ljust(self.RECV_HEADER_SIZE)
        recv_header_size          = recv_header_size.encode(DEFAULT_ENCODING,
                                                            errors=STRICT_ENCODING_ERRORS)
        self.RECV_HEADER_SIZE     = len(secret.encrypt(recv_header_size))
        self.header_send_callback = lambda header: secret.encrypt(header)
        self.header_recv_callback = lambda header: secret.decrypt(header)
        self.send_callback        = lambda body: secret.encrypt(zlib.compress(body))
        self.recv_callback        = lambda body: zlib.decompress(secret.decrypt(body))

class AsymmetricSocket(Socket):

    def __init__(
        self,
        *args,
        public_key: str=None,
        private_key: str=None,
        public_key_data: str=None,
        **kwargs
    ) -> None:
        super().__init__(*args, **kwargs)

        assert isinstance(public_key, str) or public_key is None, f'Wrong type: {public_key=}'
        assert isinstance(private_key, str) or private_key is None, f'Wrong type: {private_key=}'
        assert isinstance(public_key_data, str) or public_key_data is None, f'Wrong type: {public_key_data=}'

        self.public_key      = public_key
        self.private_key     = private_key
        self.public_key_data = public_key_data

    def set_context(self) -> None:
        assert self.server_side, f'Wrong value: {self.server_side=}'

        if self.is_host:
            self.data_wrap       = 'HOSTING :: TLS'
            self.data_wrap_notes = f'{self.public_key} :: {self.private_key}'
        else:
            self.data_wrap = 'CONNECTING :: TLS'
            cipher         = self.conn.cipher()

            if cipher:
                self.data_wrap_notes = ' :: '.join(cipher[:2])

    def set_middleware(self) -> None:
        if self.server_side:
            assert self.is_host, f'Wrong value: {self.is_host=}'
            assert self.public_key, f'Missing attribute: {self.public_key=}'
            assert self.private_key, f'Missing attribute: {self.private_key=}'

            context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            context.load_cert_chain(self.public_key, self.private_key)
            self.conn = context.wrap_socket(self.conn, server_side=True)
        else:
            assert self.public_key_data, f'Missing attribute: {self.public_key_data=}'

            context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            context.load_verify_locations(cadata=self.public_key_data)
            self.conn = context.wrap_socket(self.conn)
