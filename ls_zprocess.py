#####################################################################
#                                                                   #
# ls_zprocess.py                                                    #
#                                                                   #
# Copyright 2013, Monash University                                 #
#                                                                   #
# This file is part of the labscript suite (see                     #
# http://labscriptsuite.org) and is licensed under the Simplified   #
# BSD License. See the license.txt file in the root of the project  #
# for the full license.                                             #
#                                                                   #
#####################################################################
from __future__ import division, unicode_literals, print_function, absolute_import
from labscript_utils import PY2
if PY2:
    str = unicode

import sys
from socket import gethostbyname
from distutils.version import LooseVersion
import traceback
from inspect import getcallargs
import zmq

from labscript_utils import check_version, get_version, VersionException
check_version('zprocess', '2.15.2', '3.0.0')

import zprocess
import zprocess.process_tree
from zprocess.security import SecureContext
from labscript_utils.labconfig import LabConfig
from labscript_utils import dedent
import zprocess.zlog
import zprocess.zlock
import zprocess.remote
from zprocess import KillLock


"""This module is a number of wrappers around zprocess objects that configures them with
the settings in LabConfig with regard to security, and the host and port of the zlock
server. Multiprocessing done with these wrappers will automatically be configured
according to LabConfig. Manual configuration can be done by instantiating the objects
directly from zprocess instead.

To use zprocess with LabConfig configuration, use the convenience functions defined at
the bottom of this module.
"""

kill_lock = KillLock()

_cached_config = None

def get_config():
    """Get relevant options from LabConfig, substituting defaults where appropriate and
    return as a dict"""
    global _cached_config
    # Cache the config so it is not loaded multiple times per process:
    if _cached_config is not None:
        return _cached_config

    labconfig = LabConfig()
    config = {}
    try:
        config['zlock_host'] = labconfig.get('servers', 'zlock')
    except (labconfig.NoOptionError, labconfig.NoSectionError):
        msg = "No zlock server specified in labconfig"
        raise RuntimeError(msg)
    try:
        config['zlock_port'] = labconfig.get('ports', 'zlock')
    except (labconfig.NoOptionError, labconfig.NoSectionError):
        config['zlock_port'] = zprocess.zlock.DEFAULT_PORT
    # We hard-code the zlog host and port, since zlog always runs on the computer with
    # the top-level process
    config['zlog_host'] = 'localhost'
    config['zlog_port'] = zprocess.zlog.DEFAULT_PORT
    try:
        config['zprocess_remote_port'] = labconfig.get('ports', 'zprocess_remote')
    except (labconfig.NoOptionError, labconfig.NoSectionError):
        config['zprocess_remote_port'] = zprocess.remote.DEFAULT_PORT
    try:
        shared_secret_file = labconfig.get('security', 'shared_secret')
    except (labconfig.NoOptionError, labconfig.NoSectionError):
        config['shared_secret'] = None
        config['shared_secret_file'] = None
    else:
        config['shared_secret'] = open(shared_secret_file).read().strip()
        config['shared_secret_file'] = shared_secret_file
    try:
        config['allow_insecure'] = labconfig.getboolean('security', 'allow_insecure')
    except (labconfig.NoOptionError, labconfig.NoSectionError):
        # Default will be set to False once the security rollout is complete:
        config['allow_insecure'] = True
    try:
        config['logging_maxBytes'] = labconfig.getint('logging', 'maxBytes')
    except (labconfig.NoOptionError, labconfig.NoSectionError):
        config['logging_maxBytes'] = 1024 * 1024 * 50
    try:
        config['logging_backupCount'] = labconfig.getint('logging', 'backupCount')
    except (labconfig.NoOptionError, labconfig.NoSectionError):
        config['logging_backupCount'] = 1
    _cached_config = config
    return config


class ProcessTree(zprocess.ProcessTree):
    """A singleton zprocess.ProcessTree configured with settings from labconfig for
    security, zlock and zlog. Being a singleton is not enforced - the class can still be
    instantiated as normal - but calling the .instance() classmethod will give the
    singleton."""

    _instance = None

    @classmethod
    def instance(cls):
        # If we are already a child process, return the ProcessTree associated with the
        # connection to our parent. This may not even be an instance of this subclass,
        # but it will be if this subclass was used when calling connect_to_parent().
        instance = zprocess.ProcessTree.instance()
        if instance is not None:
            return instance
        # Otherwise, return previously initialised singleton for the top-level process:
        if cls._instance is not None:
            return cls._instance
        # Otherwise, create that singleton and return it:
        config = get_config()
        cls._instance = cls(
            shared_secret=config['shared_secret'],
            allow_insecure=config['allow_insecure'],
            zlock_host=config['zlock_host'],
            zlock_port=config['zlock_port'],
            zlog_host='localhost',
            zlog_port=config['zlog_port'],
        )
        # Assign this to the default zprocess ProcessTree so that code using deprecated
        # zprocess calls use this ProcessTree:
        zprocess.process_tree._default_process_tree = cls._instance
        # Assign the zlock client as the default zlock server so that code using
        # deprecated zlock calls can use it:
        zprocess.zlock._default_zlock_client = cls._instance.zlock_client

        return cls._instance


class ZMQServer(zprocess.ZMQServer):
    """A ZMQServer configured with security settings from labconfig"""

    def __init__(
        self,
        port=None,
        dtype='pyobj',
        pull_only=False,
        bind_address='tcp://0.0.0.0',
        timeout_interval=None,
        **kwargs
    ):
        # There are ways to process args and exclude the keyword arguments we disallow
        # without having to include the whole function signature above, but they are
        # Python 3 only, so we avoid them for now.
        msg = """keyword argument {} not allowed - it will be set according to
            LabConfig. To make a custom ZMQServer, use zprocess.ZMQserver instead of
            labscript_utils.zprocess.ZMQServer"""

        # Error if these args are provided, since we provide them:
        for kwarg in ['shared_secret', 'allow_insecure']:
            if kwarg in kwargs:
                raise ValueError(dedent(msg.format(kwarg)))

        config = get_config()
        shared_secret = config['shared_secret']
        allow_insecure = config['allow_insecure']

        zprocess.ZMQServer.__init__(
            self,
            port=port,
            dtype=dtype,
            pull_only=pull_only,
            bind_address=bind_address,
            shared_secret=shared_secret,
            allow_insecure=allow_insecure,
            timeout_interval=timeout_interval,
            **kwargs
        )


class ZMQClient(zprocess.ZMQClient):
    """A singleton zprocess.ZMQClient configured with settings from labconfig for
    security.  Being a singleton is not enforced - the class can still be
    instantiated as normal - but calling the .instance() classmethod will give the
    singleton."""

    _instance = None

    def __init__(self):
        config = get_config()
        shared_secret = config['shared_secret']
        allow_insecure = config['allow_insecure']
        zprocess.ZMQClient.__init__(
            self, shared_secret=shared_secret, allow_insecure=allow_insecure
        )

    @classmethod
    def instance(cls):
        # Return previously initialised singleton:
        if cls._instance is None:
            # Create singleton:
            cls._instance = cls()
        return cls._instance
        

class Context(SecureContext):
    """Subclass of zprocess.security.SecureContext configured with settings from
    labconfig, substitutable for a zmq.Context. Can be instantiated to get a unique
    context, or call the .instance() classmethod to possibly get an already-existing
    one. Only use the latter if you do not indent to terminate the context."""
    def __init__(self, io_threads=1, shared_secret=None):
        config = get_config()
        # Allow shared_secret only if it matches what we expect. This is because
        # zprocess SecureContext.instance() will call our __init__ method with the
        # shared secret whether we like it or not, so let's cooperate with that.
        if shared_secret is not None and shared_secret != config['shared_secret']:
            msg = "shared_secret must be None or match labconfig"
            raise ValueError(msg)
        SecureContext.__init__( 
            self, io_threads=io_threads, shared_secret=config['shared_secret']
        )

    @classmethod
    def instance(cls):
        config = get_config()
        # Super required to call unbound class method of parent class:
        return super(Context, cls).instance(shared_secret=config['shared_secret'])

    def socket(self, *args, **kwargs):
        config = get_config()
        kwargs['allow_insecure'] = config['allow_insecure']
        return SecureContext.socket(self, *args, **kwargs)


def Lock(*args, **kwargs):
    if 'read_only' in kwargs and not _zlock_server_supports_readwrite:
        # Ignore read_only argument if the server does not support it:
        del kwargs['read_only']
    return ProcessTree.instance().lock(*args, **kwargs)


def Event(*args, **kwargs):
    return ProcessTree.instance().event(*args, **kwargs)


def Handler(*args, **kwargs):
    return ProcessTree.instance().logging_handler(*args, **kwargs)


def zmq_get(*args, **kwargs):
    return ZMQClient.instance().get(*args, **kwargs)


def zmq_get_multipart(*args, **kwargs):
    return ZMQClient.instance().get_multipart(*args, **kwargs)


def zmq_get_string(*args, **kwargs):
    return ZMQClient.instance().get_string(*args, **kwargs)


def zmq_get_raw(*args, **kwargs):
    return ZMQClient.instance().get_raw(*args, **kwargs)


def zmq_push(*args, **kwargs):
    return ZMQClient.instance().push(*args, **kwargs)


def zmq_push_multipart(*args, **kwargs):
    return ZMQClient.instance().push_multipart(*args, **kwargs)


def zmq_push_string(*args, **kwargs):
    return ZMQClient.instance().push_string(*args, **kwargs)


def zmq_push_raw(*args, **kwargs):
    return ZMQClient.instance().push_raw(*args, **kwargs)


def RemoteProcessClient(host, port=None):
    if port is None:
        config = get_config()
        port = config['zprocess_remote_port']
    return ProcessTree.instance().remote_process_client(host, port)


ZLOCK_DEFAULT_TIMEOUT = 45
_zlock_server_supports_readwrite = False

def connect_to_zlock_server():
    # Ensure we are connected to a zlock server, and start one if one is supposed
    # to be running on localhost but is not.
    client = ProcessTree.instance().zlock_client
    if gethostbyname(client.host) == gethostbyname('localhost'):
        try:
            # short connection timeout if localhost, don't want to
            # waste time:
            client.ping(timeout=0.05)
        except zmq.ZMQError:
            # No zlock server running on localhost. Start one. It will run forever, even
            # after this program exits. This is important for other programs which might
            # be using it. I don't really consider this bad practice since the server is
            # typically supposed to be running all the time:
            zprocess.start_daemon(
                [sys.executable, '-m', 'labscript_utils.zlock', '--daemon']
            )
            # Try again. Longer timeout this time, give it time to start up:
            client.ping(timeout=15)
    else:
        client.ping()

    # Check if the zlock server supports read-write locks:
    global _zlock_server_supports_readwrite
    if hasattr(client, 'get_protocol_version'):
        version = client.get_protocol_version()
        if LooseVersion(version) >= LooseVersion('1.1.0'):
            _zlock_server_supports_readwrite = True

    # The user can call these functions to change the timeouts later if they
    # are not to their liking:
    client.set_default_timeout(ZLOCK_DEFAULT_TIMEOUT)


_connected_to_zlog = False


def ensure_connected_to_zlog():
    """Ensure we are connected to a zlog server. If one is not running and we are the
    top-level process, start a zlog server configured according to LabConfig."""
    global _connected_to_zlog
    if _connected_to_zlog:
        return
    # setup connection with the zlog server:
    client = ProcessTree.instance().zlog_client
    if gethostbyname(client.host) == gethostbyname('localhost'):
        try:
            # short connection timeout if localhost, don't want to
            # waste time:
            client.ping(timeout=0.05)
        except zmq.ZMQError:
            # No zlog server running on localhost. Start one. It will run forever, even
            # after this program exits. This is important for other programs which might
            # be using it. I don't really consider this bad practice since the server is
            # typically supposed to be running all the time:
            zprocess.start_daemon(
                [sys.executable, '-m', 'labscript_utils.zlog', '--daemon']
            )
            # Try again. Longer timeout this time, give it time to start up:
            client.ping(timeout=15)
    else:
        client.ping()
    _connected_to_zlog = True


# A version number for the protocol itself
RPC_PROTO_VERSION = '1.0.0'


class RPCServer(ZMQServer):
    """A ZMQServer than handles requests in the form of methods with arguments, keyword
    arguments, and a list of required versions of modules to be passed to check_version
    on the server before the method call. Methods must be named `handle_<name>` where
    <name> is the name of a method in the corresponding client class"""
    server_name = None
    def __init__(self, port=None, bind_address='tcp://0.0.0.0', timeout_interval=None):
        ZMQServer.__init__(
            self,
            port=port,
            bind_address=bind_address,
            timeout_interval=timeout_interval,
        )
        if self.server_name is None:
            msg = """Please set class attribute server_name to the name
                of the program the server is running in"""
            raise ValueError(dedent(msg))

    def handle_get_version(self, *args, **kwargs):
        return get_version(*args, **kwargs)

    def handle_hello(self):
        return 'hello'

    def handler(self, request_data):
        try:
            try:
                method_name, args, kwargs, request_metadata = request_data
                method_name = str(method_name)
                args = tuple(args)
                kwargs = dict(kwargs)
                request_metadata = dict(request_metadata)
                required_server_versions = request_metadata['required_server_versions']
            except (ValueError, TypeError, KeyError):
                return self.fallback_handler(request_data)
            for v_args, v_kwargs in required_server_versions:
                check_version(*v_args, **v_kwargs)
            try:
                f = getattr(self, 'handle_' + method_name)
            except AttributeError:
                raise AttributeError(
                    ' %s server has no such method ' % self.server_name
                    + repr(method_name)
                )
            return f(*args, **kwargs)
        except Exception as e:
            msg = traceback.format_exc()
            msg = '%s server returned an exception:\n' % self.server_name + msg
            e = e.__class__(msg)
            # This extra attribute is how the client can tell the difference between a
            # handled exception from this class, and an exception from an older
            # ZMQServer that does not know how to handle its request. Since the
            # old-style servers do not have versioning capabilities, this is the best we
            # can do! The clients will treat any exceptions not tagged in this way as
            # due to the server being too old and will raise a VersionException instead.
            e.from_RPCServer = True
            return e

    def fallback_handler(self, request_data):
        """Subclasses should implement this method to support requests that are not in
        the form of a method, arguments and keyword arguments, for backward
        compatibility with cleints speaking older RPC protocols."""
        msg = "Request did not conform to RPC protocol %s format" % RPC_PROTO_VERSION
        raise ValueError(msg)


class RPCClient(ZMQClient):
    _required_server_versions = None
    _client_versions = None
    server_name = None

    def __init__(self, host=None, port=None):
        ZMQClient.__init__(self)
        self.host = host
        self.port = port
        if self._required_server_versions is None:
            msg = """RPCClient subclass must call self.require_server_version() at
                least once from its __init__ method specifying the minimum version of
                the server program required."""
            raise RuntimeError(dedent(msg))
        if self._client_versions is None:
            msg = """RPCClient subclass must call self.declare_client_version() at least
                once from its __init__ method specifying the version of the client
                program or API."""
            raise RuntimeError(dedent(msg))
        if self.server_name is None:
            msg = """RPCClient subclass must set the class attribute server_name."""
            raise ValueError(dedent(msg))
        self._client_versions.append(('_rpc_proto', RPC_PROTO_VERSION))

    def require_server_version(self, *args, **kwargs):
        """Call this method from __init__ of a subclass for each required version of a
        component on the server. All method calls will check that the server satisfies
        these requirements. Call signature is the same as labscript_utils.check_version.
        This method must be called at least once before calling RPCClient.__init__ from
        a subclass, as at the very least the minimum version of the program containing
        the RPCServer must be specified."""
        if self._required_server_versions is None:
            self._required_server_versions = []
        self._required_server_versions.append((args, kwargs))

    def declare_client_version(self, name, version):
        """Call this method from the __init__ of  subclass to declare the version of a
        component on the client. This will be communicated to the server and it may
        change its behaviour depending on the client's versions. At the very least
        this must be called once to declare the version of the client API itself."""
        if self._client_versions is None:
            self._client_versions = []
        self._client_versions.append((name, version))


    def request(self, method_name, *args, **kwargs):
        request_metadata = {
            'required_server_versions': self._required_server_versions,
            'client_versions': self._client_versions,
        }
        response = self.get(
            self.port,
            self.host,
            data=[method_name, args, kwargs, request_metadata],
            timeout=15,
            raise_server_exceptions=False,
        )

        if not isinstance(response, Exception):
            return response

        if getattr(response, 'from_RPCServer', False):
            # The error was from an RPCServer, so raise it
            raise response
        # The error was from an old-style ZMQServer not using the new RPC protocol.
        # Raise an error telling the user to upgrade the server instead:
        msg = """ {} server version not new enough to handle request. Please ensure the
            server satisfies the following version requirements:"""
        msg = dedent(msg).format(self.server_name)
        for args, kwargs in self._required_versions:
            call_values = getcallargs(check_version, *args, **kwargs)
            module_name = call_values['module_name']
            at_least = call_values['at_least']
            less_than = call_values['less_than']
            line = '\n    {at_least} <= {module_name} < {less_than}'
            msg += line.format(
                module_name=module_name, at_least=at_least, less_than=less_than
            )
        raise VersionException(msg)

    def say_hello(self):
        return self.request('hello')

    def get_version(self, *args, **kwargs):
        return self.get_version(*args, **kwargs)