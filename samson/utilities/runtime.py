from samson.auxiliary.progress import Progress
from multiprocessing.dummy import Pool as ThreadPool
from multiprocessing.pool import Pool as ProcessPool
from multiprocessing import cpu_count
from functools import wraps, lru_cache
from types import FunctionType
from hmac import compare_digest
import math
import logging
import inspect
import sys
import os

from samson.auxiliary.lazy_loader import LazyLoader
_integer_ring = LazyLoader('_integer_ring', globals(), 'samson.math.algebra.rings.integer_ring')


URANDOM = open("/dev/urandom", "rb")


def default_poly_fft_heuristic(p1, p2):
    max_deg = max(len(p1)-p1.valuation(), len(p2)-p2.valuation())
    if not max_deg:
        return False

    logn = math.ceil(math.log2(max_deg))
    n    = 2**logn

    return p1.coeffs.sparsity * p2.coeffs.sparsity > 10*(3*n*logn+n)


def default_ntt_heuristic(p1, p2):
    return max(p1.degree(), p2.degree()) > 7 and (p1.coeff_ring.is_field() and (1 < p1.coeff_ring.characteristic().bit_length() < 768)) or p1.coeff_ring == _integer_ring.ZZ


class RuntimeConfiguration(object):
    """
    Global runtime configuration. Allows for the dynamic configuration of existing samson code.
    """

    def __init__(self, log_fmt: str='%(asctime)s - %(name)s [%(levelname)s] %(message)s', use_color: bool=True, use_rich: bool=True, minimize_output: bool=True):
        # Initialize reporter
        try:
            from samson.auxiliary.tqdm_handler import TqdmHandler
            from samson.auxiliary.tqdm_reporter import TqdmReporter
            from samson.auxiliary.colored_formatter import ColoredFormatter

            handler = TqdmHandler()

            self.use_color = use_color
            self.use_rich  = use_rich

            # Only color logs if attached to TTY
            if sys.stdout.isatty() and use_color:
                formatter = ColoredFormatter(fmt=log_fmt)
            else:
                formatter = logging.Formatter(fmt=log_fmt)

            handler.setFormatter(formatter)
            handler.setLevel(logging.DEBUG)

            self.reporter = TqdmReporter()
            self.set_global_log_handler(handler)

        except ImportError:
            from samson.auxiliary.reporter import Reporter
            self.reporter = Reporter()


        if use_color and use_rich:
            try:
                self.install_rich_exceptions()
            except ImportError:
                pass


        self.random = lambda size: URANDOM.read(size)
        self.poly_fft_heuristic = default_poly_fft_heuristic
        self.poly_exp_separator = "^"
        self.poly_ntt_heuristic = default_ntt_heuristic

        if minimize_output:
            self.default_short_printer = lambda elem: elem.tinyhand()
        else:
            self.default_short_printer = lambda elem: elem.shorthand()

        self.minimize_output = minimize_output

        self.enable_poly_intercept = False
        self.enable_MOV_attack = True
        self.auto_promote = True
        self.index_calculus_supremacy = 70

        self.last_tb = None

        self.global_cache_size = 1024
        self.global_cache_enabled = True

        # Find mseive
        import distutils.spawn
        self.msieve_loc = distutils.spawn.find_executable("msieve")
        self.cado_nfs_loc = distutils.spawn.find_executable('cado-nfs.py') or distutils.spawn.find_executable('cado-nfs')
        self.cado_nfs_supremacy = 70


        # Initialize exploit mappings
        self.exploits = {}
        self.exploit_mappings = {}
        self.constraints = {}

        self.primitives = []

        self._contexts = {}


    def __repr__(self):
        return f"<RuntimeConfiguration: reporter={self.reporter}, auto_promote={self.auto_promote}, enable_poly_intercept={self.enable_poly_intercept}, enable_MOV_attack={self.enable_MOV_attack}>"

    def __str__(self):
        return self.__repr__()



    def set_global_log_handler(self, handler: logging.StreamHandler, log_level: int=logging.DEBUG):
        """
        Replaces the default global log handler.

        Parameters:
            handler (StreamHandler): New log StreamHandler.
            log_level         (int): Log level for global logging.
        """
        root_logger = logging.getLogger()
        root_logger.handlers = []
        root_logger.addHandler(handler)
        root_logger.propagate = False
        root_logger.setLevel(log_level)



    def report_progress(self, iterable: object, **kwargs) -> Progress:
        """
        Reports context-specific progress to the runtime reporter.

        Parameters:
            iterable (iterable): Iterable to report for. Can be set to `None`/updated manually.
            **kwargs   (kwargs): Keyword arguments to pass to the returned Progress object.

        Returns:
            Progress: Progress reporting object.
        """
        caller_locals = inspect.stack()[1][0].f_locals

        if 'self' in caller_locals:
            key = 'self'
        elif 'cls' in caller_locals:
            key = 'cls'
        else:
            raise ValueError("Calling func must have a 'self' or 'cls' identifier.")

        return self.reporter.wrap_iteration(caller_locals[key], iterable, kwargs)



    def report(self, func: FunctionType) -> FunctionType:
        """
        Initializes a reporting context for an object or class method.

        Parameters:
            func (func): Object or class method.

        Returns:
            func: Contextualized function.
        """
        @wraps(func)
        def new_func(*args, **kwargs):
            result = None
            caller = args[0]

            try:
                self.reporter.create_context(caller, func)
                result = func(*args, **kwargs)
            finally:
                self.reporter.cleanup_context(caller, func)

            return result

        return new_func



    def register_exploit(self, cls, consequence, requirements):
        from samson.ace.exploit import DynamicExploit
        self.exploits[cls] = DynamicExploit(cls, consequence, requirements)


    def register_exploit_mapping(self, cls, attack):
        if cls not in self.exploit_mappings:
            self.exploit_mappings[cls] = []

        self.exploit_mappings[cls].append(attack)


    def register_primitive(self, cls):
        self.primitives.append(cls)


    def search_primitives(self, filter_func: FunctionType=lambda primitive: True):
        return [primitive for primitive in self.primitives if filter_func(primitive)]


    def show_primitives(self, filter_func: FunctionType=lambda primitive: True, sort_key: FunctionType=lambda primitive: str(primitive).split('.')[-1][:-2], reverse: bool=False):
        filtered_prims = sorted(self.search_primitives(filter_func), key=sort_key, reverse=reverse)
        columns        = ['Primitive', 'PrimitiveType', 'CipherType', 'SymmetryType', 'SecurityProofType', 'ConstructionType', 'UsageFrequency']

        filtered_prims = sorted(filtered_prims, key=lambda prim: prim.USAGE_FREQUENCY.value, reverse=True)

        if self.use_color and self.use_rich:
            self.__build_prims_rich_table(columns, filtered_prims)
        else:
            self.__build_prims_ascii_table(columns, filtered_prims)



    def __build_prims_ascii_table(self, col_names, primitives):
        lines = []
        all_columns = [col_names]
        max_column_sizes = [len(col) for col in all_columns[0]]

        for primitive in primitives:
            columns = [str(primitive).split('.')[-1][:-2], primitive.PRIMITIVE_TYPE.name, primitive.CIPHER_TYPE.name, primitive.SYMMETRY_TYPE.name, primitive.SECURITY_PROOF.name, ', '.join([ctype.name for ctype in primitive.CONSTRUCTION_TYPES]), primitive.USAGE_FREQUENCY.name]
            max_column_sizes = [max(len(col), curr_max) for col, curr_max in zip(columns, max_column_sizes)]
            all_columns.append(columns)

        for columns in all_columns:
            lines.append('| ' + ' | '.join([col.ljust(max_column_sizes[idx]) for idx, col in enumerate(columns)]) + ' |')
            lines.append('-' * len(lines[-1]))

        table = '=' * len(lines[-1]) + '\n' + '\n'.join(lines)
        print(table)


    def __build_prims_rich_table(self, col_names, primitives):
        from rich.table import Table
        from rich import print

        table = Table(title="Matching Cryptographic Primitives", show_lines=True)

        styles = ["dim white", "green", "magenta", "yellow", "cyan", "dim white", "green"]

        for name, style in zip(col_names, styles):
            table.add_column(name, style="bold " + style, no_wrap=True)

        for primitive in primitives:
            table.add_row(*[str(primitive).split('.')[-1][:-2], primitive.PRIMITIVE_TYPE.name, primitive.CIPHER_TYPE.name, primitive.SYMMETRY_TYPE.name, primitive.SECURITY_PROOF.name, ', '.join([ctype.name for ctype in primitive.CONSTRUCTION_TYPES]), primitive.USAGE_FREQUENCY.name])

        print()
        print(table)



    def compare_bytes(self, a: bytes, b: bytes) -> bool:
        return compare_digest(a, b)



    def set_context(self, **ctx_kwargs)-> FunctionType:
        def wrapper_0(func):
            code = func.__code__
            self._contexts[(code.co_name, code.co_nlocals, code.co_filename)] = RuntimeProxyContext(**ctx_kwargs)
            return func

        return wrapper_0


    def get_context(self):
        fr  = sys._getframe(0).f_back
        c   = None
        ctx = self._contexts

        while fr:
            c = fr.f_code

            try:
                return ctx[(c.co_name, c.co_nlocals, c.co_filename)]
            except KeyError:
                pass

            fr = fr.f_back

        return self


    def install_rich_exceptions(self):
        # https://stackoverflow.com/a/28758396
        from rich.console import Console
        from rich.traceback import Traceback
        import sys
        traceback_console = Console(file=sys.stderr)


        def showtraceback(self, _type, exception, trace):
            _type, exception, trace = sys.exc_info()
            RUNTIME.last_tb = trace

            traceback_console.print(
                Traceback.from_exception(_type, exception, trace.tb_next)
            )

        import IPython
        IPython.core.interactiveshell.InteractiveShell._showtraceback = showtraceback



    def threaded(self, threads: int, starmap: bool=False, visual: bool=False, visual_args: dict=None, chunk_size: int=None, terminate_filter: FunctionType=None):
        """
        Runs the function with `threads` threads. The returned function should take an iterable.

        Parameters:
            threads      (int): Number of threads to run.
            starmap     (bool): Whether or not to "starmap" output (see Python multiprocessing).
            visual      (bool): Whether or not to display a progress bar.
            visual_args (dict): Kwargs for progress bar.
            chunk_size   (int): Chunk sizes to use for visual mode. This is a tradeoff between progress granularity and communication overhead.

        Returns:
            list: Results.

        Examples:
            >>> from samson.utilities.runtime import RUNTIME
            >>> @RUNTIME.threaded(threads=10)
            >>> def myfunc(i):
            >>>     return i
            >>> myfunc(range(5))
            [0, 1, 2, 3, 4]

        """
        return self.__build_concurrent_pool(threads, ThreadPool, starmap, visual, visual_args, chunk_size, terminate_filter=terminate_filter)


    def parallel(self, processes: int=None, starmap: bool=False, visual: bool=False, visual_args: dict=None, chunk_size: int=None, terminate_filter: FunctionType=None):
        """
        Runs the function with `processes` processes. The returned function should take an iterable.

        Parameters:
            processes    (int): Number of processes to run.
            starmap     (bool): Whether or not to "starmap" output (see Python multiprocessing).
            visual      (bool): Whether or not to display a progress bar.
            visual_args (dict): Kwargs for progress bar.
            chunk_size   (int): Chunk sizes to use for visual mode. This is a tradeoff between progress granularity and communication overhead.

        Returns:
            list: Results.

        Examples:
            >>> from samson.utilities.runtime import RUNTIME
            >>> @RUNTIME.parallel(processes=10)
            >>> def myfunc(i):
            >>>     return i
            >>> myfunc(range(5))
            [0, 1, 2, 3, 4]

        """
        return self.__build_concurrent_pool(processes or cpu_count(), ProcessPool, starmap, visual, visual_args, chunk_size, terminate_filter=terminate_filter)



    def __build_concurrent_pool(self, workers: int, pool_type: 'Pool', starmap: bool=False, visual: bool=False, visual_args: dict=None, chunk_size: int=None, terminate_filter: FunctionType=None):
        if not visual_args:
            visual_args = {}

        def _outer_wrap(func):
            def _runner(iterable):
                local_func      = func
                local_chunk     = chunk_size
                local_term_filt = terminate_filter

                with pool_type(workers) as pool:
                    run_func = local_func

                    if visual or local_term_filt:
                        pool_runner = pool.imap_unordered

                        # Manually create a starmapper since we can't have unordered and starmap normally
                        if starmap:
                            def star_wrapper(arg):
                                return local_func(*arg)

                            run_func = star_wrapper

                    elif starmap:
                        pool_runner = pool.starmap
                    else:
                        pool_runner = pool.map


                    # https://stackoverflow.com/questions/41920124/multiprocessing-use-tqdm-to-display-a-progress-bar
                    if visual:
                        from tqdm import tqdm
                        num_items = len(iterable)

                        if not local_chunk:
                            local_chunk = max(num_items // (workers*2), 1)

                        final_runner = tqdm(pool_runner(run_func, iterable, chunksize=local_chunk), total=num_items, **visual_args)

                    else:
                        final_runner = pool_runner(run_func, iterable)


                    if local_term_filt:
                        results = []
                        for result in final_runner:
                            results.append(result)

                            if local_term_filt(results):
                                pool.terminate()
                                break

                        return results
                    else:
                        return list(final_runner)

            return _runner

        return _outer_wrap


    def global_cache(self, size: int=None, enable_user_cache: bool=False, user_cache_selector: FunctionType=None):
        """
        Wraps a function with a LRU cache of size `size`.
        """
        def _outer_wrap(func):
            cache = lru_cache(size or self.global_cache_size)(func)

            if enable_user_cache:
                if not user_cache_selector:
                    raise ValueError("User cache enabled but no selector function supplied")

                cache.user_cache = {}
                cache.user_cache_selector = user_cache_selector

            @wraps(func)
            def _inner_wrap(*args, **kwargs):
                if enable_user_cache:
                    try:
                        return cache.user_cache[cache.user_cache_selector(*args, **kwargs)]
                    except KeyError:
                        pass


                if self.global_cache_enabled:
                    return cache(*args, **kwargs)
                else:
                    return func(*args, **kwargs)

            _inner_wrap.cache_clear = cache.cache_clear
            _inner_wrap.cache_info  = cache.cache_info

            if enable_user_cache:
                _inner_wrap.user_cache  = cache.user_cache
                _inner_wrap.user_cache_selector = cache.user_cache_selector


            return _inner_wrap

        return _outer_wrap



    def _register_known_exploits(self):
        from samson.ace.exploit import KeyPossession, PlaintextPossession, BitlevelMalleability
        self.exploits[KeyPossession] = KeyPossession()
        self.exploits[PlaintextPossession] = PlaintextPossession()
        self.exploits[BitlevelMalleability] = BitlevelMalleability()



class RuntimeProxyContext(object):
    def __init__(self, **kwargs):
        self.attrs = kwargs

    def __getattr__(self, name):
        try:
            attr = self.attrs[name]
        except KeyError:
            attr = getattr(RUNTIME, name)

        return attr



RUNTIME = RuntimeConfiguration(use_color=(os.environ.get('USE_COLOR', 'True') == 'True'))
RUNTIME._register_known_exploits()
