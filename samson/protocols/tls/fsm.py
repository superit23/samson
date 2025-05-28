from samson.core.base_object import BaseObject
from queue import Queue
import inspect
import logging


class FiniteStateMachineFinished(Exception):
    pass

class FiniteStateMachine(BaseObject):
    def __init__(self):
        self.msg_queue = Queue()
        self.transition_table = {}

        self.FINISHED = object()
        self._register_transitions()
        self._logger = logging.getLogger(__name__)
    

    def log(self, level: int, text: str, frame_idx: int=1):
        func_name = inspect.stack()[frame_idx].function
        caller    = getattr(self, func_name)
        self._logger.log(level, f'{caller._transition.name}: {text}')


    def log_debug(self, text: str, frame_idx: int=2):
        self.log(logging.DEBUG, text=text, frame_idx=frame_idx)


    def log_info(self, text: str, frame_idx: int=2):
        self.log(logging.INFO, text=text, frame_idx=frame_idx)


    def _register_transitions(self):
        for attr_name in dir(self):
            attr = getattr(self, attr_name)

            if hasattr(attr, '_transition'):
                self.transition_table[attr._transition] = attr

    

    def next(self):
        next_state, args, kwargs = self.msg_queue.get()

        if next_state == self.FINISHED:
            raise FiniteStateMachineFinished


        self.transition_table[next_state](*args, **kwargs)


    @staticmethod
    def transition(state):
        def _fsm_wrapper(func):
            def _call_wrap(self, *args, **kwargs):
                self.msg_queue.put(func(self, *args, **kwargs))
            
            _call_wrap._transition = state
            return _call_wrap
        
        return _fsm_wrapper



FSM = FiniteStateMachine
