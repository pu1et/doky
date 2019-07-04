import logging
from abc import ABCMeta
from queue import Queue
from collections import defaultdict
from threading import Lock, Thread
import time
from ..types import DokyBase
import threading

global queue_lock
queue_lock = Lock()

class EventQueue(Queue, object):
    def __init__(self, num_worker=10):
        super(EventQueue, self).__init__()
        self.all_scanners = dict()
        self.hooks = defaultdict(list)
        self.running = True
        self.workers = list()

        for i in range(num_worker):
            t = Thread(target=self.work)
            t.daemon = True
            t.start()
            self.workers.append(t)
        t = Thread(target=self.notifier)
        t.daemon = True
        t.start()


    def hang(self, event, hook=None, expectport=None):
        def wrapper(hook):
            self.hang_event(event, hook=hook, expectport=expectport)
            return hook

        return wrapper

    def hang_event(self, event, hook=None, expectport=None):
        if DokyBase in hook.__mro__:
       #     logging.debug(hook.__mro__)
            self.all_scanners[hook] = hook.__doc__
        
        if hook not in self.hooks[event]:
            self.hooks[event].append((hook, expectport))
            logging.debug('{} hang with {}'.format(hook, event))

    def pick_point(self, event, caller=None):
        logging.debug('Class {} pick a point with {}'.format(event.__class__, event))
        for hooked_event in self.hooks.keys():
            if hooked_event in event.__class__.__mro__:
                for hook, expectport in self.hooks[hooked_event]:
                    if expectport and not expectport(event):
                        continue

                    if caller:
                        event.previous = caller.event
                    self.put(hook(event))

    def work(self):
        while self.running:
            queue_lock.acquire()
            hook = self.get()
            queue_lock.release()
            try:
                hook.execute()
            except Exception as ex:
                logging.debug(ex)
            self.task_done()
        logging.debug("thread complete")


    def notifier(self):
        time.sleep(2)
        while self.unfinished_tasks > 0:
            logging.debug("{} tasks uncomplete".format(self.unfinished_tasks))
            time.sleep(3)

    def free(self):
        self.running = False
        with self.mutex:
            self.queue.clear()


works = EventQueue(500)

