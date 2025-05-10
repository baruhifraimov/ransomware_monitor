"""
Module to start and stop directory monitoring using Watchdog.

Performance:
    - Memory Usage: O(1) - Only maintains observer and path information
    - Runtime Complexity: O(1) - Event handling is delegated to handlers
    - I/O Complexity: Low - Uses OS-level file event notifications (not polling)
"""
import time
from watchdog.observers import Observer
from handler import RansomwareEventHandler
from logger import logger

class DirectoryMonitor:
    def __init__(self, path):
        self.path = path
        self.observer = Observer()

    def start(self):
        logger.info(f'Starting live monitor on directory: "{self.path}"')
        event_handler = RansomwareEventHandler()
        self.observer.schedule(event_handler, self.path, recursive=False)
        self.observer.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        self.observer.stop()
        self.observer.join()
        logger.info('Stopped live monitor.')
