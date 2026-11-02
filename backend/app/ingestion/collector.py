import asyncio
import os
import aiofiles
import logging
from abc import ABC, abstractmethod
from typing import Callable, Awaitable

logger = logging.getLogger(__name__)

class LogCollector(ABC):
    @abstractmethod
    async def start(self):
        pass

    @abstractmethod
    async def stop(self):
        pass

class FileCollector(LogCollector):
    def __init__(self, file_path: str, callback: Callable[[str], Awaitable[None]]):
        self.file_path = file_path
        self.callback = callback
        self._running = False
        self._task = None

    async def start(self):
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._monitor())
        logger.info(f"Started monitoring {self.file_path}")

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
        logger.info(f"Stopped monitoring {self.file_path}")

    async def _monitor(self):
        # basic tail -f implementation
        position = 0
        if os.path.exists(self.file_path):
            position = os.path.getsize(self.file_path)

        while self._running:
            try:
                if not os.path.exists(self.file_path):
                    await asyncio.sleep(1)
                    continue

                async with aiofiles.open(self.file_path, mode='r', encoding='utf-8', errors='replace') as f:
                    # Handle log rotation/truncation
                    current_size = os.path.getsize(self.file_path)
                    if current_size < position:
                        position = 0
                    
                    await f.seek(position)
                    
                    while self._running:
                        line = await f.readline()
                        if not line:
                            break
                        line = line.rstrip('\n')
                        if line:
                            await self.callback(line)
                    position = await f.tell()
            except Exception as e:
                logger.error(f"Error reading file {self.file_path}: {e}")
            
            await asyncio.sleep(1)

class SampleCollector(LogCollector):
    def __init__(self, sample_dir: str, callback: Callable[[str], Awaitable[None]]):
        self.sample_dir = sample_dir
        self.callback = callback
        self._running = False
        self._task = None

    async def start(self):
        self._running = True
        self._task = asyncio.create_task(self._run_demo())
        logger.info(f"Started sample collector from {self.sample_dir}")

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()

    async def _run_demo(self):
        # Iterates over sample files and feeds them slowly
        while self._running:
            try:
                for file_name in os.listdir(self.sample_dir):
                    if not self._running: break
                    file_path = os.path.join(self.sample_dir, file_name)
                    if os.path.isfile(file_path) and file_name.endswith('.log'):
                        async with aiofiles.open(file_path, 'r', encoding='utf-8') as f:
                            async for line in f:
                                if not self._running: break
                                line = line.rstrip('\n')
                                if line:
                                    await self.callback(line)
                                    await asyncio.sleep(0.5) # Fake delay
            except Exception as e:
                logger.error(f"Error in sample collector: {e}")
            await asyncio.sleep(5)
