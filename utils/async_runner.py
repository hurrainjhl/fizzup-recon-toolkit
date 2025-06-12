import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import List, Callable, Any, Coroutine

class AsyncRunner:
    """
    Manages concurrent operations with thread pooling and async execution
    Supports both I/O-bound and CPU-bound operations
    """
    def __init__(self, max_workers: int = 10):
        self.max_workers = max_workers
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
    
    async def run_io_tasks(self, tasks: List[Callable]) -> List[Any]:
        """
        Execute I/O-bound tasks asynchronously
        Ideal for network operations (HTTP requests, DNS queries, etc.)
        """
        async def _run_task(func):
            return await asyncio.get_event_loop().run_in_executor(
                self.executor, func
            )
        
        return await asyncio.gather(*[_run_task(task) for task in tasks])
    
    async def run_cpu_tasks(self, tasks: List[Callable]) -> List[Any]:
        """
        Execute CPU-bound tasks asynchronously
        Ideal for data processing, analysis, and computation
        """
        return await asyncio.gather(*tasks)
    
    def run_parallel(self, tasks: List[Callable], io_bound: bool = True) -> List[Any]:
        """
        Simplified interface for parallel execution
        Automatically selects appropriate method based on task type
        """
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            if io_bound:
                results = loop.run_until_complete(self.run_io_tasks(tasks))
            else:
                results = loop.run_until_complete(self.run_cpu_tasks(tasks))
            return results
        finally:
            loop.close()
    
    def map_async(self, func: Callable, items: List[Any]) -> List[Any]:
        """
        Apply a function to each item in a list asynchronously
        """
        tasks = [lambda item=item: func(item) for item in items]
        return self.run_parallel(tasks)
    
    def shutdown(self):
        """Clean up executor resources"""
        self.executor.shutdown(wait=True)

# Singleton instance for easy access
async_runner = AsyncRunner(max_workers=20)

if __name__ == "__main__":
    # Example usage
    import time
    
    def io_task(x):
        time.sleep(0.1)
        return x * 2
    
    def cpu_task(x):
        return sum(i*i for i in range(10000))
    
    # Run I/O-bound tasks
    io_results = async_runner.run_parallel([lambda: io_task(i) for i in range(10)])
    print(f"I/O Results: {io_results}")
    
    # Run CPU-bound tasks
    cpu_results = async_runner.run_parallel(
        [lambda: cpu_task(i) for i in range(5)], 
        io_bound=False
    )
    print(f"CPU Results: {cpu_results}")
    
    # Map async example
    mapped = async_runner.map_async(lambda x: x**2, [1, 2, 3, 4, 5])
    print(f"Mapped Results: {mapped}")
    
    async_runner.shutdown()
