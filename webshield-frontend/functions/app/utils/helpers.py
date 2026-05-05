import asyncio
from typing import Any, Coroutine, List

async def run_parallel_tasks(tasks: List[Coroutine]) -> List[Any]:
    """
    Helper to run multiple async tasks in parallel and gather results.
    """
    return await asyncio.gather(*tasks, return_exceptions=True)

def format_timestamp(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")
