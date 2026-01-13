# progress.py — CarapauCracker Progress Indicators
"""
Progress bars and visual feedback for long-running operations
"""
from typing import Optional, Callable
from rich.progress import (
    Progress, SpinnerColumn, TextColumn, BarColumn,
    TimeRemainingColumn, TaskID, MofNCompleteColumn
)
from rich.console import Console
from contextlib import contextmanager
import time

console = Console()


@contextmanager
def progress_context(description: str, total: Optional[int] = None):
    """
    Context manager for progress bars
    
    Args:
        description: Description of the operation
        total: Total number of items (None for indeterminate)
    
    Example:
        with progress_context("Scanning ports", total=100) as progress:
            for i in range(100):
                progress.update(1)
                time.sleep(0.1)
    """
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn() if total else TextColumn(""),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeRemainingColumn(),
        console=console,
        transient=False
    ) as progress:
        task_id = progress.add_task(description, total=total)
        yield ProgressWrapper(progress, task_id)


class ProgressWrapper:
    """Wrapper for progress task updates"""
    
    def __init__(self, progress: Progress, task_id: TaskID):
        self.progress = progress
        self.task_id = task_id
    
    def update(self, advance: int = 1, description: Optional[str] = None):
        """Update progress"""
        self.progress.update(
            self.task_id,
            advance=advance,
            description=description
        )
    
    def set_total(self, total: int):
        """Update total"""
        self.progress.update(self.task_id, total=total)


def show_spinner(description: str, func: Callable, *args, **kwargs):
    """
    Show spinner while executing a function
    
    Args:
        description: Description to show
        func: Function to execute
        *args, **kwargs: Arguments for function
    
    Returns:
        Function result
    """
    with progress_context(description) as progress:
        result = func(*args, **kwargs)
        progress.update(1)
        return result


def progress_bar(description: str, total: int):
    """
    Create a progress bar for iteration
    
    Args:
        description: Description of operation
        total: Total number of items
    
    Returns:
        Generator that yields progress updates
    
    Example:
        for item, progress in progress_bar("Processing", 100):
            process(item)
            progress.update(1)
    """
    with progress_context(description, total=total) as progress:
        def update_wrapper(items):
            for item in items:
                yield item, progress
        
        return update_wrapper


def estimate_time_remaining(current: int, total: int, elapsed: float) -> float:
    """
    Estimate time remaining based on current progress
    
    Args:
        current: Current progress
        total: Total items
        elapsed: Elapsed time in seconds
    
    Returns:
        Estimated seconds remaining
    """
    if current == 0:
        return 0.0
    
    rate = current / elapsed
    remaining = total - current
    
    if rate > 0:
        return remaining / rate
    
    return 0.0
