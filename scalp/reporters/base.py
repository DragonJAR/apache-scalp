"""Base reporter interface."""
from abc import ABC, abstractmethod
from scalp.core.engine import ScanResult


class BaseReporter(ABC):
    @classmethod
    @abstractmethod
    def generate(cls, result: ScanResult, output_path: str, source_name: str = "") -> None:
        """Generates report from ScanResult into output_path."""
        pass
