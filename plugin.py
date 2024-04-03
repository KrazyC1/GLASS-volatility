from typing import Iterable, Tuple, List
from volatility3.framework import interfaces, constants, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import scanners
from volatility3.plugins.windows import pslist
import string
import os

class BankScanner(interfaces.plugins.PluginInterface):
    """Searches the memory dump for the string 'bank'."""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(name='kernel', description='Windows kernel'),
            requirements.PluginRequirement(name='pslist', plugin=pslist.PsList, version=(2, 0, 0)),
        ]

    def _generator(self) -> Iterable[Tuple[int, Tuple[str, str, str, int, str, str]]]:
        """Scans the memory dump for the string 'bank'."""
        rows = []
        for layer_name in self.context.layers:
            layer = self.context.layers[layer_name]
            if hasattr(layer, 'file_path'):
                file_path = layer.file_path
            else:
                file_path = 'Unknown'
            scanner = scanners.MultiStringScanner([b'bank'])
            for offset, match in layer.scan(context=self.context, scanner=scanner):
                # Get the context around the found string
                start = max(0, offset - 32)
                try:
                    end = min(layer.maximum_address, offset + len(match) + 32)
                except (TypeError, ValueError):
                    # If the maximum_address is not available, fall back to the file size
                    end = min(layer.file.get_size(), offset + len(match) + 32)
                context = layer.read(start, end - start)
                # Remove non-printable characters from the context
                printable = set(string.printable)
                context = ''.join(filter(lambda x: x in printable, context.decode('utf-8', errors='ignore')))
                rows.append((0, (os.path.basename(file_path), os.path.dirname(file_path), layer_name, offset, match.decode('utf-8', errors='ignore'), context)))

        yield from rows

    def run(self) -> interfaces.renderers.TreeGrid:
        """Runs the plugin and returns the results."""
        return renderers.TreeGrid(
            [
                ("File", str),
                ("Directory", str),
                ("Layer", str),
                ("Offset", int),
                ("String", str),
                ("Context", str),
            ],
            self._generator()
        )