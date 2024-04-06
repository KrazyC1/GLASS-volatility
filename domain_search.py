from typing import Iterable, Tuple, List
from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import scanners
from volatility3.plugins.windows import pslist
import string, os

class Search(interfaces.plugins.PluginInterface):
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(name='kernel', description='Windows kernel'),
            requirements.PluginRequirement(name='pslist', plugin=pslist.PsList, version=(2, 0, 0)),
        ]

    def _generator(self) -> Iterable[Tuple[int, Tuple[str, str, str, int, str, str]]]:
        rows = []
        for layer_name in self.context.layers:
            layer = self.context.layers[layer_name]
            file_path = layer.file_path if hasattr(layer, 'file_path') else 'Unknown'
            scanner = scanners.MultiStringScanner([b'bank'])
            for offset, match in layer.scan(context=self.context, scanner=scanner):
                start = max(0, offset - 32)
                try:
                    end = min(layer.maximum_address, offset + len(match) + 32)
                except (TypeError, ValueError):
                    end = min(layer.file.get_size(), offset + len(match) + 32)
                context = layer.read(start, end - start)
                printable = set(string.printable)
                context = ''.join(filter(lambda x: x in printable, context.decode('utf-8', errors='ignore')))
                rows.append((0, (os.path.basename(file_path), os.path.dirname(file_path), layer_name, offset, match.decode('utf-8', errors='ignore'), context)))
        yield from rows

    def run(self) -> interfaces.renderers.TreeGrid:
        return renderers.TreeGrid([("File", str), ("Directory", str), ("Layer", str), ("Offset", int), ("String", str), ("Context", str)], self._generator())