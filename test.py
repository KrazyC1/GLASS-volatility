import os
import string
import requests
from typing import Iterable, Tuple, List
from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import scanners
from volatility3.plugins.windows import pslist
from tqdm import tqdm

DOMAIN_TYPES = {
    'malware': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
    'fakenews': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-only/hosts',
    'gambling': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling-only/hosts',
    'porn': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts',
    'social': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/social-only/hosts'
}

class Search(interfaces.plugins.PluginInterface):
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(name='kernel', description='Windows kernel'),
            requirements.PluginRequirement(name='pslist', plugin=pslist.PsList, version=(2, 0, 0)),
            requirements.StringRequirement(name='domain_type', description='Type of domains to search for', default='malware', optional=False),
        ]

    def _download_domains(self, domain_type: str) -> List[str]:
        try:
            response = requests.get(DOMAIN_TYPES.get(domain_type, ''))
            response.raise_for_status()
            return [line.split()[1] for line in response.text.splitlines() if line.startswith('0.0.0.0 ') and len(line.split()[1]) > 5]
        except requests.exceptions.RequestException as e:
            self.context.log.error(f"Error downloading domains: {e}")
            return []

    def _generator(self) -> Iterable[Tuple[int, Tuple[str, str, str, int, str, str]]]:
        domain_type = self.config.get('domain_type', 'malware')
        domains = self._download_domains(domain_type)

        for layer_name in tqdm(self.context.layers, desc="Scanning layers", unit="layer"):
            layer = self.context.layers[layer_name]
            file_path = layer.file_path if hasattr(layer, 'file_path') else 'Unknown'
            scanner = scanners.MultiStringScanner([domain.encode() for domain in domains])
            for offset, match in layer.scan(context=self.context, scanner=scanner):
                domain = next(domain for domain in domains if domain.encode() == match)
                start = max(0, offset - 32)
                end = min(layer.maximum_address, offset + len(match) + 32)
                try:
                    context = layer.read(start, end - start)
                    printable = set(string.printable)
                    context = ''.join(filter(lambda x: x in printable, context.decode('utf-8', errors='ignore')))
                    yield (0, (os.path.basename(file_path), os.path.dirname(file_path), layer_name, offset, domain, context))
                except (TypeError, ValueError, UnicodeDecodeError):
                    pass

    def run(self) -> interfaces.renderers.TreeGrid:
        results = list(self._generator())
        return renderers.TreeGrid([("File", str), ("Directory", str), ("Layer", str), ("Offset", int), ("Domain", str), ("Context", str) ], results)
