from typing import Iterable, Tuple, List
from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import scanners
from volatility3.plugins.windows import pslist
import string, os
import requests

def download_domain_list(url, filename):
    """Download the domain list from the given URL and save it to the 'domains' folder."""
    if not os.path.exists('domains'):
        os.makedirs('domains')
    
    response = requests.get(url)
    with open(os.path.join('domains', filename), 'w', encoding='utf-8') as file:
        file.write(response.text)

def parse_domain_lists():
    """Read the domain lists from the 'domains' folder and return a set of unique domains."""
    domains = set()
    for filename in os.listdir('domains'):
        with open(os.path.join('domains', filename), 'r', encoding='utf-8') as file:
            for line in file:
                if line.startswith('0.0.0.0 '):
                    domains.add(line.strip('0.0.0.0 ').strip())
    return domains

class Search(interfaces.plugins.PluginInterface):
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(name='kernel', description='Windows kernel'),
            requirements.PluginRequirement(name='pslist', plugin=pslist.PsList, version=(2, 0, 0)),
            requirements.ChoiceRequirement(
                name='domain_categories',
                description='Domain categories to search for',
                choices=['Unified hosts', 'Fakenews', 'Gambling', 'Porn', 'Social'],
                default=['Unified hosts'],
            ),
        ]

    def _generator(self) -> Iterable[Tuple[int, Tuple[str, str, str, int, str, str]]]:
        rows = []
        selected_categories = self.config['domain_categories']
        domain_lists = {
            'Unified hosts': 'unified_hosts.txt',
            'Fakenews': 'fakenews.txt',
            'Gambling': 'gambling.txt',
            'Porn': 'porn.txt',
            'Social': 'social.txt',
        }

        for category, filename in domain_lists.items():
            if category in selected_categories:
                url = {
                    'Unified hosts': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
                    'Fakenews': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-only/hosts',
                    'Gambling': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling-only/hosts',
                    'Porn': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts',
                    'Social': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/social-only/hosts',
                }[category]
                download_domain_list(url, filename)

        domains = parse_domain_lists()

        for layer_name in self.context.layers:
            layer = self.context.layers[layer_name]
            file_path = layer.file_path if hasattr(layer, 'file_path') else 'Unknown'
            for domain in domains:
                scanner = scanners.MultiStringScanner([domain.encode('utf-8')])
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