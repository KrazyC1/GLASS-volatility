from typing import Iterable, Tuple, List
from volatility3.framework import interfaces, constants, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import scanners
from volatility3.plugins.windows import pslist

#langaugeID imports
from langdetect import detect_langs #pip install langdetect ---- for some reason BankScanner does not work when this command is not done and langdetect is imported.
import argparse
import psutil #pip install psutil
import ctypes

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
        
        
        
class GLASS(interfaces.plugins.PluginInterface):
    """Custom GLASS plugin with language identification functionality."""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.IntRequirement(name='pid', description='Process ID', optional=False),
            requirements.BooleanRequirement(name='langID', description='Language identification', default=False),
        ]
        
    def get_process_text_from_memory(self, pid: int) -> str:
        """Retrieve process text from memory based on PID."""
        
        process_text = ""
        try:
            process = psutil.Process(pid)
            process_memory = process.memory_info()
        
            # Read process memory using ctypes
            process_handle = ctypes.windll.kernel32.OpenProcess(0x0010, False, pid)  # 0x0010 = PROCESS_VM_READ
            if process_handle:
                buffer = ctypes.create_string_buffer(process_memory.rss)
                bytes_read = ctypes.c_size_t()
                if ctypes.windll.kernel32.ReadProcessMemory(process_handle, process_memory.addr, buffer, process_memory.rss, ctypes.byref(bytes_read)):
                    process_text = buffer.raw.decode('utf-8', errors='ignore')
                    process_text = process_text[:1000]  # Limit to first 1000 characters for demonstration
                ctypes.windll.kernel32.CloseHandle(process_handle)
        except psutil.NoSuchProcess:
            process_text = f"Process with PID {pid} not found"
        except psutil.AccessDenied:
            process_text = f"Access denied to process with PID {pid}"
    
        return process_text

    def run(self) -> interfaces.renderers.TreeGrid:
        """Runs the plugin and returns the language distribution."""
        
        pid = self.config.get('pid')
        lang_id_requested = self.config.get('langID', False)
        
        if pid is None:
            return renderers.TreeGrid([], [])
        
        # Placeholder code for retrieving process text from memory (replace with actual logic)
        #process_text = "Sample text from process memory"
        
        if lang_id_requested:
            # Perform language identification using langdetect
            lang_results = detect_langs(process_text)
            language_distribution = {lang.lang: lang.prob for lang in lang_results}
            return renderers.TreeGrid(
                [("Language", str), ("Probability", float)],
                [(lang, prob) for lang, prob in language_distribution.items()]
            )
        else:
            # Return process text without language identification
            return renderers.TreeGrid(
                [("Process Text", str)],
                [(process_text,)]
            )



    


        