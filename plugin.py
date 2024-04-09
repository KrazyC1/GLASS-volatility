
"""
from typing import Iterable, Tuple, List
from volatility3.framework import interfaces, constants, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import scanners
from volatility3.plugins.windows import pslist

#langaugeID imports
from langdetect import detect_langs #pip install langdetect ---- for some reason BankScanner does not work when this command is not done and langdetect is imported.
from langdetect.lang_detect_exception import LangDetectException  # Import LangDetectException
from volatility3.framework import interfaces, constants
from volatility3.framework.layers import scanners
from typing import List
#?
from typing import Dict




#import argparse
import psutil #pip install psutil
import ctypes
import string
import os
"""

import os
import psutil
import string
import ctypes
from typing import Iterable, Tuple, List
from volatility3.framework import interfaces, constants, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import scanners#, registry
from volatility3.plugins.windows import pslist

from volatility3.framework.objects import utility
from volatility3.framework import exceptions
from volatility3.framework.interfaces import configuration
from volatility3.framework.renderers import format_hints
#langaugeID imports
from langdetect import detect_langs
from langdetect.lang_detect_exception import LangDetectException


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
        

#new plugin class

class DllList(interfaces.plugins.PluginInterface):
    
    _required_framework_version = (2, 0, 0)
    
    #check requirements....
    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(name = 'kernel', description = 'Windows kernel'),
            requirements.PluginRequirement(name='pslist', plugin=pslist.PsList, version=(2, 0, 0)),
            requirements.ListRequirement(name = 'pid', element_type = int, description = "Process IDs to include (all other processes are excluded)",optional = True),
        ]
    print("after requirements")
        
    
    def _generator(self, procs):
        for proc in procs:
            for entry in proc.load_order_modules():
                BaseDllName = FullDllName = renderers.UnreadableValue()
                try:
                    BaseDllName = entry.BaseDllName.get_string()
                    # we assume that if the BaseDllName points to an invalid buffer, so will FullDllName
                    FullDllName = entry.FullDllName.get_string()
                except exceptions.InvalidAddressException:
                    pass
                
                yield (0, (proc.UniqueProcessId,
                           proc.ImageFileName.cast("String", max_length = proc.ImageFileName.vol.count,
                                                   errors = 'replace'),
                           format_hints.Hex(entry.DllBase), format_hints.Hex(entry.SizeOfImage),
                           BaseDllName, FullDllName))             
    
    print("after generator")
    
    
    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get('pid', None))
        kernel = self.context.modules[self.config['kernel']]
        
        
        return renderers.TreeGrid([
            ("PID", int),
            ("Process", str),
            ("Base", format_hints.Hex),
            ("Size", format_hints.Hex),
            ("Name", str),
            ("Path", str)],
            self._generator(pslist.PsList.list_processes(self.context, kernel.layer_name, kernel.symbol_table_name, filter_func = filter_func)))


"""
class LangID(interfaces.plugins.PluginInterface):
    #Custom GLASS LANGID plugin with language identification functionality.

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ListRequirement(name='pid', description='Process ID', optional=False),
            requirements.BooleanRequirement(name='langID', description='Language identification', default=False),
        ]

    def get_process_text_from_memory(self, pid: int) -> str:
        #Retrieve process text from memory based on PID.
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
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            process_text = f"Unable to retrieve process text for PID {pid}"
    
        return process_text

    def run(self) -> renderers.TreeGrid:
        #Runs the plugin and returns the language distribution if langID is requested.
        pid = self.config['pid']
        lang_id_requested = self.config['langID']

        # Check if the specified PID exists as a process
        if not any(pid == process.pid for process in psutil.process_iter()):
            return renderers.TreeGrid([("Error, PID not found in processes", str)], [("PID not found in processes",)])

        try:
            process_text = self.get_process_text_from_memory(pid)
        except psutil.NoSuchProcess:
            return renderers.TreeGrid([("Error", str)], [("PID not found in dump",)])

        if lang_id_requested:
            try:
                lang_results = detect_langs(process_text)
                language_distribution = {lang.lang: lang.prob for lang in lang_results}

                if language_distribution:
                    return renderers.TreeGrid(
                        [("Language", str), ("Probability", float)],
                        language_distribution.items()
                    )
                else:
                    return renderers.TreeGrid([("Message", str)], [("No language distribution data",)])
            except LangDetectException as e:
                return renderers.TreeGrid([("Error", str)], [(str(e),)])
        else:
            return renderers.TreeGrid([("Process Text", str)], [(process_text,)])
    """
    
"""
    def run(self) -> renderers.TreeGrid:
        #Runs the plugin and returns the language distribution if langID is requested.
        pid = self.config['pid']
        lang_id_requested = self.config['langID']

        # Check if the specified PID exists as a process
        if not any(pid == process.pid for process in psutil.process_iter()):
            return renderers.TreeGrid([("Error", str)], [("PID not found in processes",)])

        try:
            process_text = self.get_process_text_from_memory(pid)
        except psutil.NoSuchProcess:
            return renderers.TreeGrid([("Error", str)], [("PID not found in dump",)])

        if lang_id_requested:
            try:
                lang_results = detect_langs(process_text)
                language_distribution = {lang.lang: lang.prob for lang in lang_results}

                if language_distribution:
                    return renderers.TreeGrid(
                        [("Language", str), ("Probability", float)],
                        language_distribution.items()
                    )
                else:
                    return renderers.TreeGrid([("Message", str)], [("No language distribution data",)])
            except LangDetectException as e:
                return renderers.TreeGrid([("Error", str)], [(str(e),)])
        else:
            return renderers.TreeGrid([("Process Text", str)], [(process_text,)])
        """


  
"""
class LangID(interfaces.plugins.PluginInterface):
    # Custom GLASS LANGID plugin with language identification functionality.

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.IntRequirement(name='pid', description='Process ID', optional=False),
            requirements.BooleanRequirement(name='langID', description='Language identification', default=False),
        ]

    def get_process_text_from_memory(self, pid: int) -> str:
        # Retrieve process text from memory based on PID.
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

    def convert_language_distribution(self, language_distribution: Dict[str, float]) -> List[Tuple[str, float]]:
        # Convert language distribution dictionary to list of tuples
        return [(lang, prob) for lang, prob in language_distribution.items()]

    def run(self) -> renderers.TreeGrid:
        # Runs the plugin and returns the language distribution.
        pid = self.config.get('pid')
        lang_id_requested = self.config.get('langID', False)

        if pid is None:
            return renderers.TreeGrid([("Message", str)], [("No PID provided",)])
        
        # Placeholder code for retrieving process text from memory (replace with actual logic)
        process_text = self.get_process_text_from_memory(pid)
        
        
        if lang_id_requested:
            try:
                # Perform language identification using langdetect
                lang_results = detect_langs(process_text)  # Use detect_langs directly
                language_distribution = {}
                for lang in lang_results:
                    language_distribution[lang.lang] = lang.prob

                # Convert language distribution to list of tuples
                language_distribution_list = self.convert_language_distribution(language_distribution)

                # Ensure language_distribution_list is not empty before rendering
                if language_distribution_list:
                    return renderers.TreeGrid(
                        [("Language", str), ("Probability", float)],
                        language_distribution_list
                    )
                else:
                    return renderers.TreeGrid([("Message", str)], [("No language distribution data",)])
            except LangDetectException as e:
                return renderers.TreeGrid([("Error", str)], [(str(e),)])
        else:
            # Return process text without language identification
            return renderers.TreeGrid(
                [("Process Text", str)],
                [(process_text,)]
            )
"""
        

     




    


        