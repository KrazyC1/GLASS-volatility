import os
import string
import requests
from tqdm import tqdm
import time

from typing import Iterable, Tuple, List
from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import scanners
from volatility3.plugins.windows import pslist
from volatility3.framework.objects import utility
from volatility3.framework import exceptions
from volatility3.framework.interfaces import configuration
#langaugeID imports
from langdetect import detect_langs
from langdetect.lang_detect_exception import LangDetectException


DOMAIN_TYPES = {
    'malware': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
    'fakenews': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-only/hosts',
    'gambling': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling-only/hosts',
    'porn': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts',
    'social': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/social-only/hosts'
}

class domain(interfaces.plugins.PluginInterface):  # to run this do GLASS.domain --type
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(name='kernel', description='Windows kernel'),
            requirements.PluginRequirement(name='pslist', plugin=pslist.PsList, version=(2, 0, 0)),
            requirements.StringRequirement(name='type', description='Type of domains to search for: "porn", "malware", "social", "gambling", "fakenews"', default='malware', optional=False),
            requirements.IntRequirement(name='context', description='Length of context to display around the domain', default=32, optional=True),
        ]

    def _download_domains(self, domain_type: str) -> List[str]:
        try:
            response = requests.get(DOMAIN_TYPES.get(domain_type, ''))
            response.raise_for_status()
            return [line.split()[1] for line in response.text.splitlines() if line.startswith('0.0.0.0 ') and len(line.split()[1]) > 5 and line.split()[1] != '0.0.0.0']
        except requests.exceptions.RequestException as e:
            self.context.log.error(f"Error downloading domains: {e}")
            return []

    def _generator(self) -> Iterable[Tuple[int, Tuple[str, str, str, int, str, str]]]:
        domain_type = self.config.get('domain_type', 'malware')
        context_length = self.config.get('context', 32)
        domains = self._download_domains(domain_type)

        for layer_name in tqdm(self.context.layers, desc="Scanning layers", unit="layer"):
            layer = self.context.layers[layer_name]
            file_path = layer.file_path if hasattr(layer, 'file_path') else 'Unknown'
            scanner = scanners.MultiStringScanner([domain.encode() for domain in domains])

            for offset, match in layer.scan(context=self.context, scanner=scanner):
                domain = next(domain for domain in domains if domain.encode() == match)
                start = max(0, offset - context_length)
                end = min(layer.maximum_address, offset + len(match) + context_length)

                try:
                    context = layer.read(start, end - start)
                    printable = set(string.printable)
                    context = ''.join(filter(lambda x: x in printable, context.decode('utf-8', errors='ignore')))
                    context += '\n\n--------------------------------------------------------\n'  # Add a newline character
                    yield (0, (os.path.basename(file_path), os.path.dirname(file_path), layer_name, offset, domain, context))
                except (TypeError, ValueError, UnicodeDecodeError):
                    pass

    def run(self) -> interfaces.renderers.TreeGrid:
        # ASCII art
        ascii_art = """

   ________    ___   __________
  / ____/ /   /   | / ___/ ___/
 / / __/ /   / /| | \__ \\__ \ 
/ /_/ / /___/ ___ |___/ /__/ / 
\____/_____/_/  |_/____/____/  
                                                                                                     
        """
        # Print ASCII art line by line with 1 second delay
        for line in ascii_art.split('\n'):
            print(line)
            time.sleep(.15)

        results = list(self._generator())
        return renderers.TreeGrid([("File", str), ("Directory", str), ("Layer", str), ("Offset", int), ("Domain", str), ("Context", str)], results)


#new plugin class
class DllList(interfaces.plugins.PluginInterface):
     # This plugin basically lists all the dlls that may be loaded in the processes
     # Hopefully this helps you with figuring out how to do PID stuff
     # to run this plugin run the following command - vol.exe -f lab3.raw -p . GLASS.DllList

    _version = (1, 0, 0)
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(name='kernel', description='Windows kernel'),
            requirements.ListRequirement(name='pid', element_type=int, description='Process IDs to include (all other processes are excluded)', optional=True),
            requirements.PluginRequirement(name='pslist', plugin=pslist.PsList, version=(2, 0, 0))
        ]

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get('pid', None))
        kernel = self.context.modules[self.config['kernel']]

        return renderers.TreeGrid([("PID", int),
                                   ("Process", str),
                                   ("Base", renderers.format_hints.Hex),
                                   ("Size", renderers.format_hints.Hex),
                                   ("Name", str),
                                   ("Path", str)],
                                  self._generator(pslist.PsList.list_processes(self.context,
                                                                               kernel.layer_name,
                                                                               kernel.symbol_table_name,
                                                                               filter_func=filter_func)))

    def _generator(self, procs):
        for proc in procs:
            for entry in proc.load_order_modules():
                BaseDllName = FullDllName = renderers.UnreadableValue()
                try:
                    BaseDllName = entry.BaseDllName.get_string()
                    FullDllName = entry.FullDllName.get_string()
                except exceptions.InvalidAddressException:
                    pass

                yield (0, (proc.UniqueProcessId,
                           proc.ImageFileName.cast("string", max_length=proc.ImageFileName.vol.count, errors='replace'),
                           renderers.format_hints.Hex(entry.DllBase),
                           renderers.format_hints.Hex(entry.SizeOfImage),
                           BaseDllName, FullDllName))
    
    
#getPID
class findPID(interfaces.plugins.PluginInterface):
    #this class deteremines if a given pid is found inside a memory dump or not
    
    _version = (1, 0, 0)
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(name='kernel', description='Windows kernel'),
            requirements.ListRequirement(name='pid', element_type=int, description='Process IDs to include (all other processes are excluded)', optional=False),
            requirements.PluginRequirement(name='pslist', plugin=pslist.PsList, version=(2, 0, 0))
        ]
    
    def run(self) -> interfaces.renderers.TreeGrid:
        
        #convet to int?
        config = dict(self.config)
        pid_to_find = config.get('pid', None)
        pid_to_find = int(pid_to_find[0])
        
        found_status = self._generator(pid_to_find)
        #print(found_status)
        
        return renderers.TreeGrid([("PID", int),("Status", str)], self._generator(pid_to_find))


    def _generator(self, pid_to_find: int) -> Iterable[Tuple[int, Tuple[str, str]]]:
        
        kernel = self.context.modules[self.config['kernel']]
        processes = pslist.PsList.list_processes(self.context, kernel.layer_name, kernel.symbol_table_name)
        
        # Iterate through processes to check if pid_to_find is present
        rows = []
        for proc in processes:
            if proc.UniqueProcessId == pid_to_find:
                rows.append((pid_to_find, (pid_to_find, "Found")))  
                break
        else:
            rows.append((pid_to_find, (pid_to_find, "Not Found")))  
        
        yield from rows


class langID(interfaces.plugins.PluginInterface):
    #Custom GLASS LANGID plugin with language identification functionality.

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(name='kernel', description='Windows kernel'),
            requirements.ListRequirement(name='pid', description='Process ID', optional=False),
            requirements.BooleanRequirement(name='langID', description='Language identification', default=False),
            requirements.PluginRequirement(name='pslist', plugin=pslist.PsList, version=(2, 0, 0)),
            requirements.StringRequirement(name='text_file', description='Path to text file', optional=False, default='ALL.txt')
        ]

    
    def _get_strings_from_text_file(self, text_file: str, encoding: str = 'utf-16') -> Iterable[str]:
        with open(text_file, 'r', encoding=encoding, errors='replace') as file:
            for line in file:
                yield line.strip()

    def run(self) -> interfaces.renderers.TreeGrid:
        """Run the plugin and return language distribution if langID is requested."""
        
        #gets pid input (makes sure its an INT value)
        config = dict(self.config)
        pid = config.get('pid', None)
        pid = int(pid[0])
        lang_id_requested = config['langID']
        #maybe different text files later?
        text_file = os.path.join(os.path.dirname(__file__), config['text_file'])  # Use relative path
        #text_file = os.path.join(os.path.dirname(__file__), 'languages', 'ALL.txt') #gets ALL.txt from languages folder.
        
        if lang_id_requested:
            return renderers.TreeGrid([("PID", int), ("Language Distribution", str)], self._generator(pid, text_file))
        
    
    
    def _generator(self, pid: int, text_file: str) -> Iterable[Tuple[int, Tuple[int, str]]]:
        """Generator method to yield language distributions."""
        
        strings_to_check = set(self._get_strings_from_text_file(text_file, encoding='utf-16'))
        process_text = " ".join(strings_to_check)  # Concatenate strings for langDetect
        
        kernel = self.context.modules[self.config['kernel']]
        processes = pslist.PsList.list_processes(self.context, kernel.layer_name, kernel.symbol_table_name)
        
        rows = []
        for proc in processes:
            if proc.UniqueProcessId == pid:
                if process_text == "":
                    rows.append((pid, (pid, "Error, No strings found")))
                    break
                else:
                    lang_results = detect_langs(process_text)
                    language_distribution = {lang.lang: lang.prob for lang in lang_results}
                    language_distribution_str = ", ".join([f"{lang}: {prob*100:.2f}%" for lang, prob in language_distribution.items()])
                    rows.append((pid, (pid, language_distribution_str))) 
                    break
        else:
            rows.append((pid, (pid, "Error: PID Not Found")))  
        
        yield from rows

                
            #How to RUN
    #-------------------------------------------------------------------------------------------#
    #Step 1 = vol.exe -f "/path/to/memory/image" windows.memmap.Memmap --pid 4404 --dump
    #   This step dumps a given PID to a .dmp file.
        
    #Step 2 = powershell -> .\strings.exe 4404.dmp > sampleText.txt.abs
    #   This step extracts strings from .dmp file and extracts to .txt file. (inside the same directory)
        
    #Step 3 = vol.exe -f "/path/to/memory/image" -p . plugin.LangID --pid 4404 --langID --text-file sampleText.txt  
    #   This step analyzes the .txt file and provides language analysis.


    #Notes:
    #Still working on automatization of the process but this works right now. It could be improved in the future.
    #Encountered difficulty reading strings from process memory in PID, so we had to dump it to extract it.
    #-------------------------------------------------------------------------------------------#     
        


#TEST
"""
class LangID(interfaces.plugins.PluginInterface):
    #Custom GLASS LANGID plugin with language identification functionality.

    _required_framework_version = (2, 0, 0)

 
    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(name='kernel', description='Windows kernel'),
            requirements.ListRequirement(name='pid', description='Process ID', optional=False),
            requirements.BooleanRequirement(name='langID', description='Language identification', default=False),
            requirements.PluginRequirement(name='pslist', plugin=pslist.PsList, version=(2, 0, 0))
        ]


    def run(self) -> interfaces.renderers.TreeGrid:
        #Run the plugin and return language distribution if langID is requested.
        
        #gets pid input (makes sure its an INT value)
        config = dict(self.config)
        pid = config.get('pid', None)
        pid = int(pid[0])
        lang_id_requested = config['langID']
            
        if lang_id_requested:
            return renderers.TreeGrid([("PID", int), ("Language Distribution", str)], self._generator(pid))
        
        #GO DOWN CREATION OF EXTERNAL FILE PATH
    def get_process_text_from_memory(self, pid):
        # Constants for desired access rights
        PROCESS_QUERY_INFORMATION = 0x0400
        PROCESS_VM_READ = 0x0010

        try:
            # Open process handle using NtOpenProcess API from ntdll
            ntdll = ctypes.WinDLL('ntdll')
            handle = ctypes.c_void_p()
            status = ntdll.NtOpenProcess(ctypes.byref(handle), PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, None, ctypes.c_uint(pid))
            if status != 0:
                return f"Error opening process handle for PID {pid}. Error code: {status}"

            # Read process memory into buffer
            bytes_read = ctypes.c_size_t()
            buffer_size = 4096  # Adjust buffer size as needed
            buffer = ctypes.create_string_buffer(buffer_size)
            if ctypes.windll.kernel32.ReadProcessMemory(handle, 0, buffer, buffer_size, ctypes.byref(bytes_read)):
                # Decode the buffer to retrieve process text
                process_text = buffer.raw.decode('utf-8', errors='ignore')
            else:
                process_text = f"Error reading process memory for PID {pid}"
        except Exception as e:
            process_text = f"Error: {str(e)}"
        finally:
            if handle:
                ctypes.windll.kernel32.CloseHandle(handle)
        return process_text

    
    
    def _generator(self, pid: int) -> Iterable[Tuple[int, Tuple[int, str]]]:
        #Generator method to yield language distributions.
        
        process_text = self.get_process_text_from_memory(pid)
        print(process_text)
        lang_results = detect_langs(process_text)
        language_distribution = {lang.lang: lang.prob for lang in lang_results}
        
        #Format the language distribution as a string
        distribution_str = ", ".join([f"{lang}: {prob*100:.2f}%" for lang, prob in language_distribution.items()])
        
        kernel = self.context.modules[self.config['kernel']]
        processes = pslist.PsList.list_processes(self.context, kernel.layer_name, kernel.symbol_table_name)
        
        rows = []
        for proc in processes:
            if proc.UniqueProcessId == pid:
                rows.append((pid, (pid, distribution_str)))  
                break
        else:
            rows.append((pid, (pid, "Error: PID Not Found")))  
        
        yield from rows
        """
        
    