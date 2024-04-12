import os
import string
import psutil
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
     # This plugin basically lists all the dlls that may be loaded in the processes
     # Hopefully this helps you with figuring out how to do PID stuff
     # to run this plugin run the following command - vol.exe -f lab3.raw -p . example.DllList

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


class LangIDTEXT(interfaces.plugins.PluginInterface):
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
        #print(text_file) #able to get the strings
        
        if lang_id_requested:
            return renderers.TreeGrid([("PID", int), ("Language Distribution", str)], self._generator(pid, text_file))
        
    
    
    def _generator(self, pid: int, text_file: str) -> Iterable[Tuple[int, Tuple[int, str]]]:
        """Generator method to yield language distributions."""
        
        #strings_to_check = set(self._get_strings_from_text_file(text_file))  # Convert to set for faster lookup
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
        #vol.exe -f "C:\Users\jmbau\OneDrive - Grand Valley State University\Junior Year\Semester 2\Computer and Cyber Forensics\lab3\memdump.mem" windows.memmap.Memmap --pid 4404 --dump
        #powershell -> .\strings.exe 4404.dmp > sampleText.txt
        #vol.exe -f "C:\Users\jmbau\OneDrive - Grand Valley State University\Junior Year\Semester 2\Computer and Cyber Forensics\lab3\memdump.mem" -p . plugin.LangIDTEXT --pid 4404 --langID --text-file sampleText.txt  
        


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
        
    