
#How to RUN
#-------------------------------------------------------------------------------------------#
#Step 1 = vol.exe -f "/path/to/memory/image" windows.memmap.Memmap --pid 4404 --dump
#   This step dumps a given PID to a .dmp file.
    
#Step 2 = powershell -> .\strings.exe 4404.dmp > sampleText.txt.abs
#   This step extracts strings from .dmp file and extracts to .txt file. (inside the same directory)
    
#Step 3 = vol.exe -f "/path/to/memory/image" -p . plugin.LangIDTEXT --pid 4404 --langID --text-file sampleText.txt  
#   This step analyzes the .txt file and provides language analysis.


#Notes:
#Still working on automatization of the process but this works right now. It could be improved in the future.
#Encountered difficulty reading strings from process memory in PID, so we had to dump it to extract it.
#-------------------------------------------------------------------------------------------#   

import os
import string
from typing import Iterable, Tuple, List
from volatility3.framework import interfaces, constants, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import scanners
from volatility3.plugins.windows import pslist
from volatility3.framework.objects import utility
from volatility3.framework import exceptions
from volatility3.framework.interfaces import configuration
#langaugeID imports
from langdetect import detect_langs
from langdetect.lang_detect_exception import LangDetectException


class languageID(interfaces.plugins.PluginInterface):
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