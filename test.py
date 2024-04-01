from volatility3.framework import interfaces
from volatility3.framework import renderers
from volatility3.framework import exceptions
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist
from volatility3.framework.interfaces.configuration import requirements

# this basically just lists dlls

class DllList(interfaces.plugins.PluginInterface):
    _version = (1, 0, 0)
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            interfaces.configuration.requirements.ModuleRequirement(
                name='kernel',
                description='Windows kernel',
                architectures=["Intel32", "Intel64"]),
            interfaces.configuration.requirements.ListRequirement(
                name='pid',
                element_type=int,
                description="Process IDs to include (all other processes are excluded)",
                optional=True),
            interfaces.configuration.requirements.PluginRequirement(
                name='pslist',
                plugin=pslist.PsList,
                version=(2, 0, 0))
        ]

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
                           proc.ImageFileName.cast("string", max_length=proc.ImageFileName.vol.count,
                                                   errors='replace'),
                           format_hints.Hex(entry.DllBase), format_hints.Hex(entry.SizeOfImage),
                           BaseDllName, FullDllName))
