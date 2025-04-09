using System.Runtime.InteropServices;
using System.Diagnostics;
using System.IO;

namespace MemoryInjectorLib
{
    public class MemoryInjector
    {
        #region Windows API Imports
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, uint processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize,
            uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize,
            uint dwFreeType);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
            byte[] lpBuffer, int nSize, out int lpNumberOfBytesWritten);
        #endregion

        #region Constants
        private const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_RESERVE = 0x2000;
        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        private const uint MEM_RELEASE = 0x8000;
        private const uint PAGE_SIZE = 0x1000;
        private const string INJECTION_INFO_FILE = "injection_info.dat";
        #endregion

        #region Fields
        private Process _process;
        private bool _isInjected;
        private string _processName;
        private IntPtr _hProcess;
        private IntPtr _newmemAddress;
        private IntPtr _injectAddress;
        private IntPtr _matchtimeAddress;
        private IntPtr _jumpAddress;
        private IntPtr _endInjectAddress;
        private byte[] _oriData;
        private byte[] _newmemData;
        private byte[] _injectData;
        #endregion

        #region Properties
        public bool IsInjected => _isInjected;
        public string ProcessName => _processName;
        #endregion

        #region Constructor
        public MemoryInjector(string processName = "FL_2023.exe")
        {
            _processName = processName;
            _isInjected = false;
            _oriData = new byte[] { 
                0x8B, 0x44, 0x24, 0x40,    // mov eax, [esp+40h]
                0x89, 0x44, 0x24, 0x40     // mov [esp+40h], eax
            };
            _newmemData = new byte[] { 
                0x83, 0xF8, 0x00,          // cmp eax, 0
                0x0F, 0x84, 0x04, 0x00, 0x00, 0x00,  // je short
                0x89, 0x44, 0x24, 0x40,    // mov [esp+40h], eax
                0x8B, 0x44, 0x24, 0x40,    // mov eax, [esp+40h]
                0x89, 0x44, 0x24, 0x40     // mov [esp+40h], eax
            };
            _injectData = new byte[] { 0x90, 0x90, 0x90 }; // NOP instructions

            // Try to restore injection state
            LoadInjectionState();
        }
        #endregion

        #region Public Methods
        public bool UnInject()
        {
            try
            {
                _process = Process.GetProcessesByName(_processName.Split('.')[0])[0];
                _hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, (uint)_process.Id);

                // Restore original memory content
                bool success = WriteProcessMemory(_hProcess, _injectAddress, _oriData, _oriData.Length, out _);

                // Free allocated memory
                if (_newmemAddress != IntPtr.Zero)
                {
                    success &= VirtualFreeEx(_hProcess, _newmemAddress, 0, MEM_RELEASE);
                    _newmemAddress = IntPtr.Zero;
                }

                _isInjected = false;
                
                // Clear the injection state file
                ClearInjectionState();

                return success;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"UnInject failed: {ex.Message}");
                _isInjected = false;
                return false;
            }
            finally
            {
                if (_hProcess != IntPtr.Zero)
                {
                    CloseHandle(_hProcess);
                    _hProcess = IntPtr.Zero;
                }
            }
        }

        public bool Inject()
        {
            try
            {
                // Step 1: Get target process
                try
                {
                    _process = Process.GetProcessesByName(_processName.Split('.')[0])[0];
                }
                catch (IndexOutOfRangeException)
                {
                    Console.WriteLine($"Error: Process '{_processName}' not found!");
                    return false;
                }

                // Step 2: Get base address
                var baseAddresses = GetBaseAddress();
                if (baseAddresses == null)
                {
                    Console.WriteLine("Error: Failed to get process base address!");
                    return false;
                }

                long startAddress = baseAddresses.Item1.ToInt64();
                long endAddress = baseAddresses.Item2.ToInt64();
                byte[] injectPattern = _oriData;

                // Step 3: Open process and find injection point
                _hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, (uint)_process.Id);
                if (_hProcess == IntPtr.Zero)
                {
                    Console.WriteLine("Error: Failed to open process! Access denied?");
                    return false;
                }

                _injectAddress = FindMatchedAddress(injectPattern, startAddress, endAddress);
                if (_injectAddress == IntPtr.Zero)
                {
                    Console.WriteLine("Error: Failed to find injection point!");
                    return false;
                }

                // Step 4: Allocate new memory
                var allocationResult = AllocateNewMemory();
                if (allocationResult == null)
                {
                    Console.WriteLine("Error: Failed to allocate memory!");
                    return false;
                }

                _hProcess = allocationResult.Item1;
                _newmemAddress = allocationResult.Item2;
                _jumpAddress = (IntPtr)(_injectAddress.ToInt64() + 0x8);
                _matchtimeAddress = (IntPtr)(_newmemAddress.ToInt64() + 0x100);
                _endInjectAddress = (IntPtr)(_newmemAddress.ToInt64() + 0x1B);

                // Step 5: Prepare injection data
                try
                {
                    _newmemData = MovEaxMemoryBytes(_newmemAddress.ToInt64(), _matchtimeAddress.ToInt64())
                        .Concat(_newmemData)
                        .Concat(CalculateJmpBytes(_endInjectAddress.ToInt64(), _jumpAddress.ToInt64()))
                        .ToArray();
                    _injectData = CalculateJmpBytes(_injectAddress.ToInt64(), _newmemAddress.ToInt64())
                        .Concat(_injectData)
                        .ToArray();
                }
                catch (ArgumentException ex)
                {
                    Console.WriteLine($"Error: Failed to calculate jump offsets: {ex.Message}");
                    return false;
                }

                // Step 6: Perform injection
                if (!PerformInjection())
                {
                    Console.WriteLine("Error: Failed to write memory!");
                    return false;
                }

                // Save the injection state
                SaveInjectionState();

                Console.WriteLine("Injection completed successfully!");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: Unexpected error during injection: {ex.Message}");
                return false;
            }
            finally
            {
                if (_hProcess != IntPtr.Zero)
                    CloseHandle(_hProcess);
            }
        }

        public bool SetValue(float value)
        {
            if (!_isInjected) return false;

            try
            {
                _process = Process.GetProcessesByName(_processName.Split('.')[0])[0];
                _hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, (uint)_process.Id);
                byte[] buffer = BitConverter.GetBytes(value);
                bool success = WriteProcessMemory(_hProcess, _matchtimeAddress, buffer, buffer.Length, out _);
                CloseHandle(_hProcess);
                return success;
            }
            catch (Exception)
            {
                _isInjected = false;
                return false;
            }
        }

        public bool FreeMemory()
        {
            if (_hProcess == IntPtr.Zero || _newmemAddress == IntPtr.Zero) return false;
            return VirtualFreeEx(_hProcess, _newmemAddress, 0, MEM_RELEASE);
        }
        #endregion

        #region Private Methods
        private Tuple<IntPtr, IntPtr> AllocateNewMemory()
        {
            ulong baseAddress = 0x13FF10000UL;
            ulong endAddress = 0x16FFFFFFFUL;

            if (_process == null || _process.HasExited) return null;

            uint pid = (uint)_process.Id;
            _hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
            if (_hProcess == IntPtr.Zero) return null;

            ulong currentAddress = baseAddress;
            while (currentAddress < endAddress)
            {
                IntPtr allocatedAddress = VirtualAllocEx(_hProcess, (IntPtr)currentAddress, PAGE_SIZE,
                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

                if (allocatedAddress != IntPtr.Zero)
                {
                    return Tuple.Create(_hProcess, allocatedAddress);
                }
                currentAddress += PAGE_SIZE;
            }
            return null;
        }
        private IntPtr FindMatchedAddress(byte[] pattern, long startAddress, long endAddress)
        {
            int scanSize = 0x1000;
            byte[] buffer = new byte[scanSize];

            for (long addr = startAddress; addr < endAddress; addr += scanSize)
            {
                if (ReadProcessMemory(_hProcess, (IntPtr)addr, buffer, scanSize, out int bytesRead))
                {
                    for (int i = 0; i < bytesRead - pattern.Length + 1; i++)
                    {
                        if (buffer.Skip(i).Take(pattern.Length).SequenceEqual(pattern))
                        {
                            return (IntPtr)(addr + i);
                        }
                    }
                }
            }
            return IntPtr.Zero;
        }

        private byte[] MovEaxMemoryBytes(long instructionAddress, long targetAddress)
        {
            byte opcode = 0x8B;
            byte modrm = 0x05;
            int instructionLength = 6;
            int displacement = (int)(targetAddress - (instructionAddress + instructionLength));
            return new byte[] { opcode, modrm }.Concat(BitConverter.GetBytes(displacement)).ToArray();
        }

        private byte[] CalculateJmpBytes(long opcodeAddr, long targetAddr)
        {
            int instructionLength = 5;
            long rip = opcodeAddr + instructionLength;
            int offset = (int)(targetAddr - rip);

            if (offset > 0x7FFFFFFF || offset < -0x80000000)
                throw new ArgumentException($"Offset {offset:X} exceeds 32-bit signed range");

            return new byte[] { 0xE9 }.Concat(BitConverter.GetBytes(offset)).ToArray();
        }

        private bool PerformInjection()
        {
            try
            {
                if (!WriteProcessMemory(_hProcess, _newmemAddress, _newmemData, _newmemData.Length, out _))
                {
                    Console.WriteLine("Error: Failed to write new memory data!");
                    return false;
                }

                float zero = 0.0f;
                if (!WriteProcessMemory(_hProcess, _matchtimeAddress, BitConverter.GetBytes(zero), sizeof(float), out _))
                {
                    Console.WriteLine("Error: Failed to write initial value!");
                    return false;
                }

                System.Threading.Thread.Sleep(1000);

                if (!WriteProcessMemory(_hProcess, _injectAddress, _injectData, _injectData.Length, out _))
                {
                    Console.WriteLine("Error: Failed to write injection data!");
                    return false;
                }

                _isInjected = true;
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error during memory writing: {ex.Message}");
                return false;
            }
        }

        private Tuple<IntPtr, IntPtr> GetBaseAddress()
        {
            try
            {
                IntPtr baseAddress = _process.MainModule.BaseAddress;
                IntPtr endAddress = IntPtr.Add(baseAddress, _process.MainModule.ModuleMemorySize);
                return Tuple.Create(baseAddress, endAddress);
            }
            catch (Exception)
            {
                return null;
            }
        }

        private void SaveInjectionState()
        {
            try
            {
                using (var writer = new BinaryWriter(File.Open(INJECTION_INFO_FILE, FileMode.Create)))
                {
                    writer.Write(_isInjected);
                    writer.Write(_injectAddress.ToInt64());
                    writer.Write(_newmemAddress.ToInt64());
                    writer.Write(_matchtimeAddress.ToInt64());
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to save injection state: {ex.Message}");
            }
        }

        private void LoadInjectionState()
        {
            try
            {
                if (File.Exists(INJECTION_INFO_FILE))
                {
                    using (var reader = new BinaryReader(File.Open(INJECTION_INFO_FILE, FileMode.Open)))
                    {
                        _isInjected = reader.ReadBoolean();
                        _injectAddress = new IntPtr(reader.ReadInt64());
                        _newmemAddress = new IntPtr(reader.ReadInt64());
                        _matchtimeAddress = new IntPtr(reader.ReadInt64());
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to load injection state: {ex.Message}");
                _isInjected = false;
                _injectAddress = IntPtr.Zero;
                _newmemAddress = IntPtr.Zero;
                _matchtimeAddress = IntPtr.Zero;
            }
        }

        private void ClearInjectionState()
        {
            try
            {
                if (File.Exists(INJECTION_INFO_FILE))
                {
                    File.Delete(INJECTION_INFO_FILE);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to clear injection state: {ex.Message}");
            }
        }
        #endregion
    }
}
