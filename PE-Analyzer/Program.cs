using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;


struct Section
{
    public uint VirtualAddress;
    public uint VirtualSize;
    public uint PointerToRawData;
}

class Program
{
    static uint RVAToOffset(List<Section> sections, uint RVA)
    {
        foreach (Section s in sections)
        {
            if (RVA >= s.VirtualAddress && RVA < s.VirtualAddress + s.VirtualSize)
            {
                return RVA - s.VirtualAddress + s.PointerToRawData;
            }
        }
        return 0;
    }

    static void Main(string[] args)
    {
        if (args.Length == 0)
        {
            Console.WriteLine("Передайте путь к файлу аргументом");
            Console.WriteLine("\nНажмите любую клавишу для выхода");
            Console.ReadLine();
        }

        string filepath = args[0];

        if (!File.Exists(filepath))
        {
            Console.WriteLine("Файл не найден");
            Console.WriteLine("\nНажмите любую клавишу для выхода");
            Console.ReadLine();
        }

        using (BinaryReader reader = new BinaryReader(File.Open(filepath, FileMode.Open)))
        {
            // поиск DOS-заголовка, чтение "MZ" (e_magic)

            byte[] mz = reader.ReadBytes(2);

            if (mz[0] != 0x4D || mz[1] != 0x5A)
            {
                Console.WriteLine("DOS-заголовок не найден");
                Console.WriteLine("\nНажмите любую клавишу для выхода");
                Console.ReadLine();
            }

            // чтение e_lfanew со смещением к NT-заголовку

            reader.BaseStream.Seek(0x3C, SeekOrigin.Begin);
            int peOffset = reader.ReadInt32();
            reader.BaseStream.Seek(peOffset, SeekOrigin.Begin);

            // чтение сигнатуры NT-заголовка (поле Signature, 4 байта, PE\0\0)

            byte[] pe = reader.ReadBytes(4);
            byte[] pe_correct = { 0x50, 0x45, 0x00, 0x00 };

            if (!pe.SequenceEqual(pe_correct))
            {
                Console.WriteLine("PE-заголовок не найден");
                Console.WriteLine("\nНажмите любую клавишу для выхода");
                Console.ReadLine();
            }

            string Filename = Path.GetFileName(filepath);
            Console.WriteLine("Название анализируемого файла: " + Filename);

            // чтение поля Machine (2 байта)

            ushort machine = reader.ReadUInt16();
            string architecture = "Uknown";

            if (machine == 0x014C) architecture = "32 bit";
            else if (machine == 0x0200) architecture = "Intel x64";
            else if (machine == 0x8664) architecture = "AMD64";

            Console.WriteLine("Архитектура программы: " + architecture);

            // чтение поля NumberOfSections (2 байта)

            ushort NumberOfSections = reader.ReadUInt16();

            reader.BaseStream.Seek(12, SeekOrigin.Current);

            // чтение поля SizeOfOptionalHeader (2 байта)

            ushort SizeOfOptionalHeader = reader.ReadUInt16();

            // чтение поля Characteristics (2 байта)

            ushort Characteristics = reader.ReadUInt16();

            Console.WriteLine("\nХарактеристики:");
            if ((Characteristics & 0x0002) != 0) Console.WriteLine("0x0002 - Файл образа действителен и может быть запущен");
            if ((Characteristics & 0x0020) != 0) Console.WriteLine("0x0020 - Приложение может обрабатывать > 2 ГБ-адресов");
            if ((Characteristics & 0x2000) != 0) Console.WriteLine("0x2000 - Библиотека динамической компоновки (DLL)");
            Console.WriteLine("\n");

            // чтение поля Magic структуры IMAGE_OPTIONAL_HEADER

            ushort Magic = reader.ReadUInt16();

            if (Magic == 0x010B)
            {
                Console.WriteLine($"Файл является 32-разрядным - поле Magic: 0x{Magic:X4}");
            }
            else
            {
                Console.WriteLine($"Файл является 64-разрядным - поле Magic: 0x{Magic:X4}");
            }

            reader.BaseStream.Seek(14, SeekOrigin.Current);

            // чтение поля AddressOfEntryPoint (4 байта)

            uint AddressOfEntryPoint = reader.ReadUInt32();

            Console.WriteLine($"Адрес точки входа в программу: 0x{AddressOfEntryPoint:X8}");

            // чтение поля ImageBase

            reader.BaseStream.Seek(4, SeekOrigin.Current);

            if (Magic == 0x010B)
            {
                reader.BaseStream.Seek(4, SeekOrigin.Current);
                uint ImageBase = reader.ReadUInt32();
                Console.WriteLine($"Адрес загрузки образа по умолчанию: 0x{ImageBase:X8}");
            }
            else
            {
                ulong ImageBase = reader.ReadUInt64();
                Console.WriteLine($"Адрес загрузки образа по умолчанию: 0x{ImageBase:X16}");
            }

            // чтение поля SectionAlignment и FileAlignment

            uint SectionAlignment = reader.ReadUInt32();
            uint FileAlignment = reader.ReadUInt32();
            Console.WriteLine($"Виртуальное выравнивание: 0x{SectionAlignment:X8}");
            Console.WriteLine($"Физическое выравнивание: 0x{FileAlignment:X8}");

            // чтение SizeOfImage

            reader.BaseStream.Seek(16, SeekOrigin.Current);

            uint SizeOfImage = reader.ReadUInt32();

            Console.WriteLine($"Размер образа PE-файла в памяти: {SizeOfImage} байт");

            // чтение DllCharacteristic

            reader.BaseStream.Seek(10, SeekOrigin.Current);

            ushort DllCharacteristic = reader.ReadUInt16();

            Console.WriteLine("\nDLL Характеристики:");
            if ((DllCharacteristic & 0x0020) != 0) Console.WriteLine("0x0020 - Может обрабатывать 64-разрядное виртуальное адресное пространство");
            if ((DllCharacteristic & 0x0040) != 0) Console.WriteLine("0x0040 - DLL можно переместить во время загрузки");
            if ((DllCharacteristic & 0x0100) != 0) Console.WriteLine("0x0100 - Совместимо с NX");
            if ((DllCharacteristic & 0x4000) != 0) Console.WriteLine("0x4000 - Поддерживает функцию управления Flow Guard");
            Console.WriteLine("\n");

            // чтение структуры IMAGE_DATA_DIRECTORY

            if (Magic == 0x010B)
            {
                reader.BaseStream.Seek(24, SeekOrigin.Current);
            }
            else
            {
                reader.BaseStream.Seek(40, SeekOrigin.Current);
            }

            uint ExportRVA = reader.ReadUInt32();
            uint ExportSize = reader.ReadUInt32();

            uint ImportRVA = reader.ReadUInt32();
            uint ImportSize = reader.ReadUInt32();

            uint ResourcesRVA = reader.ReadUInt32();
            uint ResourcesSize = reader.ReadUInt32();

            if (ResourcesSize > 0) Console.WriteLine("Файл содержит ресурсы");

            reader.BaseStream.Seek(16, SeekOrigin.Current);

            uint RelocationRVA = reader.ReadUInt32();
            uint RelocationSize = reader.ReadUInt32();

            if (RelocationSize > 0) Console.WriteLine("Файл содержит релокации");

            // чтение структуры IMAGE_SECTION_HEADER

            reader.BaseStream.Seek(80, SeekOrigin.Current);

            Console.WriteLine("\nСекции\n" + $"{"#",-5} {"Имя",-13} {"Вирт. размер",-15} {"Вирт. адрес",-15} {"Физ. размер",-15} {"Физ. смещение",-15} {"Флаги",-15}");

            List<Section> sections = new List<Section>();

            for (int i = 0; i < NumberOfSections; i++)
            {
                byte[] nameBytes = reader.ReadBytes(8);
                string name = System.Text.Encoding.ASCII.GetString(nameBytes).TrimEnd('\0');

                uint VirtualSize = reader.ReadUInt32();
                uint VirtualAddress = reader.ReadUInt32();
                uint SizeOfRawData = reader.ReadUInt32();
                uint PointerToRawData = reader.ReadUInt32();

                reader.BaseStream.Seek(12, SeekOrigin.Current);

                uint SectionCharacteristics = reader.ReadUInt32();

                sections.Add(new Section { VirtualAddress = VirtualAddress, VirtualSize = VirtualSize, PointerToRawData = PointerToRawData, });

                string OutputCharacteristics = "";

                if ((SectionCharacteristics & 0x20000000) != 0) OutputCharacteristics += "E";
                if ((SectionCharacteristics & 0x40000000) != 0) OutputCharacteristics += "R";
                if ((SectionCharacteristics & 0x80000000) != 0) OutputCharacteristics += "W";

                string virtSize = $"{VirtualSize} байт";
                string rawSize = $"{SizeOfRawData} байт";
                string virtAddr = $"0x{VirtualAddress:X8}";
                string rawAddr = $"0x{PointerToRawData:X8}";

                Console.WriteLine($"#{i,-3} {name,-15} {virtSize,-15} {virtAddr,-15} {rawSize,-15} {rawAddr,-15} {OutputCharacteristics}");
            }

            // чтение таблицы импортов

            if (ImportRVA > 0)
            {
                uint ImportOffset = RVAToOffset(sections, ImportRVA);
                reader.BaseStream.Seek(ImportOffset, SeekOrigin.Begin);

                Console.WriteLine("\nИмпорты:");

                while (true)
                {
                    uint OriginalFirstThunk = reader.ReadUInt32();
                    reader.BaseStream.Seek(8, SeekOrigin.Current);
                    uint NameRVA = reader.ReadUInt32();
                    reader.BaseStream.Seek(4, SeekOrigin.Current);

                    if (OriginalFirstThunk == 0) // до иницилизированной нулями
                        break;

                    uint NameOffset = RVAToOffset(sections, NameRVA);

                    long saved = reader.BaseStream.Position;
                    reader.BaseStream.Seek(NameOffset, SeekOrigin.Begin);

                    string dllName = "";
                    byte _char;

                    while ((_char = reader.ReadByte()) != 0)
                        dllName += (char)_char;

                    Console.WriteLine(dllName);

                    reader.BaseStream.Seek(saved, SeekOrigin.Begin);
                }
            }
            else Console.WriteLine("\nТаблица импортов не найдена");

            // чтение таблицы экспортов

            if (ExportRVA > 0)
            {
                uint ExportOffset = RVAToOffset(sections, ExportRVA);
                reader.BaseStream.Seek(ExportOffset, SeekOrigin.Begin);

                Console.WriteLine("\nЭкспорты:");

                reader.BaseStream.Seek(12, SeekOrigin.Current);

                uint nameRva = reader.ReadUInt32();
                reader.BaseStream.Seek(8, SeekOrigin.Current);
                uint numberOfNames = reader.ReadUInt32();

                reader.BaseStream.Seek(4, SeekOrigin.Current);
                uint NamesRVA = reader.ReadUInt32();
                reader.BaseStream.Seek(4, SeekOrigin.Current);

                uint NameOffset = RVAToOffset(sections, nameRva);

                long saved = reader.BaseStream.Position;
                reader.BaseStream.Seek(NameOffset, SeekOrigin.Begin);

                string dllName = "";
                byte _char;

                while ((_char = reader.ReadByte()) != 0)
                    dllName += (char)_char;

                Console.WriteLine("\nDLL: " + dllName);

                // чтение функций dll

                reader.BaseStream.Seek(saved, SeekOrigin.Begin);

                uint namesOffset = RVAToOffset(sections, NamesRVA);
                reader.BaseStream.Seek(namesOffset, SeekOrigin.Begin);

                for (int i = 0; i < numberOfNames; i++)
                {
                    uint FunctionRVA = reader.ReadUInt32();
                    uint FunctionOffset = RVAToOffset(sections, FunctionRVA);

                    long Position = reader.BaseStream.Position;
                    reader.BaseStream.Seek(FunctionOffset, SeekOrigin.Begin);

                    string FunctionName = "";
                    byte c;

                    while ((c = reader.ReadByte()) != 0)
                        FunctionName += (char)c;

                    Console.WriteLine("Function: " + FunctionName);

                    reader.BaseStream.Seek(Position, SeekOrigin.Begin);
                }
            }
            else
            {
                Console.WriteLine("Таблица экспортов не найдена");
            }

            Console.WriteLine("\nНажмите любую клавишу для выхода");
            Console.ReadLine();
        }
    }
}