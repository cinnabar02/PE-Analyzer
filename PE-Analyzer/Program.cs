using System;
using System.IO;

class Program
{
    static void Main(string[] args)
    {
        if (args.Length == 0)
        {
            Console.WriteLine("Передайте путь к файлу аргументом");
            return;
        }

        string filepath = args[0];

        if (!File.Exists(filepath))
        {
            Console.WriteLine("Файл не найден");
            return;
        }

        using (BinaryReader reader = new BinaryReader(File.Open(filepath, FileMode.Open)))
        {
            // поиск DOS-заголовка, чтение "MZ" (e_magic)

            byte[] mz = reader.ReadBytes(2);

            if (mz[0] != 0x4D || mz[1] != 0x5A)
            {
                Console.WriteLine("DOS-заголовок не найден");
                return;
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
                return;
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
            if ((Characteristics & 0x0002) != 0) Console.WriteLine("0x0002 - File is executable");
            if ((Characteristics & 0x0020) != 0) Console.WriteLine("0x0020 - App can handle >2gb addresses");
            if ((Characteristics & 0x2000) != 0) Console.WriteLine("0x2000 - File is a DLL");
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
        }
    }
}