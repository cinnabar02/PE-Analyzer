using System;
using System.IO;
using System.Reflection.PortableExecutable;

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

            Console.WriteLine("Характеристики:");
            if ((Characteristics & 0x0002) != 0) Console.WriteLine("0x0002 - File is executable");
            if ((Characteristics & 0x0020) != 0) Console.WriteLine("0x0020 - App can handle >2gb addresses");
            if ((Characteristics & 0x2000) != 0) Console.WriteLine("0x2000 - File is a DLL");

        }
    }
}