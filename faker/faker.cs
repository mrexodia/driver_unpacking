using System;
using System.Collections.Generic;
using System.IO;
using System.Globalization;

namespace faker
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Usage: faker libname exports.txt");
                return;
            }
            var def = new List<string>();
            def.Add(string.Format("LIBRARY \"{0}\"", args[0]));
            def.Add("EXPORTS");
            var fake = new List<string>();
            fake.Add("#define FAKE(x) void* x() { return #x; }");
            foreach (var line in File.ReadAllLines(args[1]))
            {
                var split = line.Split(' ');
                var ord = int.Parse(
                    split[0].TrimStart('0'),
                    NumberStyles.HexNumber);
                var name = split[split.Length - 1];
                if (name == "N/A")
                {
                    def.Add(string.Format("noname{0} @{0} NONAME", ord));
                    fake.Add(string.Format("FAKE(noname{0})", ord));
                }
                else
                {
                    def.Add(string.Format("{0}={0}_FAKE @{1}", name, ord));
                    fake.Add(string.Format("FAKE({0}_FAKE)", name));
                }
            }
            def.Add("");
            File.WriteAllLines(args[0] + ".def", def);
            File.WriteAllLines(args[0] + ".cpp", fake);
        }
    }
}
