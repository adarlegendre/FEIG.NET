using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading;
using FeigDotNet;
using FeigDotNet.Configuration;
using FeigDotNet.Connections;
using FeigDotNet.Discovery;
using FeigDotNet.Exceptions;
using FeigDotNet.Readers;

namespace FeigScan
{
    internal static class Program
    {
        private static volatile bool keepRunning = true;

        private static int Main(string[] args)
        {
            Options options = Options.Parse(args);
            if (options.ShowHelp)
            {
                PrintHelp();
                return 0;
            }

            Console.WriteLine("FEIG RFID scanner");
            Console.WriteLine("Read-only inventory. Press Ctrl+C to stop.");
            Console.WriteLine();

            string host = options.Ip;
            int port = options.Port;

            if (string.IsNullOrWhiteSpace(host))
            {
                List<FeigReaderInfo> discovered = DiscoverReaders();
                if (discovered.Count == 0)
                {
                    Console.WriteLine("No FEIG reader found on the network.");
                    Console.WriteLine("Connect the reader to this LAN, or run with --ip <address>");
                    Console.WriteLine("Example: dotnet run --project FeigScan -- --ip 192.168.1.125");
                    return 2;
                }

                FeigReaderInfo selected = discovered[0];
                host = selected.IPAddress;
                if (selected.Port > 0)
                {
                    port = selected.Port;
                }

                if (discovered.Count > 1)
                {
                    Console.WriteLine("Using the first reader. Pass --ip to pick another.");
                    Console.WriteLine();
                }
            }
            else
            {
                Console.WriteLine("Skipping discovery, using --ip {0}:{1}", host, port);
                Console.WriteLine();
            }

            Console.CancelKeyPress += (sender, eventArgs) =>
            {
                eventArgs.Cancel = true;
                keepRunning = false;
            };

            try
            {
                using (FeigReaderTcpConnection connection = new FeigReaderTcpConnection(host, port, timeout: 3000))
                {
                    Console.WriteLine("Connecting to {0}:{1} ...", host, port);
                    LRU1002Reader reader = new LRU1002Reader(connection);
                    Console.WriteLine("Reader connected.");
                    Console.WriteLine("Mode:       {0}", reader.InterfaceMode.ReaderMode);
                    Console.WriteLine("Regulation: {0}", reader.RFInterface.Regulation);
                    Console.WriteLine("EPC Gen2:   {0}", reader.RFInterface.EpcGen2Enabled);
                    Console.WriteLine("Ant1 power: {0:F1} W", reader.RFInterface.Antenna1Power);
                    Console.WriteLine("Ant2 power: {0:F1} W", reader.RFInterface.Antenna2Power);
                    Console.WriteLine("Ant3 power: {0:F1} W", reader.RFInterface.Antenna3Power);
                    Console.WriteLine("Ant4 power: {0:F1} W", reader.RFInterface.Antenna4Power);

                    if (options.SetRegulation != null || options.SetPower > 0)
                    {
                        if (options.SetRegulation != null)
                        {
                            Console.WriteLine(">> Changing regulation to {0}", options.SetRegulation.Value);
                            reader.RFInterface.Regulation = options.SetRegulation.Value;
                        }

                        if (options.SetPower > 0)
                        {
                            Console.WriteLine(">> Setting antenna power to {0:F1} W", options.SetPower);
                            reader.RFInterface.Antenna1Power = options.SetPower;
                            reader.RFInterface.Antenna2Power = options.SetPower;
                            reader.RFInterface.Antenna3Power = options.SetPower;
                            reader.RFInterface.Antenna4Power = options.SetPower;
                        }

                        reader.ApplyConfigurationChanges();
                        Console.WriteLine(">> Configuration applied and RF reset done.");
                    }

                    Console.WriteLine();
                    Console.WriteLine("Listening for tags...");
                    Console.WriteLine();

                    RunInventoryLoop(reader, options);
                }
            }
            catch (FeigException ex)
            {
                Console.WriteLine("Reader is not reachable or did not respond.");
                Console.WriteLine(ex.Message);
                if (ex.InnerException != null)
                {
                    Console.WriteLine(ex.InnerException.Message);
                }

                return 1;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Failed to talk to the reader: {0}", ex.Message);
                return 1;
            }

            Console.WriteLine();
            Console.WriteLine("Stopped.");
            return 0;
        }

        private static List<FeigReaderInfo> DiscoverReaders()
        {
            FeigReaderDiscovery discovery = new FeigReaderDiscovery();
            IList<NetworkInterface> networkInterfaces = discovery.ListNetworkInterfaces();

            Console.WriteLine("Searching {0} network interface(s) for FEIG readers...", networkInterfaces.Count);

            IDictionary<NetworkInterface, List<FeigReaderInfo>> pairs = discovery.FindReaders(networkInterfaces, timeout: 1500);

            List<FeigReaderInfo> readers = pairs
                .SelectMany(pair => pair.Value)
                .GroupBy(info => info.IPAddress)
                .Select(group => group.First())
                .ToList();

            foreach (KeyValuePair<NetworkInterface, List<FeigReaderInfo>> pair in pairs)
            {
                foreach (FeigReaderInfo readerInfo in pair.Value)
                {
                    int port = readerInfo.Port > 0 ? readerInfo.Port : 10001;
                    Console.WriteLine(
                        "  {0}  {1}  {2}:{3}  {4}",
                        pair.Key.Name,
                        readerInfo.Type,
                        readerInfo.IPAddress,
                        port,
                        readerInfo.MacAddress);
                }
            }

            Console.WriteLine();
            return readers;
        }

        private static void RunInventoryLoop(LRU1002Reader reader, Options options)
        {
            FeigReaderAntenna[] antennas = options.Antennas;
            bool useAntennaMask = antennas.Length > 0;
            int emptyPolls = 0;

            while (keepRunning)
            {
                DateTime started = DateTime.Now;
                IList<FeigTag> tags;

                try
                {
                    tags = Scan(reader, useAntennaMask ? antennas : null);
                }
                catch (FeigInventoryException ex)
                {
                    if (useAntennaMask && antennas.Length > 1)
                    {
                        Console.WriteLine("Antenna scan failed ({0}). Falling back to a full inventory.", ex.Message);
                        useAntennaMask = false;
                        Sleep(options.IntervalMs);
                        continue;
                    }

                    Console.Write("\rWaiting for antenna... ({0})   ", ex.Message);
                    Sleep(options.IntervalMs);
                    continue;
                }
                catch (EndOfStreamException)
                {
                    Console.Write("\rReader returned a short response, retrying...   ");
                    Sleep(options.IntervalMs);
                    continue;
                }
                catch (FeigException ex)
                {
                    Console.WriteLine("Lost connection: {0}", ex.Message);
                    break;
                }

                TimeSpan elapsed = DateTime.Now - started;

                if (tags.Count == 0)
                {
                    emptyPolls++;
                    Console.Write("\rNo tags in field  ({0} ms)   scans: {1}   ", (int)elapsed.TotalMilliseconds, emptyPolls);
                }
                else
                {
                    emptyPolls = 0;
                    Console.WriteLine();
                    Console.WriteLine("{0:HH:mm:ss.fff}  {1} tag(s)  ({2} ms)", DateTime.Now, tags.Count, (int)elapsed.TotalMilliseconds);

                    foreach (FeigTag tag in tags)
                    {
                        string serial = ToHex(tag.SerialNumber);
                        if (tag.Antenna != 0 || tag.RSSI != 0)
                        {
                            Console.WriteLine("  ant {0}  {1} dBm  {2}", tag.Antenna, tag.RSSI, serial);
                        }
                        else
                        {
                            Console.WriteLine("  {0}", serial);
                        }
                    }

                    Console.WriteLine();
                }

                Sleep(options.IntervalMs);
            }
        }

        private static IList<FeigTag> Scan(LRU1002Reader reader, FeigReaderAntenna[] antennas)
        {
            if (antennas == null || antennas.Length == 0)
            {
                return reader.Inventory();
            }

            return reader.Inventory(antennas);
        }

        private static void Sleep(int intervalMs)
        {
            int remaining = intervalMs;
            while (keepRunning && remaining > 0)
            {
                int slice = Math.Min(100, remaining);
                Thread.Sleep(slice);
                remaining -= slice;
            }
        }

        private static string ToHex(byte[] data)
        {
            if (data == null || data.Length == 0)
            {
                return "(none)";
            }

            StringBuilder hex = new StringBuilder(data.Length * 2);
            foreach (byte value in data)
            {
                hex.AppendFormat("{0:X2}", value);
            }

            return hex.ToString();
        }

        private static void PrintHelp()
        {
            Console.WriteLine("FeigScan — discover a FEIG LRU reader and inventory tags.");
            Console.WriteLine();
            Console.WriteLine("Usage:");
            Console.WriteLine("  dotnet run --project FeigScan -- [options]");
            Console.WriteLine();
            Console.WriteLine("Options:");
            Console.WriteLine("  --ip <address>       Reader IP (skip multicast discovery)");
            Console.WriteLine("  --port <number>      TCP port (default 10001)");
            Console.WriteLine("  --antennas 1,2,3,4   Antenna ports to scan (default: all four)");
            Console.WriteLine("  --interval <ms>      Delay between scans (default 300)");
            Console.WriteLine("  --regulation <name>  Set regulation: Europe, Africa, Asia, Russia, India");
            Console.WriteLine("  --power <watts>      Set all antenna power (0.1 to 2.0)");
            Console.WriteLine("  --help               Show this help");
        }

        private sealed class Options
        {
            public string Ip { get; private set; }
            public int Port { get; private set; } = 10001;
            public int IntervalMs { get; private set; } = 300;
            public FeigRegulation? SetRegulation { get; private set; }
            public double SetPower { get; private set; }
            public FeigReaderAntenna[] Antennas { get; private set; } =
            {
                FeigReaderAntenna.Antenna1,
                FeigReaderAntenna.Antenna2,
                FeigReaderAntenna.Antenna3,
                FeigReaderAntenna.Antenna4
            };
            public bool ShowHelp { get; private set; }

            public static Options Parse(string[] args)
            {
                Options options = new Options();

                for (int i = 0; i < args.Length; i++)
                {
                    string arg = args[i];

                    if (arg == "--help" || arg == "-h")
                    {
                        options.ShowHelp = true;
                        return options;
                    }

                    if (arg == "--ip" && i + 1 < args.Length)
                    {
                        options.Ip = args[++i];
                        continue;
                    }

                    if (arg == "--port" && i + 1 < args.Length)
                    {
                        options.Port = int.Parse(args[++i]);
                        continue;
                    }

                    if (arg == "--interval" && i + 1 < args.Length)
                    {
                        options.IntervalMs = int.Parse(args[++i]);
                        continue;
                    }

                    if (arg == "--antennas" && i + 1 < args.Length)
                    {
                        options.Antennas = ParseAntennas(args[++i]);
                        continue;
                    }

                    if (arg == "--regulation" && i + 1 < args.Length)
                    {
                        options.SetRegulation = ParseRegulation(args[++i]);
                        continue;
                    }

                    if (arg == "--power" && i + 1 < args.Length)
                    {
                        options.SetPower = double.Parse(args[++i]);
                        continue;
                    }

                    Console.WriteLine("Unknown argument: {0}", arg);
                    options.ShowHelp = true;
                    return options;
                }

                return options;
            }

            private static FeigReaderAntenna[] ParseAntennas(string value)
            {
                List<FeigReaderAntenna> antennas = new List<FeigReaderAntenna>();

                foreach (string part in value.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    switch (part.Trim())
                    {
                        case "1":
                            antennas.Add(FeigReaderAntenna.Antenna1);
                            break;
                        case "2":
                            antennas.Add(FeigReaderAntenna.Antenna2);
                            break;
                        case "3":
                            antennas.Add(FeigReaderAntenna.Antenna3);
                            break;
                        case "4":
                            antennas.Add(FeigReaderAntenna.Antenna4);
                            break;
                        default:
                            throw new ArgumentException("Antennas must be 1, 2, 3, and/or 4.");
                    }
                }

                return antennas.ToArray();
            }

            private static FeigRegulation ParseRegulation(string value)
            {
                switch (value.ToLowerInvariant())
                {
                    case "europe": return FeigRegulation.EUEurope;
                    case "africa": return FeigRegulation.EUAfrica;
                    case "asia":   return FeigRegulation.EUAsiaArabia;
                    case "russia": return FeigRegulation.EURussia;
                    case "india":  return FeigRegulation.EUIndia;
                    default:
                        throw new ArgumentException("Regulation must be: Europe, Africa, Asia, Russia, or India");
                }
            }
        }
    }
}
