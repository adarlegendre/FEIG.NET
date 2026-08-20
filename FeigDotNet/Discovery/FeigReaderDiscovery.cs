using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using FeigDotNet.Connections;

namespace FeigDotNet.Discovery
{
    public class FeigReaderDiscovery
    {
        private static readonly IPEndPoint DiscoveryEndpoint = new IPEndPoint(IPAddress.Parse("224.0.36.50"), 50000);
        private static readonly byte[] DiscoveryCommand = { 0x01, 0x00, 0x00, 0x1c, 0x9b };

        public IList<NetworkInterface> ListNetworkInterfaces()
        {
            List<NetworkInterface> interfaces = new List<NetworkInterface>();

            foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up || !ni.SupportsMulticast)
                {
                    continue;
                }

                if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback ||
                    ni.NetworkInterfaceType == NetworkInterfaceType.Tunnel)
                {
                    continue;
                }

                try
                {
                    IPInterfaceProperties properties = ni.GetIPProperties();

                    if (!properties.MulticastAddresses.Any() || properties.GetIPv4Properties() == null)
                    {
                        continue;
                    }
                }
                catch (NetworkInformationException)
                {
                    continue;
                }

                interfaces.Add(ni);
            }

            return interfaces;
        }

        public IDictionary<NetworkInterface, List<FeigReaderInfo>> FindReaders(IEnumerable<NetworkInterface> networkInterfaces, int timeout = 1000)
        {
            return networkInterfaces
                .AsParallel()
                .SelectMany(ni => this.DiscoverOnInterface(ni, timeout))
                .ToList()
                .GroupBy(k => k.NetworkInterface)
                .ToDictionary(k => k.Key, v => v.Select(r => r.ReaderInfo).ToList());
        }

        private IEnumerable<DiscoveryHit> DiscoverOnInterface(NetworkInterface networkInterface, int timeout)
        {
            List<DiscoveryHit> hits = new List<DiscoveryHit>();
            IPv4InterfaceProperties ipv4;

            try
            {
                ipv4 = networkInterface.GetIPProperties().GetIPv4Properties();
            }
            catch (NetworkInformationException)
            {
                return hits;
            }

            if (ipv4 == null)
            {
                return hits;
            }

            using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
            {
                socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastInterface, IPAddress.HostToNetworkOrder(ipv4.Index));
                socket.ReceiveTimeout = Math.Max(50, Math.Min(timeout, 250));

                try
                {
                    socket.SendTo(DiscoveryCommand, DiscoveryEndpoint);
                }
                catch (SocketException)
                {
                    return hits;
                }

                DateTime deadline = DateTime.UtcNow.AddMilliseconds(timeout);

                while (DateTime.UtcNow < deadline)
                {
                    try
                    {
                        byte[] receiveBytes = new byte[256];
                        EndPoint remoteEndpoint = new IPEndPoint(IPAddress.Any, 0);
                        int length = socket.ReceiveFrom(receiveBytes, ref remoteEndpoint);

                        if (length >= 30 &&
                            receiveBytes[0] == 0x01 &&
                            receiveBytes[1] == 0x00 &&
                            (receiveBytes[3] & 0x04) == 0x04)
                        {
                            hits.Add(new DiscoveryHit
                            {
                                NetworkInterface = networkInterface,
                                ReaderInfo = this.Parse(receiveBytes)
                            });
                        }
                    }
                    catch (SocketException)
                    {
                        // receive timed out; keep waiting until the overall deadline
                    }
                }
            }

            return hits;
        }

        private FeigReaderInfo Parse(byte[] buffer)
        {
            FeigReaderInfo readerInfo = new FeigReaderInfo();

            readerInfo.DeviceID = buffer.Skip(6).Take(4).ToArray();
            readerInfo.IPAddress = string.Format("{0}.{1}.{2}.{3}", buffer[16], buffer[17], buffer[18], buffer[19]);

            FeigReaderType feigReaderType;

            if (!Enum.TryParse(buffer[5].ToString(), out feigReaderType))
            {
                feigReaderType = FeigReaderType.Undefined;
            }

            readerInfo.Type = feigReaderType;

            if ((buffer[3] & 0x02) == 0x02)
            {
                readerInfo.MacAddress = string.Format("{0:X2}-{1:X2}-{2:X2}-{3:X2}-{4:X2}-{5:X2}", buffer[10], buffer[11], buffer[12], buffer[13], buffer[14], buffer[15]);
            }
            else
            {
                readerInfo.MacAddress = "00-00-00-00-00-00";
            }

            readerInfo.DHCP = (buffer[4] & 0x80) == 0x80;

            if ((buffer[3] & 0x08) == 0x08)
            {
                readerInfo.SubnetMask = string.Format("{0}.{1}.{2}.{3}", buffer[20], buffer[21], buffer[22], buffer[23]);
            }

            if ((buffer[3] & 0x10) == 0x10)
            {
                readerInfo.GatewayAddress = string.Format("{0}.{1}.{2}.{3}", buffer[24], buffer[25], buffer[26], buffer[27]);
            }

            if ((buffer[3] & 0x20) == 0x20)
            {
                readerInfo.Port = BitConverter.ToInt16(buffer.Skip(28).Take(2).Reverse().ToArray(), 0);
            }

            return readerInfo;
        }

        private sealed class DiscoveryHit
        {
            public NetworkInterface NetworkInterface { get; set; }
            public FeigReaderInfo ReaderInfo { get; set; }
        }
    }
}
