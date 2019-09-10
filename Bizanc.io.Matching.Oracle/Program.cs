﻿using System;
using System.Linq;
using System.Collections.Generic;
using Bizanc.io.Matching.Core.Domain;
using System.Threading.Tasks;
using Bizanc.io.Matching.Infra;
using Bizanc.io.Matching.Core.Domain.Messages;
using System.Net.Sockets;
using System.Threading;
using Bizanc.io.Matching.Core.Crypto;
using Bizanc.io.Matching.Infra.Repository;
using Bizanc.io.Matching.Infra.Connector;
using System.Collections.Generic;
using Microsoft.Extensions.Configuration;
using System.IO;
using Serilog;
using Serilog.Events;
using System.Threading.Channels;
using Amazon.CloudHSM;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.Common;

namespace Bizanc.io.Matching.Oracle
{
    class NodeConfig
    {
        public string Network { get; set; }
        public int ListenPort { get; set; }
        public string SeedAddress { get; set; }
        public int SeedPort { get; set; }
        public string OracleBTCAddres { get; set; }
        public string OracleETHAddres { get; set; }
        public string BTCEndpoint { get; set; }
        public string ETHEndpoint { get; set; }
        public bool Mine { get; set; }
        public string ApiEndpoint { get; set; }
    }

    class Program
    {
        //         private static WithdrawInfoRepository repository;

        //         private static ChannelReader<Chain> reader;

        //         private static async void WithdrawListener(Miner miner, CryptoConnector connector, string btcSecret, string ethSecret, NodeConfig conf)
        //         {
        //             var withdrwawalDictionary = new Dictionary<string, Withdrawal>();
        //             var ethConnector = new EthereumOracleConnector(ethSecret, conf.ETHEndpoint, conf.OracleETHAddres);
        //             var btcConnector = new BitcoinOracleConnector(conf.Network, conf.BTCEndpoint, btcSecret);

        //             while (await reader.WaitToReadAsync())
        //             {
        //                 var chain = await reader.ReadAsync();
        //                 chain = chain.Get(5);
        //                 if (chain != null)
        //                 {
        //                     foreach (var wd in chain.CurrentBlock.Withdrawals)
        //                     {
        //                         try
        //                         {
        //                             if (!withdrwawalDictionary.ContainsKey(wd.HashStr) && !(await repository.Contains(wd.HashStr)))
        //                             {
        //                                 WithdrawInfo result = null;

        //                                 if (wd.Asset == "BTC")
        //                                     result = await btcConnector.WithdrawBtc(wd.HashStr, wd.TargetWallet, wd.Size);
        //                                 else
        //                                     result = await ethConnector.WithdrawEth(wd.HashStr, wd.TargetWallet, wd.Size, wd.Asset);

        //                                 if (result != null)
        //                                 {
        //                                     withdrwawalDictionary.Add(wd.HashStr, wd);
        //                                     result.HashStr = wd.HashStr;
        //                                     await repository.Save(result);
        //                                 }
        //                             }
        //                         }
        //                         catch (Exception e)
        //                         {
        //                             Log.Error("Failed to withdrawal... \n" + e.ToString());
        //                         }
        //                     }
        //                 }
        //             }
        //         }

        //         async static Task Main(string[] args)
        //         {
        //             var builder = new ConfigurationBuilder()
        //                 .SetBasePath(Directory.GetCurrentDirectory())
        //                 .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
        //                 .AddCommandLine(args);

        // #if DEBUG
        //             builder = builder.AddUserSecrets<Program>();
        // #else
        //             builder = builder.AddAzureKeyVault("https://testnetvaultbiz.vault.azure.net/");
        // #endif
        //             IConfigurationRoot configuration = builder.Build();

        //             AmazonCloudHSMClient client = new AmazonCloudHSMClient(Amazon.RegionEndpoint.USEast1);
        //             var signer = client.DeleteHsmAsync()

        //             Pkcs11

        //             var conf = new NodeConfig();
        //             configuration.GetSection("Node").Bind(conf);

        //             repository = new WithdrawInfoRepository();
        //             var connector = new CryptoConnector(conf.OracleETHAddres, conf.OracleBTCAddres, conf.ETHEndpoint, conf.BTCEndpoint, conf.Network);
        //             var miner = new Miner(new PeerListener(conf.ListenPort), new WalletRepository(),
        //             new BlockRepository(), new BalanceRepository(), new BookRepository(),
        //             new DepositRepository(), new OfferRepository(), new TransactionRepository(),
        //             new WithdrawalRepository(), new TradeRepository(), repository,
        //             connector, conf.ListenPort);

        //             reader = miner.GetChainStream();

        //             await miner.Start(true);

        //             WithdrawListener(miner, connector, configuration.GetValue<string>("BTCSECRET"), configuration.GetValue<string>("ETHSECRET"), conf);

        //             if (!string.IsNullOrEmpty(conf.SeedAddress) && conf.SeedPort > 0)
        //             {
        //                 try
        //                 {
        //                     var seednode = new Peer(new TcpClient(conf.SeedAddress, conf.SeedPort));
        //                     miner.Connect(seednode);
        //                 }
        //                 catch (Exception e)
        //                 {
        //                     Log.Error(e.ToString());
        //                     throw;
        //                 }
        //             }
        //             await Task.Delay(Timeout.Infinite);
        //         }
        //     }
        // }



        static void Main(string[] args)
        {
            // Specify the path to unmanaged PKCS#11 library provided by the cryptographic device vendor
            string pkcs11LibraryPath = @"/opt/cloudhsm/lib/libcloudhsm_pkcs11_standard.so";

            // Create factories used by Pkcs11Interop library
            Pkcs11InteropFactories factories = new Pkcs11InteropFactories();

            // Load unmanaged PKCS#11 library
            using (IPkcs11Library pkcs11Library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, pkcs11LibraryPath, AppType.MultiThreaded))
            {
                // Show general information about loaded library
                ILibraryInfo libraryInfo = pkcs11Library.GetInfo();

                Console.WriteLine("Library");
                Console.WriteLine("  Manufacturer:       " + libraryInfo.ManufacturerId);
                Console.WriteLine("  Description:        " + libraryInfo.LibraryDescription);
                Console.WriteLine("  Version:            " + libraryInfo.LibraryVersion);

                // Get list of all available slots
                foreach (ISlot slot in pkcs11Library.GetSlotList(SlotsType.WithOrWithoutTokenPresent))
                {
                    // Show basic information about slot
                    ISlotInfo slotInfo = slot.GetSlotInfo();

                    Console.WriteLine();
                    Console.WriteLine("Slot");
                    Console.WriteLine("  Manufacturer:       " + slotInfo.ManufacturerId);
                    Console.WriteLine("  Description:        " + slotInfo.SlotDescription);
                    Console.WriteLine("  Token present:      " + slotInfo.SlotFlags.TokenPresent);

                    if (slotInfo.SlotFlags.TokenPresent)
                    {
                        // Show basic information about token present in the slot
                        ITokenInfo tokenInfo = slot.GetTokenInfo();

                        Console.WriteLine("Token");
                        Console.WriteLine("  Manufacturer:       " + tokenInfo.ManufacturerId);
                        Console.WriteLine("  Model:              " + tokenInfo.Model);
                        Console.WriteLine("  Serial number:      " + tokenInfo.SerialNumber);
                        Console.WriteLine("  Label:              " + tokenInfo.Label);

                        // Show list of mechanisms (algorithms) supported by the token
                        Console.WriteLine("Supported mechanisms: ");
                        foreach (CKM mechanism in slot.GetMechanismList())
                            Console.WriteLine("  " + mechanism);

                    }

                    slot.
                }
            }
        }
    }
}