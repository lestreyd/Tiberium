// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2018 Tiberium developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.file:///C:/Users/Farell%20Lestreyd/AppData/Local/GitHubDesktop/app-1.0.12/resources/app/index.htmlphp.

#include "libzerocoin/Params.h"
#include "chainparams.h"
#include "random.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>
#include <fstream>
#include <iostream>
#include <string>

using namespace std;
using namespace boost::assign;

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

#include "chainparamsseeds.h"

string GetMainParametersFromConfig(string parameter)
{
        /*
        declare new variables for reading from ini-file 
        pubkeymain - public key for main network
        pubkeytest - public key for test network
        pubkeyreg - public key for regtest network
        hashmain - genesis block for main network
        hashtest - genesis block for test network
        hashreg - genesis block for regtest network
        timestamp - pszTimestamp text
        unixtime_main - time in unix format for main network
        unixtime_test - time in unix format for test network
        unixtime_reg - time in unix format for regtest network
        masternode_time - time in unix format for masternode payments activation
        merkleroot - merkle root 
        noncemain - nonce for main network
        noncetest - nonce for test network
        noncereg - nonce for reg network
        bitsmain - nBits for main network
        bitstest - nBits for test network
        bitsreg - nBits for reg network
        */

        string linebuf; 
        string optionbuf;       
        string pubkeymain;
        string pubkeytest;
        string pubkeyreg;
        
        string hashtest;
        string hashmain;
        string hashreg;
        string timestamp;
        
        string unixtime_main;
        string unixtime_test;
        string unixtime_reg;
        
        string masternode_time;
        
        string merkleroot;

        string noncemain;
        string noncetest;
        string noncereg;

        string bitsmain;
        string bitstest;
        string bitsreg;



        std::ifstream f("config.ini");

        if (f.is_open()) {
        while (getline(f, linebuf)){
            optionbuf = "pubkeymain=";
            if ((( int )linebuf.find(optionbuf)) != -1 )
            {
                linebuf.erase(0, optionbuf.length());
                pubkeymain = linebuf.c_str();
            }
            optionbuf = "pubkeytest=";
            if ((( int )linebuf.find(optionbuf)) != -1 )
            {
                linebuf.erase(0, optionbuf.length());
                pubkeytest = linebuf.c_str();
            }
            optionbuf = "pubkeyreg=";
            if ((( int )linebuf.find(optionbuf)) != -1 )
            {
                linebuf.erase(0, optionbuf.length());
                pubkeyreg = linebuf.c_str();
            }
            optionbuf = "hashmain=";
            if ((( int )linebuf.find(optionbuf)) != -1 )
            {
                linebuf.erase(0, optionbuf.length());
                hashmain = linebuf.c_str();
            }
            optionbuf = "hashtest=";
            if ((( int )linebuf.find(optionbuf)) != -1 )
            {
                linebuf.erase(0, optionbuf.length());
                hashtest = linebuf.c_str();
            }
            optionbuf = "hashreg=";
            if ((( int )linebuf.find(optionbuf)) != -1 )
            {
                linebuf.erase(0, optionbuf.length());
                hashreg = linebuf.c_str();
            }
            optionbuf = "timestamp=";
            if ((( int )linebuf.find(optionbuf)) != -1 )
            {
                linebuf.erase(0, optionbuf.length());
                timestamp = linebuf.c_str();
            }
            optionbuf = "unixtime_main=";
            if ((( int )linebuf.find(optionbuf)) != -1 )
            {
                linebuf.erase(0, optionbuf.length());
                unixtime_main = linebuf.c_str();
            }
            optionbuf = "unixtime_test=";
            if ((( int )linebuf.find(optionbuf)) != -1 )
            {
                linebuf.erase(0, optionbuf.length());
                unixtime_test = linebuf.c_str();
            }
            optionbuf = "unixtime_reg=";
            if ((( int )linebuf.find(optionbuf)) != -1 )
            {
                linebuf.erase(0, optionbuf.length());
                unixtime_reg = linebuf.c_str();
            }
            optionbuf = "masternode_time=";
            if ((( int )linebuf.find(optionbuf)) != -1 )
            {
                linebuf.erase(0, optionbuf.length());
                masternode_time = linebuf.c_str();
            }
            optionbuf = "merkleroot=";
            if ((( int )linebuf.find(optionbuf)) != -1 )
            {
                linebuf.erase(0, optionbuf.length());
                merkleroot = linebuf.c_str();
            }
            optionbuf = "noncemain=";
            if ((( int )linebuf.find(optionbuf)) != -1 )
            {
                linebuf.erase(0, optionbuf.length());
                noncemain = linebuf.c_str();
            }
            optionbuf = "noncetest=";
            if ((( int )linebuf.find(optionbuf)) != -1 )
            {
                linebuf.erase(0, optionbuf.length());
                noncetest = linebuf.c_str();
            }
            optionbuf = "noncereg=";
            if ((( int )linebuf.find(optionbuf)) != -1 )
            {
                linebuf.erase(0, optionbuf.length());
                noncereg = linebuf.c_str();
            }
            optionbuf = "bitsmain=";
            if ((( int )linebuf.find(optionbuf)) != -1 )
            {
                linebuf.erase(0, optionbuf.length());
                bitsmain = linebuf.c_str();
            }
            optionbuf = "bitstest=";
            if ((( int )linebuf.find(optionbuf)) != -1 )
            {
                linebuf.erase(0, optionbuf.length());
                bitstest = linebuf.c_str();
            }
            optionbuf = "bitsreg=";
            if ((( int )linebuf.find(optionbuf)) != -1 )
            {
                linebuf.erase(0, optionbuf.length());
                bitsreg = linebuf.c_str();
            }
        }
        f.close();
    }
    else
        cout << "Can't open file: " << "config.ini" << endl;

    if (parameter == "pubkeymain") {
        cout << "(DEBUG) pubkeymain: " << pubkeymain << endl;
        return pubkeymain;
    }
    if (parameter == "pubkeytest") {
        cout << "(DEBUG) pubkeytest: " << pubkeytest << endl;
        return pubkeytest;
    }
    if (parameter == "pubkeyreg") {
        cout << "(DEBUG) pubkeyreg: " << pubkeyreg << endl;
        return pubkeyreg;
    }
    if (parameter == "hashmain") {
        cout << "(DEBUG) hashmain: " << hashmain << endl;
        return hashmain;
    }
    if (parameter == "hashtest") {
        cout << "(DEBUG) hashtest: " << hashtest << endl;
        return hashtest;
    }
    if (parameter == "hashreg") {
        cout << "(DEBUG) hashreg: " << hashreg << endl;
        return hashreg;
    }
    if (parameter == "timestamp") {
        cout << "(DEBUG) timestamp: " << timestamp << endl;
        return timestamp;
    }
    if (parameter == "unixtime_main") {
        cout << "(DEBUG) unixtime_main: " << unixtime_main << endl;
        return unixtime_main;
    }    
    if (parameter == "unixtime_test") {
        cout << "(DEBUG) unixtime_test: " << unixtime_test << endl;
        return unixtime_test;
    } 
    if (parameter == "unixtime_reg") {
        cout << "(DEBUG) unixtime_reg: " << unixtime_reg << endl;
        return unixtime_reg;
    } 
    if (parameter == "masternode_time") {
        cout << "(DEBUG) masternode_time: " << masternode_time << endl;
        return masternode_time;
    } 
    if (parameter == "merkleroot") {
        cout << "(DEBUG) merkleroot: " << merkleroot << endl;
        return merkleroot;
    } 
    if (parameter == "noncemain") {
        cout << "(DEBUG) noncemain: " << noncemain << endl;
        return noncemain;
    } 
    if (parameter == "noncetest") {
        cout << "(DEBUG) noncetest: " << noncetest << endl;
        return noncetest;
    } 
    if (parameter == "noncereg") {
        cout << "(DEBUG) noncereg: " << noncereg << endl;
        return noncereg;
    } 
    if (parameter == "bitsmain") {
        cout << "bitsmain: " << bitsmain << endl;
        return bitsmain;
    } 
    if (parameter == "bitstest") {
        cout << "(DEBUG) bitstest: " << bitstest << endl;
        return bitstest;
    } 
    if (parameter == "bitsreg") {
        cout << "(DEBUG) bitsreg: " << bitsreg << endl;
        return bitsreg;
    } 
    else
        return "";

}

/**
 * Main network
 */

//! Convert the pnSeeds6 array into usable address objects.
static void convertSeed6(std::vector<CAddress>& vSeedsOut, const SeedSpec6* data, unsigned int count)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7 * 24 * 60 * 60;
    for (unsigned int i = 0; i < count; i++) {
        struct in6_addr ip;
        memcpy(&ip, data[i].addr, sizeof(ip));
        CAddress addr(CService(ip, data[i].port));
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

//   What makes a good checkpoint block?
// + Is surrounded by blocks with reasonable timestamps
//   (no blocks before with a timestamp after, none after with
//    timestamp before)
// + Contains no strange transactions
static Checkpoints::MapCheckpoints mapCheckpoints =
    boost::assign::map_list_of
    // + new zero checkpoint for Tiberium (main network)
    (0, uint256(GetMainParametersFromConfig("hashmain")));
static const Checkpoints::CCheckpointData data = {
    &mapCheckpoints,
    atoi(GetMainParametersFromConfig("unixtime_main")), // * UNIX timestamp of last checkpoint block (new UNIX time 28/02/2018 00.00)
    0,          // * total number of transactions between genesis and last checkpoint
                //   (the tx=... number in the SetBestChain debug.log lines)
    2000        // * estimated number of transactions per day after checkpoint
};

static Checkpoints::MapCheckpoints mapCheckpointsTestnet =
//+new genesis hash for Tiberium testnet
    boost::assign::map_list_of(0, uint256(GetMainParametersFromConfig("hashtest")));
static const Checkpoints::CCheckpointData dataTestnet = {
    &mapCheckpointsTestnet,
    atoi(GetMainParametersFromConfig("unixtime_test")),
    0,
    250};

static Checkpoints::MapCheckpoints mapCheckpointsRegtest =
//+new parameters for Tiberium regtest
    boost::assign::map_list_of(0, uint256(GetMainParametersFromConfig("hashreg")));
static const Checkpoints::CCheckpointData dataRegtest = {
    &mapCheckpointsRegtest,
    atoi(GetMainParametersFromConfig("unixtime_reg")),
    0,
    100};

libzerocoin::ZerocoinParams* CChainParams::Zerocoin_Params() const
{
    assert(this);
    static CBigNum bnTrustedModulus(zerocoinModulus);
    static libzerocoin::ZerocoinParams ZCParams = libzerocoin::ZerocoinParams(bnTrustedModulus);

    return &ZCParams;
}

class CMainParams : public CChainParams
{
public:
    CMainParams()
    {
        networkID = CBaseChainParams::MAIN;
        strNetworkID = "main";
        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */

        pchMessageStart[0] = 0xbf;
        pchMessageStart[1] = 0x0c;
        pchMessageStart[2] = 0x6b;
        pchMessageStart[3] = 0xbd;
        vAlertPubKey = ParseHex("049cf17e11ca8e328d1b7f1dcaa878d63586eb28d23ef21ef3fbd49f554b2c86a74b37b638ec3edbeee357f3098c9ffe7d55bfad5b87ddabfff5b8a45a58930249");
        nDefaultPort = 9887;
        bnProofOfWorkLimit = ~uint256(0) >> 20; // Tiberium starting difficulty is 1 / 2^12
        nSubsidyHalvingInterval = 210000;
        nMaxReorganizationDepth = 100;
        nEnforceBlockUpgradeMajority = 750;
        nRejectBlockOutdatedMajority = 950;
        nToCheckBlockUpgradeMajority = 1000;
        nMinerThreads = 0;
        nTargetTimespan = 1 * 60; // Tiberium: 1 day
        nTargetSpacing = 1 * 60;  // Tiberium: 1 minute
        nMaturity = 100;
        nMasternodeCountDrift = 20;
        nMaxMoneyOut = 21000000 * COIN;

        /** Height or Time Based Activations **/
        nLastPOWBlock = 0;
        nModifierUpdateBlock = 615800;
        nZerocoinStartHeight = 863787;
        nZerocoinStartTime = 1535760000; // 01.09.2018 00.00.00
        nBlockEnforceSerialRange = 895400; //Enforce serial range starting this block
        nBlockRecalculateAccumulators = 908000; //Trigger a recalculation of accumulators
        nBlockFirstFraudulent = 0; //First block that bad serials emerged
        nBlockLastGoodCheckpoint = 0; //Last valid accumulator checkpoint
        nBlockEnforceInvalidUTXO = 0; //Start enforcing the invalid UTXO's

        /**
         * Build the genesis block. Note that the output of the genesis coinbase cannot
         * be spent as it did not originally exist in the database.
         *
         * CBlock(hash=00000ffd590b14, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=e0028e, nTime=1390095618, nBits=1e0ffff0, nNonce=28917698, vtx=1)
         *   CTransaction(hash=e0028e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
         *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d01044c5957697265642030392f4a616e2f3230313420546865204772616e64204578706572696d656e7420476f6573204c6976653a204f76657273746f636b2e636f6d204973204e6f7720416363657074696e6720426974636f696e73)
         *     CTxOut(nValue=50.00000000, scriptPubKey=0xA9037BAC7050C479B121CF)
         *   vMerkleTree: e0028e
         */
        const char* pszTimestamp = GetMainParametersFromConfig("timestamp").c_str();
        CMutableTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 250 * COIN;
        txNew.vout[0].scriptPubKey = CScript() << ParseHex(GetMainParametersFromConfig("pubkeymain")) << OP_CHECKSIG;
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 00000000000000;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime = atoi(GetMainParametersFromConfig("unixtime_main"));
        //genesis.nBits = Params().ProofOfWorkLimit().GetCompact();//atoi(GetMainParametersFromConfig("bitsmain"));
        genesis.nBits = ~uint256(0) >> 20
        //atoi((~uint256(0) >> 24).ToString().c_str());
        //cout << "(DEBUG) Correct nBits for this network: " << genesis.nBits << endl;


        //genesis.nNonce = CBigNum().SetCompact(block.nBits).getuint256();
        genesis.nNonce = atoi(GetMainParametersFromConfig("noncemain"));

        hashGenesisBlock = genesis.GetHash();

        cout << "(DEBUG) Genesis block for assertion: " <<hashGenesisBlock.ToString().c_str() << endl;
        cout << "(DEBUG) Merkle root for assertion: " <<genesis.hashMerkleRoot.ToString().c_str() << endl;

        assert(hashGenesisBlock == uint256(GetMainParametersFromConfig("hashmain")));

        cout << "(DEBUG) Target nNonce: " << CBigNum().SetCompact(genesis.nBits).getuint256().ToString().c_str() << endl;
        //cout << "(DEBUG) Target nBits : " << Params().ProofOfWorkLimit().GetCompact() << endl;
        
        //printf(hashGenesisBlock.ToString().c_str());


        assert(genesis.hashMerkleRoot == uint256(GetMainParametersFromConfig("merkleroot")));


        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 30);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 13);
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 212);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x02)(0x2D)(0x25)(0x33).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x02)(0x21)(0x31)(0x2B).convert_to_container<std::vector<unsigned char> >();
        // 	BIP44 coin type is from https://github.com/satoshilabs/slips/blob/master/slip-0044.md
        base58Prefixes[EXT_COIN_TYPE] = boost::assign::list_of(0x80)(0x00)(0x00)(0x77).convert_to_container<std::vector<unsigned char> >();

        convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fAllowMinDifficultyBlocks = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fSkipProofOfWorkCheck = false;
        fTestnetToBeDeprecatedFieldRPC = false;
        fHeadersFirstSyncingActive = false;

        nPoolMaxTransactions = 3;
        strSporkKey = "04d33b2dc6f90e15117204f5ee869c414c8251d757c2185e483f78d5eaf5b7e1c0e39cf202622709332926d9f17889340a65556e7c76009786ffef2abf5672ce92";
        strObfuscationPoolDummyAddress = "D87q2gC9j6nNrnzCsg4aY6bHMLsT9nUhEw";
        nStartMasternodePayments = atoi(GetMainParametersFromConfig("masternode_time")); 

        /** Zerocoin */
        zerocoinModulus = "25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784"
            "4069182906412495150821892985591491761845028084891200728449926873928072877767359714183472702618963750149718246911"
            "6507761337985909570009733045974880842840179742910064245869181719511874612151517265463228221686998754918242243363"
            "7259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133"
            "8441436038339044149526344321901146575444541784240209246165157233507787077498171257724679629263863563732899121548"
            "31438167899885040445364023527381951378636564391212010397122822120720357";
        nMaxZerocoinSpendsPerTransaction = 7; // Assume about 20kb each
        nMinZerocoinMintFee = 1 * CENT; //high fee required for zerocoin mints
        nMintRequiredConfirmations = 20; //the maximum amount of confirmations until accumulated in 19
        nRequiredAccumulation = 1;
        nDefaultSecurityLevel = 100; //full security level for accumulators
        nZerocoinHeaderVersion = 4; //Block headers must be this version once zerocoin is active
        nBudget_Fee_Confirmations = 6; // Number of confirmations for the finalization fee
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return data;
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CMainParams
{
public:
    CTestNetParams()
    {
        networkID = CBaseChainParams::TESTNET;
        strNetworkID = "test";
        pchMessageStart[0] = 0xbf;
        pchMessageStart[1] = 0x0c;
        pchMessageStart[2] = 0x6b;
        pchMessageStart[3] = 0xbd;
        vAlertPubKey = ParseHex("044d5ee735c63b4692e6d15102e056054cbe6e6d924a05cefdc4ad1ce3936cb8d8d12a003ee8e0483113a0963110ab6448917dc4dd7930681db5a78b1227c611b5");
        nDefaultPort = 19887;
        nEnforceBlockUpgradeMajority = 51;
        nRejectBlockOutdatedMajority = 75;
        nToCheckBlockUpgradeMajority = 100;
        nMinerThreads = 0;
        nTargetTimespan = 1 * 60; // Tiberium: 1 day
        nTargetSpacing = 1 * 60;  // Tiberium: 1 minute
        nLastPOWBlock = 200;
        nMaturity = 15;
        nMasternodeCountDrift = 4;
        nModifierUpdateBlock = 1520358882; // 24.02.2018 13.51
        nMaxMoneyOut = 43199500 * COIN;
        nZerocoinStartHeight = 201576;
        nZerocoinStartTime = 604331463;
        nBlockEnforceSerialRange = 1; //Enforce serial range starting this block
        nBlockRecalculateAccumulators = 9908000; //Trigger a recalculation of accumulators
        nBlockFirstFraudulent = 9891737; //First block that bad serials emerged
        nBlockLastGoodCheckpoint = 9891730; //Last valid accumulator checkpoint
        nBlockEnforceInvalidUTXO = 9902850; //Start enforcing the invalid UTXO's

        //! Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nTime = atoi(GetMainParametersFromConfig("unixtime_test"));
        genesis.nNonce = atoi(GetMainParametersFromConfig("noncemain"));

        hashGenesisBlock = genesis.GetHash();

        cout << "(DEBUG) Genesis block for test assertion: " << hashGenesisBlock.ToString().c_str() << endl;

        assert(hashGenesisBlock == uint256(GetMainParametersFromConfig("hashtest")));

        vFixedSeeds.clear();
        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 139); // Testnet Tiberium addresses start with 'x' or 'y'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 19);  // Testnet Tiberium script addresses start with '8' or '9'
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 239);     // Testnet private keys start with '9' or 'c' (Bitcoin defaults)
        // Testnet Tiberium BIP32 pubkeys start with 'DRKV'
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x3a)(0x80)(0x61)(0xa0).convert_to_container<std::vector<unsigned char> >();
        // Testnet Tiberium BIP32 prvkeys start with 'DRKP'
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x3a)(0x80)(0x58)(0x37).convert_to_container<std::vector<unsigned char> >();
        // Testnet Tiberium BIP44 coin type is '1' (All coin's testnet default)
        base58Prefixes[EXT_COIN_TYPE] = boost::assign::list_of(0x80)(0x00)(0x00)(0x01).convert_to_container<std::vector<unsigned char> >();

        convertSeed6(vFixedSeeds, pnSeed6_test, ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fAllowMinDifficultyBlocks = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

        nPoolMaxTransactions = 2;
        strSporkKey = "04c93a0d0bf4a55ba53ad41744df9f381d645e972d2c0dc0f06ce091dcae1b4d22a0675aea5254f8887999bffef0a1d32836fc60c26bc001b18edde5befe57422e";
        strObfuscationPoolDummyAddress = "y57cqfGRkekRyDRNeJiLtYVEbvhXrNbmox";
        nStartMasternodePayments = atoi(GetMainParametersFromConfig("masternode_time")); //28.02.2018
        nBudget_Fee_Confirmations = 3; // Number of confirmations for the finalization fee. We have to make this very short
                                       // here because we only have a 8 block finalization window on testnet
    }
    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataTestnet;
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CTestNetParams
{
public:
    CRegTestParams()
    {
        networkID = CBaseChainParams::REGTEST;
        strNetworkID = "regtest";
        strNetworkID = "regtest";
        pchMessageStart[0] = 0xbf;
        pchMessageStart[1] = 0x0c;
        pchMessageStart[2] = 0x6b;
        pchMessageStart[3] = 0xbd;
        nSubsidyHalvingInterval = 150;
        nEnforceBlockUpgradeMajority = 750;
        nRejectBlockOutdatedMajority = 950;
        nToCheckBlockUpgradeMajority = 1000;
        nMinerThreads = 1;
        nTargetTimespan = 24 * 60 * 60; // Tiberium: 1 day
        nTargetSpacing = 1 * 60;        // Tiberium: 1 minutes
        bnProofOfWorkLimit = ~uint256(0) >> 1;
        genesis.nTime = atoi(GetMainParametersFromConfig("unixtime_reg"));
        genesis.nBits = atoi(GetMainParametersFromConfig("bitsreg"));
        genesis.nNonce = 3;

        hashGenesisBlock = genesis.GetHash();

        cout << "(DEBUG) Genesis block for regtest assertion: " << hashGenesisBlock.ToString().c_str() << endl;

        nDefaultPort = 19883;
        assert(hashGenesisBlock == uint256(GetMainParametersFromConfig("hashreg")));

        vFixedSeeds.clear(); //! Testnet mode doesn't have any fixed seeds.
        vSeeds.clear();      //! Testnet mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fAllowMinDifficultyBlocks = true;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;
    }
    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataRegtest;
    }
};
static CRegTestParams regTestParams;

/**
 * Unit test
 */
class CUnitTestParams : public CMainParams, public CModifiableParams
{
public:
    CUnitTestParams()
    {
        networkID = CBaseChainParams::UNITTEST;
        strNetworkID = "unittest";
        nDefaultPort = 18334;
        vFixedSeeds.clear(); //! Unit test mode doesn't have any fixed seeds.
        vSeeds.clear();      //! Unit test mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fAllowMinDifficultyBlocks = false;
        fMineBlocksOnDemand = true;
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        // UnitTest share the same checkpoints as MAIN
        return data;
    }

    //! Published setters to allow changing values in unit test cases
    virtual void setSubsidyHalvingInterval(int anSubsidyHalvingInterval) { nSubsidyHalvingInterval = anSubsidyHalvingInterval; }
    virtual void setEnforceBlockUpgradeMajority(int anEnforceBlockUpgradeMajority) { nEnforceBlockUpgradeMajority = anEnforceBlockUpgradeMajority; }
    virtual void setRejectBlockOutdatedMajority(int anRejectBlockOutdatedMajority) { nRejectBlockOutdatedMajority = anRejectBlockOutdatedMajority; }
    virtual void setToCheckBlockUpgradeMajority(int anToCheckBlockUpgradeMajority) { nToCheckBlockUpgradeMajority = anToCheckBlockUpgradeMajority; }
    virtual void setDefaultConsistencyChecks(bool afDefaultConsistencyChecks) { fDefaultConsistencyChecks = afDefaultConsistencyChecks; }
    virtual void setAllowMinDifficultyBlocks(bool afAllowMinDifficultyBlocks) { fAllowMinDifficultyBlocks = afAllowMinDifficultyBlocks; }
    virtual void setSkipProofOfWorkCheck(bool afSkipProofOfWorkCheck) { fSkipProofOfWorkCheck = afSkipProofOfWorkCheck; }
};
static CUnitTestParams unitTestParams;


static CChainParams* pCurrentParams = 0;

CModifiableParams* ModifiableParams()
{
    assert(pCurrentParams);
    assert(pCurrentParams == &unitTestParams);
    return (CModifiableParams*)&unitTestParams;
}

const CChainParams& Params()
{
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(CBaseChainParams::Network network)
{
    switch (network) {
    case CBaseChainParams::MAIN:
        return mainParams;
    case CBaseChainParams::TESTNET:
        return testNetParams;
    case CBaseChainParams::REGTEST:
        return regTestParams;
    case CBaseChainParams::UNITTEST:
        return unitTestParams;
    default:
        assert(false && "Unimplemented network");
        return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}
