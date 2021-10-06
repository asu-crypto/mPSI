
#include <iostream>
#include "Network/BtChannel.h"
#include "Network/BtEndpoint.h"

using namespace std;
#include "Common/Defines.h"
using namespace osuCrypto;

#include "OtBinMain.h"
#include "OtBinMain.v2.h"
#include "bitPosition.h"

#include <numeric>
#include "Common/Log.h"
#include "gbf.h"
#include "o1party.h"
#include "tpsi.h"
#include "psi3.h"
//int miraclTestMain();


void usage(const char* argv0)
{
	std::cout << "Error! Please use:" << std::endl;
	std::cout << "\t 1. For unit test: " << argv0 << " -u" << std::endl;
	std::cout << "\t 2. For simulation (5 parties <=> 5 terminals): " << std::endl;;
	std::cout << "\t\t each terminal: " << argv0 << " -n 5 -t 2 -m 12 -p [pIdx]" << std::endl;

}
int main(int argc, char** argv)
{
	//OPPRFn_Aug_EmptrySet_Test_Impl();
	//return 0;
	//InitDebugPrinting();
//	GbfTest();
//	return 0;
	//PolyTest();
	//party_test(PolyOkvs);
	//party2psi_Test_Main();
	//tpsi_test(PaxosOkvs, secSemiHonest);

	//nPSI2_server_aided_Test();
	//O1nPSI_Test();
	//return 0;

	/*nPSI3_Test();
	O1nPSI_Test();
	return 0;*/
	//============
	/*O1nPSI_Test();

	nPSI2_server_aided_Test();*/
	/*tPSI_Test();



	return 0;*/

	//tPSI_Test();



	//return 0;

	//myCuckooTest_stash();
	//Table_Based_Random_Test();
	//OPPRF2_EmptrySet_Test_Main();
	//OPPRFn_EmptrySet_Test_Main();
	//Transpose_Test();
	//OPPRF3_EmptrySet_Test_Main();
	//OPPRFnt_EmptrySet_Test_Main();
	//OPPRFnt_EmptrySet_Test_Main();
	//OPPRFn_Aug_EmptrySet_Test_Impl();
	//OPPRFnt_EmptrySet_Test_Main();
	//OPPRF2_EmptrySet_Test_Main();
	//return 0;


	u64 pSetSize = 5, psiSecParam = 40, bitSize = 128;

	u64 nParties, tParties, opt_basedOPPRF, setSize, isAug;

	u64 roundOPPRF;


	switch (argc) {
	case 2: //unit test
		if (argv[1][0] == '-' && argv[1][1] == 'u')
			tPSI_Test();
		break;

	case 6: //2psi with server-aider
		if (argv[1][0] == '-' && argv[1][1] == 'm')
			setSize = 1 << atoi(argv[2]);
		else
		{
			cout << "setSize: wrong format\n";
			usage(argv[0]);
			return 0;
		}
		if (argv[5][0] == '2' && argv[5][1] == 'p' && argv[5][2] == 's' && argv[5][3] == 'i')
			if (argv[3][0] == '-' && argv[3][1] == 'p')
			{
				u64 pIdx = atoi(argv[4]);
				//cout << setSize << " \t"  << nParties << " \t" << tParties << "\t" << pIdx << "\n";
				if(pIdx==1)
					cout << "party_psi2_server_aided\n";
				party_psi2_server_aided(pIdx, setSize, secSemiHonest);
			}
		else
		{
			cout << "pIdx: wrong format\n";
			usage(argv[0]);
			return 0;
		}
		break;

	case 5: //3psi
		if (argv[1][0] == '-' && argv[1][1] == 'm')
			setSize = 1 << atoi(argv[2]);
		else
		{
			cout << "setSize: wrong format\n";
			usage(argv[0]);
			return 0;
		}

		if (argv[3][0] == '-' && argv[3][1] == 'p')
		{
			u64 pIdx = atoi(argv[4]);
			//cout << setSize << " \t"  << nParties << " \t" << tParties << "\t" << pIdx << "\n";
			//party_psi3(pIdx, setSize, PaxosOkvs, secSemiHonest);
			party_psi3(pIdx, setSize, SimulatedOkvs, secSemiHonest);
			//party_psi2_server_aided(pIdx, setSize,secSemiHonest);
		}
		else
		{
			cout << "pIdx: wrong format\n";
			usage(argv[0]);
			return 0;
		}
		break;

	case 7:
		if (argv[1][0] == '-' && argv[1][1] == 'm')
			setSize = 1 << atoi(argv[2]);
		else
		{
			cout << "setSize: wrong format\n";
			usage(argv[0]);
			return 0;
		}

		if (argv[3][0] == '-' && argv[3][1] == 'n')
			nParties = atoi(argv[4]);
		else
		{
			cout << "nParties: wrong format\n";
			usage(argv[0]);
			return 0;
		}

		if (argv[5][0] == '-' && argv[5][1] == 'p')
		{
			u64 pIdx = atoi(argv[6]);
			//cout << setSize << " \t"  << nParties << " \t" << tParties << "\t" << pIdx << "\n";

			if (pIdx == 0)
				cout << "partyO1 protocol\n";

			//partyO1(pIdx, nParties, setSize, PaxosOkvs, secSemiHonest);
			partyO1(pIdx, nParties, setSize, SimulatedOkvs, secSemiHonest);
		}
		else
		{
			cout << "pIdx: wrong format\n";
			usage(argv[0]);
			return 0;
		}

		break;


	case 9: //tPSI
		//cout << "9\n";

		if (argv[1][0] == '-' && argv[1][1] == 'm')
			setSize = 1 << atoi(argv[2]);
		else
		{
			cout << "setSize: wrong format\n";
			usage(argv[0]);
			return 0;
		}

		if (argv[3][0] == '-' && argv[3][1] == 'n')
			nParties = atoi(argv[4]);
		else
		{
			cout << "nParties: wrong format\n";
			usage(argv[0]);
			return 0;
		}

		if (argv[5][0] == '-' && argv[5][1] == 't')
			tParties = atoi(argv[6]);
		else
		{
			cout << "tParties: wrong format\n";
			usage(argv[0]);
			return 0;
		}

		if (argv[7][0] == '-' && argv[7][1] == 'p')
		{
			u64 pIdx = atoi(argv[8]);
			//cout << setSize << " \t"  << nParties << " \t" << tParties << "\t" << pIdx << "\n";
			//tpsi_party(pIdx, nParties, tParties, setSize, PaxosOkvs, secSemiHonest);
			tpsi_party(pIdx, nParties, tParties, setSize, SimulatedOkvs, secSemiHonest);
		}
		else
		{
			cout << "pIdx: wrong format\n";
			usage(argv[0]);
			return 0;
		}

		break;
	}



	return 0;
}
