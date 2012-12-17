
#include "stdafx.h"

#ifndef SIGNATURE
#define SIGNATURE uint
#endif

#ifndef URLID
#define URLID uint
#endif

typedef std::map<SIGNATURE, std::set<URLID>> SIGNATUREMAP;
typedef std::map<URLID, std::set<SIGNATURE>> SIDMAP;

struct EDGE
{
	URLID nSid;
	SIGNATURE Sig;
};

struct SigSids
{
	SIGNATURE Sig;
	std::vector<URLID> nSids;
};

struct COMPSIGSIDS
{
	BOOL operator()(SigSids &a, SigSids &b)
	{
		return a.nSids.size() > b.nSids.size();
	}
};

void Output(std::vector<SigSids> &result)
{
	struct COMP
	{
		BOOL operator()(SigSids &a, SigSids &b)
		{
			return a.Sig < b.Sig;
		}
	};
	sort(result.begin(), result.end(), COMP());
	std::ofstream fout("C:\\URLResults\\Signatures.txt", std::ios::binary);
	size_t nCnt = result.size();
	fout.write((char*)&nCnt, 4);
	for (std::vector<SigSids>::iterator i = result.begin(); i != result.end(); ++i)
	{
		fout.write((char*)&(i->Sig), 4);
	}
	fout.close();
	//std::ofstream fout("C:\\test\\Signatures.txt");
	//for (std::vector<SigSids>::iterator i = result.begin(); i != result.end(); ++i)
	//{
	//	fout << i->Sig << std::endl;
	//}
	//fout.close();
}

unsigned int Hash(unsigned int &value)
{
	return value % 39953;
	//return value % 15991; //0.3%
	//return value % 34981; //0%
}

void Output(SIGNATUREMAP &results)
{
	std::vector<SigSids> result;
	SigSids temp;
	for (SIGNATUREMAP::iterator i = results.begin(); i != results.end(); ++i)
	{
		if ((i->second).size() != 0)
		{
			temp.Sig = i->first;
			for (std::set<URLID>::iterator j = (i->second).begin(); j !=(i->second).end(); ++j)
			{
				temp.nSids.push_back(*j);
			}
			result.push_back(temp);
			temp.nSids.clear();
		}
	}

	sort(result.begin(), result.end(), COMPSIGSIDS());
	std::ofstream foutNoRules("C:\\URLResults\\Results.txt");
	std::set<unsigned int> tmp;
	struct COMP
	{
		BOOL operator()(SigSids &a, SigSids &b)
		{
			return a.Sig < b.Sig;
		}
	};
	sort(result.begin(), result.end(), COMP());
	int count = 0;
	for (std::vector<SigSids>::iterator i = result.begin(); i != result.end(); ++i)
	{
		if (tmp.count(Hash(i->Sig)))
		{
			++count;
			std::cout << i->Sig << std::endl;
		}
		tmp.insert(Hash(i->Sig));
		foutNoRules << i->Sig << "\t" << i->nSids.size() << "\t";
		for (std::vector<URLID>::iterator j = i->nSids.begin(); j != i->nSids.end(); ++j)
		{
			foutNoRules << *j << " ";
		}
		foutNoRules << "\t" << Hash(i->Sig) << std::endl;
	}
	std::cout << "Number of Signatures that have conflict with others:" << count << std::endl;
	std::cout << "Total number of Signatures:" << tmp.size() << std::endl;
	std::cout << "Conflict rate:" << count / (result.size() + 0.0) * 100 << "%" << std::endl;
	foutNoRules.close();
	Output(result);
}
void OptimizeMapping(SIGNATUREMAP &results, SIDMAP &dmap);
void Optimize(SIGNATUREMAP &gmap, SIGNATUREMAP &results, SIDMAP &dmap)
{
	std::set<URLID> Sids;
	for (SIDMAP::iterator i = dmap.begin(); i != dmap.end(); ++i)
	{
		if ((i->second).size() == 1)
		{
			results[*((i->second).begin())].insert(i->first);
			Sids.insert(i->first);
		}
	}
	for (SIGNATUREMAP::iterator i = gmap.begin(); i != gmap.end(); ++i)
	{
		if ((i->second).size() == 1 && !Sids.count(*(i->second.begin())))
		{
			results[i->first].insert(*((i->second).begin()));
			Sids.insert(*((i->second).begin()));
		}
	}
	OptimizeMapping(results, dmap);
}

typedef std::set<unsigned int> SIGSET;
struct AdjustPath
{
	SIGNATURE parent;
	SIGNATURE self;
	size_t level;
};
bool myFindAdjust(std::map<unsigned int, SIGSET> &mapHashSigSet, SIDMAP &sidMap, SIGNATUREMAP &results, std::vector<SIGNATURE> &SigSet, size_t nDepth, std::vector<AdjustPath> &vecPath);

void Adjust(SIGNATUREMAP &results, SIDMAP &dmap)
{
	std::map<unsigned int, SIGSET> mapHashSigSet;
	for (SIGNATUREMAP::iterator i = results.begin(); i != results.end(); ++i)
	{
		if (i->second.size() >= 1)
		{
			mapHashSigSet[Hash((unsigned int)i->first)].insert(i->first);
		}
	}
	for (SIGNATUREMAP::iterator i = results.begin(); i != results.end(); ++i)
	{
		unsigned int iHashValue = Hash((unsigned int)i->first);
		SIGSET &iset = mapHashSigSet[iHashValue];
		size_t count = iset.size();
		if (i->second.size() == 1 && count >= 2)
		{
			for (std::set<URLID>::iterator j = i->second.begin(); j != i->second.end();)
			{
				std::set<URLID>::iterator k = dmap[*j].begin();
				for (; k != dmap[*j].end(); ++k)
				{
					unsigned int kHashValue = Hash((unsigned int)(*k));
					SIGSET &kset = mapHashSigSet[kHashValue];
					if (results[*k].size() == 0 && kset.size() + 1 < count)
					{
						kset.insert(*k);
						iset.erase(i->first);
						results[*k].insert(*j);
						break;
					}
				}
				if (k == dmap[*j].end())
				{
					break;
				}
				else
				{
					j = i->second.erase(j);
				}
			}
		}
	}
	int count = 0;
	bool flag = true;
	while (flag)
	{
		++count;
		std::cout << "Adjust: " << count << std::endl;
		flag = false;
		for (SIGNATUREMAP::iterator i = results.begin(); i != results.end(); ++i)
		{
			unsigned int iHashValue = Hash((unsigned int)i->first);
			SIGSET &iset = mapHashSigSet[iHashValue];
			size_t count = iset.size();
			if (i->second.size() == 1 && count >= 2)
			{
				std::vector<SIGNATURE> Sigs;
				std::vector<AdjustPath> vecPath;
				SIGNATURE oneSig;
				oneSig = i->first;
				Sigs.push_back(oneSig);
				if (myFindAdjust(mapHashSigSet, dmap, results, Sigs, 1, vecPath))
				{
					flag = true;
					AdjustPath onePoint;
					onePoint.parent = vecPath[vecPath.size() - 1].parent;
					onePoint.self = vecPath[vecPath.size() - 1].self;
					onePoint.level = vecPath[vecPath.size() - 1].level;
					URLID oneSid;
					while (onePoint.level != 0)
					{
						oneSid = *(results[onePoint.parent].begin());
						results[onePoint.self].insert(oneSid);
						results[onePoint.parent].erase(oneSid);
						for (std::vector<AdjustPath>::iterator j = vecPath.begin(); j != vecPath.end(); ++j)
						{
							if (j->level + 1 == onePoint.level && j->self == onePoint.parent)
							{
								onePoint.parent = j->parent;
								onePoint.self = j->self;
								onePoint.level = j->level;
								break;
							}
						}
					}
					oneSid = *(results[onePoint.parent].begin());
					results[onePoint.self].insert(oneSid);
					results[onePoint.parent].erase(oneSid);
				}
			}
		}
	}
}

bool myFindAdjust(std::map<unsigned int, SIGSET> &mapHashSigSet, SIDMAP &sidMap, SIGNATUREMAP &results, std::vector<SIGNATURE> &Sigs, size_t nDepth, std::vector<AdjustPath> &vecPath)
{
	if (nDepth > 10 || Sigs.empty())
	{
		return false;
	}
	std::vector<SIGNATURE> nextSigs;
	AdjustPath onePoint;
	if (vecPath.size() == 0)
	{
		onePoint.level = 0;
	}
	else
	{
		onePoint.level = vecPath[vecPath.size() - 1].level + 1;
	}
	for (std::vector<SIGNATURE>::iterator i = Sigs.begin(); i != Sigs.end(); ++i)
	{
		onePoint.parent = *i;
		SIGSET &iset = mapHashSigSet[Hash((unsigned int)*i)];
		size_t count = iset.size();
		if (results[*i].size() == 1)
		{
			URLID sid = *(results[*i].begin());
			for (std::set<URLID>::iterator k = sidMap[sid].begin(); k != sidMap[sid].end(); ++k)
			{
				SIGSET &kset = mapHashSigSet[Hash((unsigned int)(*k))];
				if (kset.size() + 1 == count)
				{
					nextSigs.push_back(*k);
					onePoint.self = *k;
					vecPath.push_back(onePoint);
					if (results[*k].size() == 0)
					{
						return true;
					}
				}
			}
		}
	}

	return myFindAdjust(mapHashSigSet, sidMap, results, nextSigs, nDepth + 1, vecPath);

}
//void Adjust(SIGNATUREMAP &results, SIDMAP &dmap)
//{
//	std::set<unsigned int> tmp;
//	std::set<SIGNATURE>::iterator k;
//	bool flag = true;
//	for (SIGNATUREMAP::iterator i = results.begin(); i != results.end(); ++i)
//	{
//		if (i->second.size() > 1)
//		{
//			tmp.insert(Hash((unsigned int)i->first));
//		}
//	}
//	while (flag)
//	{
//		flag = false;
//		for (SIGNATUREMAP::iterator i = results.begin(); i != results.end(); ++i)
//		{
//			if (i->second.size() == 1)
//			{
//				if (tmp.count(Hash((unsigned int)i->first)))
//				{
//					for (std::set<URLID>::iterator j = i->second.begin(); j != i->second.end();)
//					{
//						for (k = dmap[*j].begin(); k != dmap[*j].end(); ++k)
//						{
//							if (!tmp.count(Hash((unsigned int)(*k))) && results[*k].size() == 0)
//							{
//								tmp.insert(Hash((unsigned int)(*k)));
//								results[*k].insert(*j);
//								flag = true;
//								break;
//							}
//						}
//						if (k == dmap[*j].end())
//						{
//							break;
//						}
//						else
//						{
//							j = i->second.erase(j);
//						}
//					}
//				}
//				else
//				{
//					tmp.insert(Hash((unsigned int)i->first));
//				}
//			}
//		}
//	}
//}

struct OptimizePath
{
	SIGNATURE original_Sig;
	URLID Sid;
	SIGNATURE current_Sig;
	size_t level;
};
bool myFindOptimize(SIGNATUREMAP &results, SIDMAP &dmap, std::vector<SIGNATURE> Sids, size_t count, std::vector<OptimizePath> &vecPath, size_t nDepth);

void OptimizeMapping(SIGNATUREMAP &results, SIDMAP &dmap)
{
	size_t min;
	SIGNATURE sig;
	size_t original_num;
	SIGNATURE original_sig;
	bool flag = true;
	int count = 0;
	while(flag)
	{
		++count;
		std::cout << "First Optimize: " << count << std::endl;
		flag = false;
		for (SIDMAP::iterator i = dmap.begin(); i != dmap.end(); ++i)
		{
			min = dmap.size() + 1;
			original_num = dmap.size() + 1;
			for (std::set<SIGNATURE>::iterator j = (i->second).begin(); j != (i->second).end(); ++j)
			{
				if (min > results[(*j)].size())
				{
					min = results[(*j)].size();
					sig = (*j);
				}
				if (results[(*j)].count(i->first))
				{
					original_num = results[(*j)].size();
					original_sig = (*j);
				}
			}
			if (original_num >= 2 && min + 1 < original_num)
			{
				if (original_num != dmap.size() + 1)
				{
					results[original_sig].erase(i->first);
				}
				results[sig].insert(i->first);
				flag = true;
				//break;
			}
		}
	}
	flag = true;
	count = 0;
	while (flag)
	{
		++count;
		std::cout << "Second Optimize: " << count << std::endl;
		flag = false;
		for (SIDMAP::iterator i = dmap.begin(); i != dmap.end(); ++i)
		{
			min = dmap.size() + 1;
			original_num = dmap.size() + 1;
			for (std::set<SIGNATURE>::iterator j = (i->second).begin(); j != (i->second).end(); ++j)
			{
				if (min > results[(*j)].size())
				{
					min = results[(*j)].size();
					sig = (*j);
				}
				if (results[(*j)].count(i->first))
				{
					original_num = results[(*j)].size();
					original_sig = (*j);
				}
			}
			if (original_num >= 2 && min + 1 == original_num)
			{
				std::vector<SIGNATURE> Sigs;
				std::vector<OptimizePath> vecPath;
				OptimizePath onePoint;
				onePoint.level = 0;
				onePoint.Sid = i->first;
				onePoint.original_Sig = original_sig;
				for (std::set<SIGNATURE>::iterator j = (i->second).begin(); j != (i->second).end(); ++j)
				{
					if (min == results[*j].size())
					{
						onePoint.current_Sig = *j;
						vecPath.push_back(onePoint);
						Sigs.push_back(*j);
					}
				}
				if (myFindOptimize(results, dmap, Sigs, min, vecPath, 1))
				{
					flag = true;
					OptimizePath onePoint;
					onePoint.original_Sig = vecPath[vecPath.size() - 1].original_Sig;
					onePoint.Sid = vecPath[vecPath.size() - 1].Sid;
					onePoint.current_Sig = vecPath[vecPath.size() - 1].current_Sig;
					onePoint.level = vecPath[vecPath.size() - 1].level;
					while (onePoint.level != 0)
					{
						results[onePoint.original_Sig].erase(onePoint.Sid);
						results[onePoint.current_Sig].insert(onePoint.Sid);
						for (std::vector<OptimizePath>::iterator j = vecPath.begin(); j != vecPath.end(); ++j)
						{
							if (j->level + 1 == onePoint.level && j->current_Sig == onePoint.original_Sig)
							{
								onePoint.original_Sig = j->original_Sig;
								onePoint.Sid = j->Sid;
								onePoint.current_Sig = j->current_Sig;
								onePoint.level = j->level;
								break;
							}
						}
					}
					results[onePoint.original_Sig].erase(onePoint.Sid);
					results[onePoint.current_Sig].insert(onePoint.Sid);
				}
			}
		}
	}
}

bool myFindOptimize(SIGNATUREMAP &results, SIDMAP &dmap, std::vector<SIGNATURE> Sigs, size_t count, std::vector<OptimizePath> &vecPath, size_t nDepth)
{
	if (nDepth > 1 || Sigs.empty())
	{
		return false;
	}
	OptimizePath onePoint;
	if (vecPath.size() == 0)
	{
		onePoint.level = 0;
	}
	else
	{
		onePoint.level = vecPath[vecPath.size() - 1].level + 1;
	}
	std::vector<SIGNATURE> nextSigs;
	for (std::vector<SIGNATURE>::iterator i = Sigs.begin(); i != Sigs.end(); ++i)
	{
		onePoint.original_Sig = *i;
		for (std::set<URLID>::iterator j = results[*i].begin(); j != results[*i].end(); ++j)
		{
			onePoint.Sid = *j;
			for (std::set<SIGNATURE>::iterator k = dmap[*j].begin(); k != dmap[*j].end(); ++k)
			{
				if (results[*k].size() < count)
				{
					onePoint.current_Sig = *k;
					vecPath.push_back(onePoint);
					return true;
				}
				else if (results[*k].size() == count && *k != *i)
				{
					nextSigs.push_back(*k);
					onePoint.current_Sig = *k;
					vecPath.push_back(onePoint);
				}
				else
				{
					continue;
				}
			}
		}
	}
	return myFindOptimize(results, dmap, nextSigs, count, vecPath, nDepth + 1);
}


void Read(std::vector<EDGE> &edges)
{
	std::ifstream fin("C:\\URLResults\\Edges.txt", std::ios::binary);
	size_t nCnt = 0;
	fin.read((char*)&nCnt, 4);
	EDGE edge;
	for (size_t i = 0; i < nCnt; ++i)
	{
		fin.read((char*)&edge.nSid, 4);
		fin.read((char*)&edge.Sig, 4);
		edges.push_back(edge);
	}
}

void main()
{
	std::vector<EDGE> edges;

	Read(edges);

	std::cout << "GenerateEdges complete!" << std::endl;

	SIGNATUREMAP gmap;
	for (std::vector<EDGE>::iterator i = edges.begin(); i != edges.end(); ++i)
	{
		gmap[i->Sig].insert(i->nSid);
	}

	std::cout << "Generate Signature map complete!" << std::endl;
	
	SIDMAP dmap;
	for (std::vector<EDGE>::iterator i = edges.begin(); i != edges.end(); ++i)
	{
		dmap[i->nSid].insert(i->Sig);
	}

	std::cout << "Generate Sid map complete!" << std::endl;

	SIGNATUREMAP results;
	Optimize(gmap, results, dmap);

	std::cout << "Optimize complete!" << std::endl;

	Adjust(results, dmap);

	std::cout << "Adjust complete!" << std::endl;

	Output(results);

	std::cout << "Output complete!" << std::endl;

	system("pause");
}