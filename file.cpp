#include "stdafx.h"

#ifndef SIGNATURE
#define SIGNATURE uint
#endif

#ifndef URLID
#define URLID uint
#endif

typedef std::map<SIGNATURE, std::set<URLID>> SIGNATUREMAP;
typedef std::map<URLID, std::set<SIGNATURE>> URLIDMAP;

struct EDGE
{
	URLID nURLid;
	SIGNATURE Sig;
};

struct SigURLids
{
	SIGNATURE Sig;
	std::vector<URLID> nURLids;
};

struct COMPSIGURLIDS
{
	BOOL operator()(SigURLids &a, SigURLids &b)
	{
		return a.nURLids.size() > b.nURLids.size();
	}
};

void Output(std::vector<SigURLids> &result)
{
	struct COMP
	{
		BOOL operator()(SigURLids &a, SigURLids &b)
		{
			return a.Sig < b.Sig;
		}
	};
	sort(result.begin(), result.end(), COMP());
	std::ofstream fout("C:\\URLResults\\Signatures.txt", std::ios::binary);
	size_t nCnt = result.size();
	size_t NumOfURLs;
	fout.write((char*)&nCnt, 4);
	for (std::vector<SigURLids>::iterator i = result.begin(); i != result.end(); ++i)
	{
		fout.write((char*)&(i->Sig), 4);
		NumOfURLs = i->nURLids.size();
		fout.write((char*)&NumOfURLs, 4);
		for (std::vector<URLID>::iterator j = i->nURLids.begin(); j != i->nURLids.end(); ++j)
		{
			fout.write((char*)&(*j), 4);
		}
	}
	fout.close();
}

unsigned int Hash(SIGNATURE &value)
{
	return value % 39953;
}

void Output(SIGNATUREMAP &results)
{
	std::vector<SigURLids> result;
	SigURLids temp;
	for (SIGNATUREMAP::iterator i = results.begin(); i != results.end(); ++i)
	{
		if ((i->second).size() != 0)
		{
			temp.Sig = i->first;
			for (std::set<URLID>::iterator j = (i->second).begin(); j !=(i->second).end(); ++j)
			{
				temp.nURLids.push_back(*j);
			}
			result.push_back(temp);
			temp.nURLids.clear();
		}
	}

	sort(result.begin(), result.end(), COMPSIGURLIDS());
	std::ofstream foutNoRules("C:\\URLResults\\Results.txt");
	std::map<unsigned int, std::set<SIGNATURE>> tmp;
	struct COMP
	{
		BOOL operator()(SigURLids &a, SigURLids &b)
		{
			return a.Sig < b.Sig;
		}
	};
	sort(result.begin(), result.end(), COMP());
	for (std::vector<SigURLids>::iterator i = result.begin(); i != result.end(); ++i)
	{
		tmp[Hash(i->Sig)].insert(i->Sig);
		foutNoRules << i->Sig << "\t" << i->nURLids.size() << "\t";
		for (std::vector<URLID>::iterator j = i->nURLids.begin(); j != i->nURLids.end(); ++j)
		{
			foutNoRules << *j << " ";
		}
		foutNoRules << "\t" << Hash(i->Sig) << std::endl;
	}
	foutNoRules.close();
	size_t count = 0;
	for (std::map<unsigned int, std::set<SIGNATURE>>::iterator i = tmp.begin(); i != tmp.end(); ++i)
	{
		if (i->second.size() > 1)
		{
			count += i->second.size() - 1;
			std::cout << i->first << std::endl;
		}
	}
	std::cout << "Number of Signatures that have conflict with others:" << count << std::endl;
	std::cout << "Total number of Signatures:" << result.size() << std::endl;
	std::cout << "Conflict rate:" << count / (result.size() + 0.0) * 100 << "%" << std::endl;
	Output(result);
}

typedef std::set<SIGNATURE> SIGSET;

bool FirstAdjust(SIGNATUREMAP &results, URLIDMAP &dmap, std::map<unsigned int, SIGSET> &mapHashSigSet)
{
	bool flag = false;
	for (SIGNATUREMAP::iterator i = results.begin(); i != results.end(); ++i)
	{
		unsigned int iHashValue = Hash((SIGNATURE)i->first);
		SIGSET &iset = mapHashSigSet[iHashValue];
		size_t count = iset.size();
		if (i->second.size() == 1 && count >= 2)
		{
			for (std::set<URLID>::iterator j = i->second.begin(); j != i->second.end();)
			{
				std::set<SIGNATURE>::iterator k = dmap[*j].begin();
				for (; k != dmap[*j].end(); ++k)
				{
					unsigned int kHashValue = Hash((SIGNATURE)(*k));
					SIGSET &kset = mapHashSigSet[kHashValue];
					if (results[*k].size() == 0 && kset.size() + 1 < count)
					{
						kset.insert(*k);
						iset.erase(i->first);
						results[*k].insert(*j);
						flag = true;
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

	return flag;
}

struct AdjustPath
{
	SIGNATURE parent;
	SIGNATURE self;
	size_t level;
};

bool myFindAdjust(std::map<unsigned int, SIGSET> &mapHashSigSet, URLIDMAP &URLidMap, SIGNATUREMAP &results, std::vector<SIGNATURE> &Sigs, size_t nDepth, std::vector<AdjustPath> &vecPath, size_t count)
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
		URLID URLid = *(results[*i].begin());
		for (std::set<SIGNATURE>::iterator k = URLidMap[URLid].begin(); k != URLidMap[URLid].end(); ++k)
		{
			SIGSET &kset = mapHashSigSet[Hash((SIGNATURE)(*k))];
			if (kset.size() + 1 < count && results[*k].size() == 0)
			{
				onePoint.self = *k;
				vecPath.push_back(onePoint);
				return true;
			}
			if (kset.size() + 1 == count && results[*k].size() == 1)
			{
				nextSigs.push_back(*k);
				onePoint.self = *k;
				vecPath.push_back(onePoint);
			}
		}
	}
	Sigs.clear();

	return myFindAdjust(mapHashSigSet, URLidMap, results, nextSigs, nDepth + 1, vecPath, count);
}

bool SecondAdjust(SIGNATUREMAP &results, URLIDMAP &dmap, std::map<unsigned int, SIGSET> &mapHashSigSet)
{
	bool flag = false;
	for (SIGNATUREMAP::iterator i = results.begin(); i != results.end(); ++i)
	{
		unsigned int iHashValue = Hash((SIGNATURE)i->first);
		SIGSET &iset = mapHashSigSet[iHashValue];
		size_t count = iset.size();
		if (i->second.size() == 1 && count >= 2)
		{
			std::vector<SIGNATURE> Sigs;
			std::vector<AdjustPath> vecPath;
			SIGNATURE oneSig;
			oneSig = i->first;
			Sigs.push_back(oneSig);
			if (myFindAdjust(mapHashSigSet, dmap, results, Sigs, 1, vecPath, count))
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
			vecPath.clear();
		}
	}

	return flag;
}

void Adjust(SIGNATUREMAP &results, URLIDMAP &dmap)
{
	std::map<unsigned int, SIGSET> mapHashSigSet;
	for (SIGNATUREMAP::iterator i = results.begin(); i != results.end(); ++i)
	{
		if (i->second.size() >= 1)
		{
			mapHashSigSet[Hash((SIGNATURE)i->first)].insert(i->first);
		}
	}
	bool flag = true;
	int count = 0;
	while (flag)
	{
		++count;
		std::cout << "First Adjust: " << count << std::endl;
		flag = FirstAdjust(results, dmap, mapHashSigSet);
	}
	count = 0;
	flag = true;
	while (flag)
	{
		++count;
		std::cout << "Second Adjust: " << count << std::endl;
		flag = SecondAdjust(results, dmap, mapHashSigSet);
	}
}

bool FirstOptimize(SIGNATUREMAP &results, URLIDMAP &dmap)
{
	size_t min;
	SIGNATURE sig;
	size_t original_num;
	SIGNATURE original_sig;
	bool flag = false;
	for (URLIDMAP::iterator i = dmap.begin(); i != dmap.end(); ++i)
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
		}
	}

	return flag;
}

struct OptimizePath
{
	SIGNATURE original_Sig;
	URLID URLid;
	SIGNATURE current_Sig;
	size_t level;
};

bool myFindOptimize(SIGNATUREMAP &results, URLIDMAP &dmap, std::vector<SIGNATURE> Sigs, size_t count, std::vector<OptimizePath> &vecPath, size_t nDepth)
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
			onePoint.URLid = *j;
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

bool SecondOptimize(SIGNATUREMAP &results, URLIDMAP &dmap)
{
	size_t min;
	SIGNATURE sig;
	size_t original_num;
	SIGNATURE original_sig;
	bool flag = false;
	for (URLIDMAP::iterator i = dmap.begin(); i != dmap.end(); ++i)
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
			onePoint.URLid = i->first;
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
				onePoint.URLid = vecPath[vecPath.size() - 1].URLid;
				onePoint.current_Sig = vecPath[vecPath.size() - 1].current_Sig;
				onePoint.level = vecPath[vecPath.size() - 1].level;
				while (onePoint.level != 0)
				{
					results[onePoint.original_Sig].erase(onePoint.URLid);
					results[onePoint.current_Sig].insert(onePoint.URLid);
					for (std::vector<OptimizePath>::iterator j = vecPath.begin(); j != vecPath.end(); ++j)
					{
						if (j->level + 1 == onePoint.level && j->current_Sig == onePoint.original_Sig)
						{
							onePoint.original_Sig = j->original_Sig;
							onePoint.URLid = j->URLid;
							onePoint.current_Sig = j->current_Sig;
							onePoint.level = j->level;
							break;
						}
					}
				}
				results[onePoint.original_Sig].erase(onePoint.URLid);
				results[onePoint.current_Sig].insert(onePoint.URLid);
			}
		}
	}

	return flag;
}

void OptimizeMapping(SIGNATUREMAP &results, URLIDMAP &dmap)
{
	bool flag = true;
	int count = 0;
	while(flag)
	{
		++count;
		std::cout << "First Optimize: " << count << std::endl;
		flag = FirstOptimize(results, dmap);
	}
	flag = true;
	count = 0;
	while (flag)
	{
		++count;
		std::cout << "Second Optimize: " << count << std::endl;
		flag = SecondOptimize(results, dmap);
	}
}

void Optimize(SIGNATUREMAP &gmap, SIGNATUREMAP &results, URLIDMAP &dmap)
{
	std::set<URLID> URLids;
	for (URLIDMAP::iterator i = dmap.begin(); i != dmap.end(); ++i)
	{
		if ((i->second).size() == 1)
		{
			results[*((i->second).begin())].insert(i->first);
			URLids.insert(i->first);
		}
	}
	for (SIGNATUREMAP::iterator i = gmap.begin(); i != gmap.end(); ++i)
	{
		if ((i->second).size() == 1 && !URLids.count(*(i->second.begin())))
		{
			results[i->first].insert(*((i->second).begin()));
			URLids.insert(*((i->second).begin()));
		}
	}
	OptimizeMapping(results, dmap);
}

void Read(std::vector<EDGE> &edges)
{
	std::ifstream fin("C:\\URLResults\\Edges.txt", std::ios::binary);
	size_t nCnt = 0;
	fin.read((char*)&nCnt, 4);
	EDGE edge;
	for (size_t i = 0; i < nCnt; ++i)
	{
		fin.read((char*)&edge.nURLid, 4);
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
		gmap[i->Sig].insert(i->nURLid);
	}

	std::cout << "Generate Signature map complete!" << std::endl;
	
	URLIDMAP dmap;
	for (std::vector<EDGE>::iterator i = edges.begin(); i != edges.end(); ++i)
	{
		dmap[i->nURLid].insert(i->Sig);
	}

	std::cout << "Generate URLid map complete!" << std::endl;

	SIGNATUREMAP results;
	Optimize(gmap, results, dmap);

	std::cout << "Optimize complete!" << std::endl;

	Adjust(results, dmap);

	std::cout << "Adjust complete!" << std::endl;

	Output(results);

	std::cout << "Output complete!" << std::endl;

	system("pause");
}