#include "Dalvik.h"
#include <vector>
#include <map>
#include <queue>
#include <iostream>
#include <fstream>
#include <string>
#include <set>

void loadKernel();
void loadApkStatic(char* apkPath);
void retrieveOffsetMap(std::map<char*, u4, charscomp>* offsetMap, char* filename);

