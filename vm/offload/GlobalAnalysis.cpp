#include "Dalvik.h"
#include "CustomizedClass.h"
#include <sstream> 
#include <stdio.h>
#include <cstdlib>

struct BitsVec;
extern std::vector<DvmDex*> loadedDex;
static ClassObject* javaLangObject;
static std::fstream outputfile;
static std::fstream reachableOffsetFile;
static std::fstream reachableMethodFile;

struct MethodFrame {
    Method* method;
    const u2* insns;
    int leftSize;
    std::map<ClassObject*, BitsVec*>* clzAccInfo;
    int callerIdx;
};

std::stringstream converter;

/* the dictionary to match the class index and its name in the file */
//std::map<unsigned int, char*>* idxClazzNameDict = new std::map<unsigned int, char*>();
/* the dictionary to match the class name and its index in the file */
//std::map<char*, unsigned int, charscomp>* clazzNameDict = new std::map<char*, unsigned int, charscomp>();
/* to store the offset in the file for a certain method */
std::map<char*, unsigned int, charscomp>* methodClzAccMap = new std::map<char*, unsigned int, charscomp>();

//void scanStatic(Method* method, std::set<Method*>* chain, std::map<ClassObject*, BitsVec*>* methodClzAccInfo);

void freeClazzAccInfoMap(std::map<ClassObject*, BitsVec*>* accMap) {
    for (std::map<ClassObject*, BitsVec*>::iterator it = accMap->begin(); it != accMap->end(); ++it) {
        BitsVec* bitsvec = it->second;
        if(bitsvec->bits != NULL) {
            //ALOGE("bitsvec size is: %d", bitsvec->size);
            free(bitsvec->bits);
        }
        delete bitsvec;
    }
    delete accMap;
}

void persistClzAccInfo(Method* method, std::map<ClassObject*, BitsVec*>* result) {
    std::streampos begin, end;
    outputfile.seekp(0, std::ios::beg);
    begin = outputfile.tellp(); 
    outputfile.seekp(0, std::ios::end);
    end = outputfile.tellp();
    unsigned int offset = end - begin;
    
    const char* clazzName = method->clazz->descriptor;
    const char* methodName = method->name;
    char idxStr[33];
    converter << method->idx;
    converter >> idxStr;
    converter.str("");
    converter.clear();
    char* key = new char[strlen(clazzName) + strlen(methodName) + strlen(idxStr) + 3];
    strcpy(key, clazzName);
    strcat(key, " ");
    strcat(key, methodName);
    strcat(key, " ");
    strcat(key, idxStr);
  
    (*methodClzAccMap)[key] = offset;
    //ALOGE("offset is: %u, key is: %s", offset, key);
    // output method identification
    outputfile << key << std::endl;
    for (std::map<ClassObject*, BitsVec*>::iterator it = result->begin(); it != result->end(); ++it) {
        ClassObject* obj = it->first;
        //dstfile << (*clazzNameDict)[obj->descriptor] << std::endl;
        outputfile << obj->descriptor << std::endl;
        BitsVec* bitsvec = it->second;
        outputfile << bitsvec->size;
        u4 sz = ((bitsvec->size - 1) >> 5) + 1;
        for(u4 i = 0; i < sz; i++) {
            outputfile << " " << bitsvec->bits[i];
        }
        outputfile << std::endl;
    }
    outputfile << std::endl;
}

void retrieveClzAccInfo(unsigned int fileoffset, std::map<ClassObject*, BitsVec*>* result) {
    //ALOGE("retrive is called, where file offset is: %u", fileoffset);
    outputfile.seekg(fileoffset);
    std::string line;
    // read the method name info
    std::getline(outputfile, line);
    while(true) {
        std::getline(outputfile, line);
        if(line.compare("") == 0) {
            break;
        }
        //unsigned int clazzIdx = atoi(line.c_str());
        //ClassObject* resClass = dvmLookupClass((*idxClazzNameDict)[clazzIdx], NULL, false);
        ClassObject* resClass = dvmLookupClass(line.c_str(), NULL, false);
        std::getline(outputfile, line);
        BitsVec* bitsvec = new BitsVec();
        unsigned int size = atoi(line.substr(0, line.find(" ")).c_str());
        bitsvec->size = size;
        if(size != 0) {
            u4 sz = ((size - 1) >> 5) + 1;
            bitsvec->bits = (u4*)calloc(sz, 4);
            line = line.substr(line.find(" ") + 1);
            for(unsigned int i = 0; i < sz; i++) {
                bitsvec->bits[i] = atoi(line.substr(0, line.find(" ")).c_str());
                line = line.substr(line.find(" ") + 1);
            }
        }
        (*result)[resClass] = bitsvec;
    }
}

void mergeClzAccInfo(std::map<ClassObject*, BitsVec*>* methodClzAccInfo, std::map<ClassObject*, BitsVec*>* clazzAccMap) {
    for (std::map<ClassObject*, BitsVec*>::iterator it = clazzAccMap->begin(); it != clazzAccMap->end(); ++it) {
        if(methodClzAccInfo->find(it->first) == methodClzAccInfo->end()) {
            (*methodClzAccInfo)[it->first] = new BitsVec();
        }
        BitsVec* clazzAccInfo = (*methodClzAccInfo)[it->first];
        BitsVec* subAccInfo = it->second;
        u4 sz = ((subAccInfo->size - 1) >> 5) + 1;
        if(clazzAccInfo->size == 0) {
            u4* newbits = (u4*)calloc(sz, 4);
            clazzAccInfo->bits = newbits;
            clazzAccInfo->size = subAccInfo->size;
        } else {
            u4 srcSz = ((clazzAccInfo->size - 1) >> 5) + 1;
            if(srcSz < sz) {
                u4* newbits = (u4*)calloc(sz, 4);
                if(clazzAccInfo->bits != NULL) {
                    memcpy(newbits, clazzAccInfo->bits, srcSz << 2);
                    free(clazzAccInfo->bits);
                }
                clazzAccInfo->bits = newbits;
            }
            if(clazzAccInfo->size < subAccInfo->size) {
                clazzAccInfo->size = subAccInfo->size;
            }
        }
        for(u4 i = 0; i < sz; i++) {
            clazzAccInfo->bits[i] = clazzAccInfo->bits[i] | subAccInfo->bits[i];
        }
    }
    freeClazzAccInfoMap(clazzAccMap);
}

void scanStatic(Method* method, std::map<ClassObject*, BitsVec*>* methodClzAccInfo) {
    std::set<Method*>* reachableMethod = new std::set<Method*>();
    std::vector<MethodFrame*>* toprocess = new std::vector<MethodFrame*>();
    MethodFrame* frame = new MethodFrame();
    frame->method = method;
    frame->insns = method->insns;
    frame->leftSize = dvmGetMethodInsnsSize(method);
    frame->clzAccInfo = methodClzAccInfo;
    frame->callerIdx = -1;
    toprocess->push_back(frame);
    
    while(!toprocess->empty()) {
        u4 frameIdx = toprocess->size() - 1;
        MethodFrame* curFrame = toprocess->at(frameIdx);
        // check if the current frame is making a cycle
        if((u4)curFrame->leftSize == dvmGetMethodInsnsSize(curFrame->method)) {
            const char* clazzName = curFrame->method->clazz->descriptor;
            const char* methodName = curFrame->method->name;
            char idxStr[33];
            converter << curFrame->method->idx;
            converter >> idxStr;
            converter.str("");
            converter.clear();
            char* key = new char[strlen(clazzName) + strlen(methodName) + strlen(idxStr) + 3];
            strcpy(key, clazzName);
            strcat(key, " ");
            strcat(key, methodName);
            strcat(key, " ");
            strcat(key, idxStr);
            int callerIdx = curFrame->callerIdx;
            if(methodClzAccMap->find(key) != methodClzAccMap->end()) {
                unsigned int fileoffset = (*methodClzAccMap)[key];
                retrieveClzAccInfo(fileoffset, curFrame->clzAccInfo);
                if(callerIdx != -1) {
                    mergeClzAccInfo(toprocess->at(callerIdx)->clzAccInfo, curFrame->clzAccInfo);
                }
                toprocess->pop_back();
                delete curFrame;
                continue;
            }
            delete[] key;
            bool isCycle = false;
            while(callerIdx != -1) {
                MethodFrame* callerFrame = toprocess->at(callerIdx);
                if(callerFrame->method == curFrame->method) {
                    // find a cycle, pop this frame
                    toprocess->pop_back();
                    freeClazzAccInfoMap(curFrame->clzAccInfo);
                    delete curFrame;
                    isCycle = true;
                    break;
                } else {
                    callerIdx = callerFrame->callerIdx;
                }
            }
            if(isCycle) {
                continue;
            }
        }
        // check if the current method reaches the end
        if(curFrame->leftSize <= 0) {
            persistClzAccInfo(curFrame->method, curFrame->clzAccInfo);
            if(curFrame->callerIdx != -1) {
                mergeClzAccInfo(toprocess->at(curFrame->callerIdx)->clzAccInfo, curFrame->clzAccInfo);
            }
            toprocess->pop_back();
            delete curFrame;
            continue;
        }

        //ALOGE("process frame size: %u, curFrame: %p", toprocess->size(), curFrame);
        //ALOGE("process frame: %p.%p,%s", curFrame, curFrame->method, curFrame->method->name);
        DvmDex* methodClassDex = curFrame->method->clazz->pDvmDex;
        const u2* insns = curFrame->insns;
        std::map<ClassObject*, BitsVec*>* clzAccInfo = curFrame->clzAccInfo;
        int width = dexGetWidthFromInstruction(insns);
        u4 ref;
        curFrame->leftSize -= width;
        curFrame->insns += width;
        Opcode opcode = dexOpcodeFromCodeUnit(*insns);
        if(opcode == OP_SGET_VOLATILE || opcode == OP_SGET_WIDE_VOLATILE || opcode == OP_SGET_OBJECT_VOLATILE
        || opcode == OP_SGET || opcode == OP_SGET_WIDE || opcode == OP_SGET_OBJECT || opcode == OP_SGET_BOOLEAN
        || opcode == OP_SGET_BYTE || opcode == OP_SGET_CHAR || opcode == OP_SGET_SHORT) {
            ref = insns[1];
            StaticField* sfield = (StaticField*)dvmDexGetResolvedField(methodClassDex, ref);
            if (sfield == NULL) {
                sfield = resolveStaticField(curFrame->method->clazz, ref);
                if(sfield == NULL) { // we should have encountered a wrong version field branch
                    return;
                }
            }
            unsigned int offset = sfield - sfield->clazz->sfields;
            if(clzAccInfo->find(sfield->clazz) == clzAccInfo->end()) {
                (*clzAccInfo)[sfield->clazz] = new BitsVec();
            }
            BitsVec* bitsvec = (*clzAccInfo)[sfield->clazz];
            u4 sz = (offset >> 5) + 1;
            if(bitsvec->size == 0) {
                u4* newbits = (u4*)calloc(sz, 4);
                bitsvec->bits = newbits;
                bitsvec->size = offset + 1;
            } else {
                u4 srcSz = ((bitsvec->size - 1) >> 5) + 1;
                if(srcSz < sz) {
                    u4* newbits = (u4*)calloc(sz, 4);
                    if(bitsvec->bits != NULL) {
                        memcpy(newbits, bitsvec->bits, srcSz << 2);
                        free(bitsvec->bits);
                    }
                    bitsvec->bits = newbits;
                }
                if(bitsvec->size < offset + 1) {
                    bitsvec->size = offset + 1;
                }
            }
            bitsvec->bits[sz - 1] = bitsvec->bits[sz - 1] | (1U << (offset & 0x1F));
        } else if(opcode == OP_INVOKE_VIRTUAL || opcode == OP_INVOKE_VIRTUAL_RANGE) {
                ref = insns[1];             // method ref
            
                int voffset;
                Method* baseMethod;
                baseMethod = dvmDexGetResolvedMethod(methodClassDex, ref);
                if (baseMethod == NULL) {
                    baseMethod = resolveMethod(curFrame->method->clazz, ref, METHOD_VIRTUAL);
                    if(baseMethod == NULL) { // we should have encountered a wrong version method branch
                        return;
                    }
                }
                bool isLangObjectClass = baseMethod->clazz == javaLangObject;
                if(isLangObjectClass) {
                    continue;
                }
                if(reachableMethod->find(baseMethod) == reachableMethod->end()) {
                    reachableMethod->insert(baseMethod);
                }
                voffset = baseMethod->methodIndex;
                std::vector<ClassObject*>* subclasses = findSubClass(baseMethod->clazz);
                //ALOGE("call virtual method: %s.%s, size: %u, subclass count: %d", baseMethod->clazz->descriptor, baseMethod->name, toprocess->size(), subclasses->size());
                std::set<Method*> parsedMethod;
                
                for(unsigned int idx = 0; idx < subclasses->size(); idx++) {
                    //ALOGE("subclasses: %p, class: %s, base is: %s", subclasses->at(idx), subclasses->at(idx)->descriptor, baseMethod->clazz->descriptor);
                    Method* methodToCall = subclasses->at(idx)->vtable[voffset];
                    assert(methodToCall != NULL);
                    if(parsedMethod.find(methodToCall) != parsedMethod.end()) {
                        continue;
                    } else {
                        parsedMethod.insert(methodToCall);
                    }
                    std::map<ClassObject*, BitsVec*>* tocallClzAccMap = new std::map<ClassObject*, BitsVec*>();
                    MethodFrame* toCallFrame = new MethodFrame();
                    toCallFrame->method = methodToCall;
                    toCallFrame->insns = methodToCall->insns;
                    toCallFrame->leftSize = dvmGetMethodInsnsSize(methodToCall);
                    toCallFrame->clzAccInfo = tocallClzAccMap;
                    toCallFrame->callerIdx = frameIdx;
                    toprocess->push_back(toCallFrame);
                }
            } else if(opcode == OP_INVOKE_INTERFACE || opcode == OP_INVOKE_INTERFACE_RANGE) { // see Interp.cpp-dvmInterpFindInterfaceMethod
                ref = insns[1];             // method ref 
            
                Method* absMethod;
                absMethod = dvmDexGetResolvedMethod(methodClassDex, ref);
                if (absMethod == NULL) {
                    absMethod = resolveInterfaceMethod(curFrame->method->clazz, ref);
                     if(absMethod == NULL) { // we should have encountered a wrong version method branch
                        return;
                    }
                }
                //ALOGE("call interface method: %s.%s, size: %u", absMethod->clazz->descriptor, absMethod->name, toprocess->size());
                if(reachableMethod->find(absMethod) == reachableMethod->end()) {
                    reachableMethod->insert(absMethod);
                }
                assert(dvmIsAbstractMethod(absMethod));
            
                std::vector<ClassObject*>* implclasses = findImplementClass(absMethod->clazz);
                // use this vector to store the method which have been parsed since it seems that the method which is not overriden by its subclass will have the same reference
                std::set<Method*> parsedMethod;
                
                for(unsigned int idx = 0; idx < implclasses->size(); idx++) {
                    Method* methodToCall;
                    int ifIdx;
                    for (ifIdx = 0; ifIdx < implclasses->at(idx)->iftableCount; ifIdx++) {
                        if (implclasses->at(idx)->iftable[ifIdx].clazz == absMethod->clazz) {
                            break;
                        }
                    }
                    int vtableIndex = implclasses->at(idx)->iftable[ifIdx].methodIndexArray[absMethod->methodIndex];
                    methodToCall = implclasses->at(idx)->vtable[vtableIndex];
                    assert(methodToCall != NULL);
                    if(parsedMethod.find(methodToCall) != parsedMethod.end()) {
                        continue;
                    } else {
                        parsedMethod.insert(methodToCall);
                    }
                    std::map<ClassObject*, BitsVec*>* tocallClzAccMap = new std::map<ClassObject*, BitsVec*>();
                    MethodFrame* toCallFrame = new MethodFrame();
                    toCallFrame->method = methodToCall;
                    toCallFrame->insns = methodToCall->insns;
                    toCallFrame->leftSize = dvmGetMethodInsnsSize(methodToCall);
                    toCallFrame->clzAccInfo = tocallClzAccMap;
                    toCallFrame->callerIdx = frameIdx;
                    toprocess->push_back(toCallFrame);
                }
            } else if(opcode == OP_INVOKE_SUPER || opcode == OP_INVOKE_DIRECT || opcode == OP_INVOKE_STATIC 
                || opcode == OP_INVOKE_SUPER_RANGE || opcode == OP_INVOKE_DIRECT_RANGE || opcode == OP_INVOKE_STATIC_RANGE) {
                ref = insns[1];             // method ref 
            
                Method* methodToCall;
                if(opcode == OP_INVOKE_SUPER || opcode == OP_INVOKE_SUPER_RANGE) {
                    Method* baseMethod;
                    baseMethod = dvmDexGetResolvedMethod(methodClassDex, ref);
                    if (baseMethod == NULL) {
                        baseMethod = resolveMethod(curFrame->method->clazz, ref, METHOD_VIRTUAL);
                        if(baseMethod == NULL) { // we should have encountered a wrong version method branch
                            return;
                        }
                    }
                    assert(baseMethod->methodIndex < curFrame->method->clazz->super->vtableCount);
                    methodToCall = curFrame->method->clazz->super->vtable[baseMethod->methodIndex];
                } else if(opcode == OP_INVOKE_DIRECT || opcode == OP_INVOKE_DIRECT_RANGE) {
                    methodToCall = dvmDexGetResolvedMethod(methodClassDex, ref);
                    if (methodToCall == NULL) {
                        methodToCall = resolveMethod(curFrame->method->clazz, ref, METHOD_DIRECT);
                    }
                } else {
                    methodToCall = dvmDexGetResolvedMethod(methodClassDex, ref);
                    if (methodToCall == NULL) {
                        methodToCall = resolveMethod(curFrame->method->clazz, ref, METHOD_STATIC);
                    }
                } 
                if(methodToCall == NULL) { // we should have encountered a wrong version method branch
                    return;
                }
                //ALOGE("call sds method: %s.%s, size: %u", methodToCall->clazz->descriptor, methodToCall->name, toprocess->size());
                if(reachableMethod->find(methodToCall) == reachableMethod->end()) {
                    reachableMethod->insert(methodToCall);
                }
                std::map<ClassObject*, BitsVec*>* tocallClzAccMap = new std::map<ClassObject*, BitsVec*>();
                MethodFrame* toCallFrame = new MethodFrame();
                toCallFrame->method = methodToCall;
                toCallFrame->insns = methodToCall->insns;
                toCallFrame->leftSize = dvmGetMethodInsnsSize(methodToCall);
                toCallFrame->clzAccInfo = tocallClzAccMap;
                toCallFrame->callerIdx = frameIdx;
                toprocess->push_back(toCallFrame);
        }
    }
    delete toprocess;
    
    if(reachableMethod->size() != 0) {
        ALOGE("clazz reachable method size is: %d, method is: %s.%s", reachableMethod->size(), method->clazz->descriptor, method->name);
        std::streampos begin, end;
        reachableMethodFile.seekp(0, std::ios::beg);
        begin = reachableMethodFile.tellp(); 
        reachableMethodFile.seekp(0, std::ios::end);
        end = reachableMethodFile.tellp();
        unsigned int offset = end - begin;
    
        reachableOffsetFile << method->clazz->descriptor << " " << method->name << " " << method->idx << std::endl;
        reachableOffsetFile << offset << std::endl;
    
        reachableMethodFile << method->clazz->descriptor << " " << method->name << " " << method->idx << std::endl;
        for (std::set<Method*>::iterator it = reachableMethod->begin(); it != reachableMethod->end(); ++it) {
            Method* reachMethod = *it;
            reachableMethodFile << reachMethod->clazz->descriptor << " " << reachMethod->name << " " << reachMethod->idx << std::endl;
        }
        reachableMethodFile << std::endl;
    }
    delete reachableMethod;
    //ALOGE("scan end, the size is: %d", clazzAccMap->size());
}

static void persistResult(std::ofstream* staticfile, std::ofstream* offsetfile, Method* method, std::map<ClassObject*, BitsVec*>* result) {
    std::streampos begin, end;
    staticfile->seekp(0, std::ios::beg);
    begin = staticfile->tellp(); 
    staticfile->seekp(0, std::ios::end);
    end = staticfile->tellp();
    unsigned int offset = end - begin;
    
    const char* clazzName = method->clazz->descriptor;
    const char* methodName = method->name;
    char idxStr[33];
    converter << method->idx;
    converter >> idxStr;
    converter.str("");
    converter.clear();
    char* key = new char[strlen(clazzName) + strlen(methodName) + strlen(idxStr) + 3];
    strcpy(key, clazzName);
    strcat(key, " ");
    strcat(key, methodName);
    strcat(key, " ");
    strcat(key, idxStr);
  
    *offsetfile << key << std::endl;
    *offsetfile << offset << std::endl;
    //ALOGE("offset is: %u, key is: %s", offset, key);
    // output method identification
    *staticfile << key << std::endl;
    for (std::map<ClassObject*, BitsVec*>::iterator it = result->begin(); it != result->end(); ++it) {
        ClassObject* obj = it->first;
        //dstfile << (*clazzNameDict)[obj->descriptor] << std::endl;
        *staticfile << obj->descriptor << std::endl;
        BitsVec* bitsvec = it->second;
        *staticfile << bitsvec->size;
        u4 sz = ((bitsvec->size - 1) >> 5) + 1;
        for(u4 i = 0; i < sz; i++) {
            *staticfile << " " << bitsvec->bits[i];
        }
        *staticfile << std::endl;
    }
    *staticfile << std::endl;
    delete[] key;
}

void loadKernel() {
    ClassPathEntry* entry;
    const char* bootPath = "/home/yli118/androidapk/data/data/jars/core.jar:/home/yli118/androidapk/data/data/jars/core-junit.jar:/home/yli118/androidapk/data/data/jars/bouncycastle.jar:/home/yli118/androidapk/data/data/jars/ext.jar:/home/yli118/androidapk/data/data/jars/framework.jar:/home/yli118/androidapk/data/data/jars/framework2.jar:/home/yli118/androidapk/data/data/jars/android.policy.jar:/home/yli118/androidapk/data/data/jars/services.jar:/home/yli118/androidapk/data/data/jars/apache-xml.jar:";
    entry = processClassPath(bootPath);
    while (entry->kind != kCpeLastEntry) {
        DvmDex* pDvmDex;
        switch (entry->kind) {
        case kCpeJar:
            {
                JarFile* pJarFile = (JarFile*) entry->ptr;

                pDvmDex = dvmGetJarFileDex(pJarFile);
            }
            break;
        case kCpeDex:
            {
                RawDexFile* pRawDexFile = (RawDexFile*) entry->ptr;

                pDvmDex = dvmGetRawDexFileDex(pRawDexFile);
            }
            break;
        default:
            ALOGE("Unknown kind %d", entry->kind);
            assert(false);
            return;
        }
        loadedDex.push_back(pDvmDex);
        pDvmDex->pDexFile->pClassLookup = dexCreateClassLookup(pDvmDex->pDexFile);
        entry++;
    }
    /*char outFileName[160];
    char* BASE_PATH = getenv("OFFLOAD_PARSE_CACHE");
    if(BASE_PATH == NULL) {
        BASE_PATH = strdup("/data/data");
    }
    strcpy(outFileName, BASE_PATH);
    strcat(outFileName, "/");
    strcat(outFileName, "dict.txt");
    std::ofstream dstfile;
    dstfile.open(outFileName, std::ios::trunc);
    unsigned int clzIdx = 0;*/
    char outFileName[160];
    char* BASE_PATH = getenv("OFFLOAD_PARSE_CACHE");
    if(BASE_PATH == NULL) {
        BASE_PATH = strdup("/data/data");
    }
    strcpy(outFileName, BASE_PATH);
    strcat(outFileName, "/static.txt");
    outputfile.open(outFileName, std::ios::in | std::ios::out | std::ios::trunc);
    char staticpath[160];
    strcpy(staticpath, BASE_PATH);
    strcat(staticpath, "/staticresult.txt");
    std::ofstream staticfile;
    staticfile.open(staticpath, std::ios::out | std::ios::trunc);
    char offsetpath[160];
    strcpy(offsetpath, BASE_PATH);
    strcat(offsetpath, "/offsetresult.txt");
    std::ofstream offsetfile;
    offsetfile.open(offsetpath, std::ios::out | std::ios::trunc);
    char reachablemethpath[160];
    strcpy(reachablemethpath, BASE_PATH);
    strcat(reachablemethpath, "/reachablemethod.txt");
    reachableMethodFile.open(reachablemethpath, std::ios::out | std::ios::trunc);
    char reachableoffpath[160];
    strcpy(reachableoffpath, BASE_PATH);
    strcat(reachableoffpath, "/reachableoffset.txt");
    reachableOffsetFile.open(reachableoffpath, std::ios::out | std::ios::trunc);
    for(unsigned int idx = 0; idx < loadedDex.size(); idx++) {
        DvmDex* pDvmDex;
        pDvmDex = loadedDex[idx];
        for(unsigned int i = 0; i < pDvmDex->pHeader->classDefsSize; i++) {
            const DexClassDef pClassDef = pDvmDex->pDexFile->pClassDefs[i];
            ClassObject* resClass;  // this segment is copied from Resolve.cpp - dvmResolveClass()
            const char* className;
            className = dexStringByTypeIdx(pDvmDex->pDexFile, pClassDef.classIdx);
            //(*clazzNameDict)[className] = clzIdx;
            //(*idxClazzNameDict)[clzIdx] = className;
            //dstfile << clzIdx++ << " " << className << endl;
            if(className[0] != '\0' && className[1] == '\0') {
                /* primitive type */
                resClass = dvmFindPrimitiveClass(className[0]);
            } else {
                resClass = customDefineClass(pDvmDex, className, NULL);
                if(strcmp(className, "Ljava/lang/Object;") == 0 && javaLangObject == NULL) {
                    javaLangObject = resClass;
                }
                if(resClass == NULL) {
                    ALOGE("find unloaded class: %s", className);
                    continue;
                }
            }
        }
    }
    
    for(unsigned int idx = 0; idx < loadedDex.size(); idx++) {
        DvmDex* pDvmDex = loadedDex[idx];
        for(unsigned int i = 0; i < pDvmDex->pHeader->classDefsSize; i++) {
            const DexClassDef pClassDef = pDvmDex->pDexFile->pClassDefs[i];
            ClassObject* resClass;  // this segment is copied from Resolve.cpp - dvmResolveClass()
            const char* className;
            className = dexStringByTypeIdx(pDvmDex->pDexFile, pClassDef.classIdx);
            if(className[0] != '\0' && className[1] == '\0') {
                /* primitive type */
                resClass = dvmFindPrimitiveClass(className[0]);
            } else {
                resClass = dvmLookupClass(className, NULL, false);
            }
            if(resClass == NULL) {
                ALOGE("find unloaded class: %s", className);
                continue;
            }
            // check if it is an interface
            if(dvmIsInterfaceClass(resClass)) {
                continue;
            }
            if(resClass == javaLangObject) {
                continue;
            }
            // traverse and parse every method in the class, see Object.cpp - findMethodInListByDescriptor
            Method* vmethods = resClass->virtualMethods;
            size_t vmethodCount = resClass->virtualMethodCount;
            for(size_t j = 0; j < vmethodCount; j++) {
                Method* method = &vmethods[j];
                if(dvmIsNativeMethod(method)) {
                    continue;
                }
                //ALOGE("start parse method: %s:%s, %u", method->clazz->descriptor, method->name, method->idx);
                //std::set<Method*>* chain = new std::set<Method*>();
                //if(strncmp(method->name, "matrixTest", 10) == 0) {
                std::map<ClassObject*, BitsVec*>* methodClzAccInfo = new std::map<ClassObject*, BitsVec*>();
                scanStatic(method, methodClzAccInfo);
                persistResult(&staticfile, &offsetfile, method, methodClzAccInfo);
                freeClazzAccInfoMap(methodClzAccInfo);
                //}
                //delete chain;
            }
            Method* dmethods = resClass->directMethods;
            size_t dmethodCount = resClass->directMethodCount;
            for(size_t j = 0; j < dmethodCount; j++) {
                Method* method = &dmethods[j];
                if(dvmIsNativeMethod(method)) {
                    continue;
                }
                //ALOGE("start parse method: %s:%s, %u", method->clazz->descriptor, method->name, method->idx);
                //std::set<Method*>* chain = new std::set<Method*>();
                std::map<ClassObject*, BitsVec*>* methodClzAccInfo = new std::map<ClassObject*, BitsVec*>();
                scanStatic(method, methodClzAccInfo);
                persistResult(&staticfile, &offsetfile, method, methodClzAccInfo);
                freeClazzAccInfoMap(methodClzAccInfo);
                //delete chain;
            }
        }
    }
    staticfile.close();
    offsetfile.close();
    outputfile.close();
    reachableMethodFile.close();
    reachableOffsetFile.close();
}

void loadApkStatic(char* apkPath) {
    ClassPathEntry* entry;
    const char* bootPath = "/home/yli118/androidapk/data/data/jars/core.jar:/home/yli118/androidapk/data/data/jars/core-junit.jar:/home/yli118/androidapk/data/data/jars/bouncycastle.jar:/home/yli118/androidapk/data/data/jars/ext.jar:/home/yli118/androidapk/data/data/jars/framework.jar:/home/yli118/androidapk/data/data/jars/framework2.jar:/home/yli118/androidapk/data/data/jars/android.policy.jar:/home/yli118/androidapk/data/data/jars/services.jar:/home/yli118/androidapk/data/data/jars/apache-xml.jar:";
    char* classPath = new char[strlen(bootPath) + strlen(apkPath) + 1];
    strcpy(classPath, bootPath);
    strcat(classPath, apkPath);
    entry = processClassPath(classPath);
    delete[] classPath;
    while (entry->kind != kCpeLastEntry) {
        DvmDex* pDvmDex;
        switch (entry->kind) {
        case kCpeJar:
            {
                JarFile* pJarFile = (JarFile*) entry->ptr;

                pDvmDex = dvmGetJarFileDex(pJarFile);
            }
            break;
        case kCpeDex:
            {
                RawDexFile* pRawDexFile = (RawDexFile*) entry->ptr;

                pDvmDex = dvmGetRawDexFileDex(pRawDexFile);
            }
            break;
        default:
            ALOGE("Unknown kind %d", entry->kind);
            assert(false);
            return;
        }
        loadedDex.push_back(pDvmDex);
        pDvmDex->pDexFile->pClassLookup = dexCreateClassLookup(pDvmDex->pDexFile);
        entry++;
    }
    /*char outFileName[160];
    char* BASE_PATH = getenv("OFFLOAD_PARSE_CACHE");
    if(BASE_PATH == NULL) {
        BASE_PATH = strdup("/data/data");
    }
    strcpy(outFileName, BASE_PATH);
    strcat(outFileName, "/");
    strcat(outFileName, "dict.txt");
    std::ofstream dstfile;
    dstfile.open(outFileName, std::ios::trunc);
    unsigned int clzIdx = 0;*/
    char outFileName[160];
    char* BASE_PATH = getenv("OFFLOAD_PARSE_CACHE");
    if(BASE_PATH == NULL) {
        BASE_PATH = strdup("/data/data");
    }
    strcpy(outFileName, BASE_PATH);
    strcat(outFileName, "/static.txt");
    outputfile.open(outFileName, std::ios::in | std::ios::out | std::ios::trunc);
    char staticpath[160];
    strcpy(staticpath, BASE_PATH);
    strcat(staticpath, "/staticresult.txt");
    std::ofstream staticfile;
    staticfile.open(staticpath, std::ios::out | std::ios::trunc);
    char offsetpath[160];
    strcpy(offsetpath, BASE_PATH);
    strcat(offsetpath, "/offsetresult.txt");
    std::ofstream offsetfile;
    offsetfile.open(offsetpath, std::ios::out | std::ios::trunc);
    for(unsigned int idx = 0; idx < loadedDex.size(); idx++) {
        DvmDex* pDvmDex;
        pDvmDex = loadedDex[idx];
        for(unsigned int i = 0; i < pDvmDex->pHeader->classDefsSize; i++) {
            const DexClassDef pClassDef = pDvmDex->pDexFile->pClassDefs[i];
            ClassObject* resClass;  // this segment is copied from Resolve.cpp - dvmResolveClass()
            const char* className;
            className = dexStringByTypeIdx(pDvmDex->pDexFile, pClassDef.classIdx);
            //(*clazzNameDict)[className] = clzIdx;
            //(*idxClazzNameDict)[clzIdx] = className;
            //dstfile << clzIdx++ << " " << className << endl;
            if(className[0] != '\0' && className[1] == '\0') {
                /* primitive type */
                resClass = dvmFindPrimitiveClass(className[0]);
            } else {
                resClass = customDefineClass(pDvmDex, className, NULL);
                if(strcmp(className, "Ljava/lang/Object;") == 0 && javaLangObject == NULL) {
                    javaLangObject = resClass;
                }
                if(resClass == NULL) {
                    ALOGE("find unloaded class: %s", className);
                    continue;
                }
            }
        }
    }
    
    //for(unsigned int idx = 0; idx < loadedDex.size(); idx++) {
        DvmDex* pDvmDex = loadedDex[loadedDex.size() - 1];
        for(unsigned int i = 0; i < pDvmDex->pHeader->classDefsSize; i++) {
            const DexClassDef pClassDef = pDvmDex->pDexFile->pClassDefs[i];
            ClassObject* resClass;  // this segment is copied from Resolve.cpp - dvmResolveClass()
            const char* className;
            className = dexStringByTypeIdx(pDvmDex->pDexFile, pClassDef.classIdx);
            if(className[0] != '\0' && className[1] == '\0') {
                /* primitive type */
                resClass = dvmFindPrimitiveClass(className[0]);
            } else {
                resClass = dvmLookupClass(className, NULL, false);
            }
            if(resClass == NULL) {
                ALOGE("find unloaded class: %s", className);
                continue;
            }
            // check if it is an interface
            if(dvmIsInterfaceClass(resClass)) {
                continue;
            }
            if(resClass == javaLangObject) {
                continue;
            }
            // traverse and parse every method in the class, see Object.cpp - findMethodInListByDescriptor
            Method* vmethods = resClass->virtualMethods;
            size_t vmethodCount = resClass->virtualMethodCount;
            for(size_t j = 0; j < vmethodCount; j++) {
                Method* method = &vmethods[j];
                if(dvmIsNativeMethod(method)) {
                    continue;
                }
                ALOGE("start parse method: %s:%s, %u", method->clazz->descriptor, method->name, method->idx);
                //std::set<Method*>* chain = new std::set<Method*>();
                //if(strncmp(method->name, "matrixTest", 10) == 0) {
                std::map<ClassObject*, BitsVec*>* methodClzAccInfo = new std::map<ClassObject*, BitsVec*>();
                scanStatic(method, methodClzAccInfo);
                persistResult(&staticfile, &offsetfile, method, methodClzAccInfo);
                freeClazzAccInfoMap(methodClzAccInfo);
                //}
                //delete chain;
            }
            Method* dmethods = resClass->directMethods;
            size_t dmethodCount = resClass->directMethodCount;
            for(size_t j = 0; j < dmethodCount; j++) {
                Method* method = &dmethods[j];
                if(dvmIsNativeMethod(method)) {
                    continue;
                }
                ALOGE("start parse method: %s:%s, %u", method->clazz->descriptor, method->name, method->idx);
                //std::set<Method*>* chain = new std::set<Method*>();
                std::map<ClassObject*, BitsVec*>* methodClzAccInfo = new std::map<ClassObject*, BitsVec*>();
                scanStatic(method, methodClzAccInfo);
                persistResult(&staticfile, &offsetfile, method, methodClzAccInfo);
                freeClazzAccInfoMap(methodClzAccInfo);
                //delete chain;
            }
        }
    //}
    staticfile.close();
    offsetfile.close();
    outputfile.close();
    
    /*char offsetFileName[160];
    strcpy(offsetFileName, BASE_PATH);
    strcat(offsetFileName, "/offset.txt");
    std::ofstream offsetfile;
    offsetfile.open(offsetFileName, std::ios::trunc);
    for (std::map<char*, unsigned int, charscomp>::iterator it = methodClzAccMap->begin(); it != methodClzAccMap->end(); ++it) {
        offsetfile << it->first << std::endl;
        offsetfile << it->second << std::endl;
    }
    offsetfile.close();*/
}

void retrieveOffsetMap(std::map<char*, u4, charscomp>* offsetMap, char* filename) {
    std::ifstream srcfile;
    srcfile.open(filename);
    std::string line;
    while(true) {
        std::getline(srcfile, line);
        if(line.compare("") == 0) {
            break;
        }
        char* methodKey = strdup(line.c_str());
        u4 offset;
        std::getline(srcfile, line);
        converter << line;
        converter >> offset;
        converter.str("");
        converter.clear();
        (*offsetMap)[methodKey] = offset;
    }
    srcfile.close();
}

