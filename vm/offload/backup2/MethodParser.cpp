
#include "Dalvik.h"
#include "libdex/DexCatch.h"

extern std::vector<DvmDex*> loadedDex;
extern ClassObject* javaLangObject;
extern std::vector<ClassObject*>* exemptClzs;
extern std::vector<ClassObject*>* exemptIfs;
std::vector<ObjectAccInfo*>* returnInterests;

// method declaration
void parseInsns(const u2* insns, MethodAccInfo* methodAccInfo, std::vector<Method*>* chain, std::vector<int>* insOffsets, std::map<u2, std::vector<ObjectAccInfo*>* >* interestRegObjMap);

u2 inst_a(const u2* insns) {
    return (*insns >> 8) & 0x0f;
}

u2 inst_b(const u2* insns) {
    return *insns >> 12;
}

u2 inst_aa(const u2* insns) {
    return *insns >> 8;
}

#if __BYTE_ORDER == __LITTLE_ENDIAN
static inline s4 s4FromSwitchData(const void* switchData) {
    return *(s4*) switchData;
}
#else
static inline s4 s4FromSwitchData(const void* switchData) {
    u2* data = switchData;
    return data[0] | (((s4) data[1]) << 16);
}
#endif

Method* resolveMethod(const ClassObject* referrer, u4 methodIdx,
    MethodType methodType) {
    DvmDex* pDvmDex = referrer->pDvmDex;
    ClassObject* resClass;
    const DexMethodId* pMethodId;
    Method* resMethod;

    assert(methodType != METHOD_INTERFACE);

    pMethodId = dexGetMethodId(pDvmDex->pDexFile, methodIdx);

    resClass = dvmResolveClass(referrer, pMethodId->classIdx, false);
    assert(resClass != NULL);

    const char* name = dexStringById(pDvmDex->pDexFile, pMethodId->nameIdx);
    DexProto proto;
    dexProtoSetFromMethodId(&proto, pDvmDex->pDexFile, pMethodId);

    /*
     * We need to chase up the class hierarchy to find methods defined
     * in super-classes.  (We only want to check the current class
     * if we're looking for a constructor; since DIRECT calls are only
     * for constructors and private methods, we don't want to walk up.)
     */
    if (methodType == METHOD_DIRECT) {
        resMethod = dvmFindDirectMethod(resClass, name, &proto);
    } else if (methodType == METHOD_STATIC) {
        resMethod = dvmFindDirectMethodHier(resClass, name, &proto);
    } else {
        resMethod = dvmFindVirtualMethodHier(resClass, name, &proto);
    }

    if(resMethod == NULL) {
        ALOGE("find error method, the name is: %s, resClass is: %s", name, resClass->descriptor);
    }
    dvmDexSetResolvedMethod(pDvmDex, methodIdx, resMethod);
    
    return resMethod;
}

/*
 * Resolve an instance field reference.
 *
 * Returns NULL and throws an exception on error (no such field, illegal
 * access).
 */
InstField* resolveInstField(const ClassObject* referrer, u4 ifieldIdx)
{
    DvmDex* pDvmDex = referrer->pDvmDex;
    ClassObject* resClass;
    const DexFieldId* pFieldId;
    InstField* resField;

    pFieldId = dexGetFieldId(pDvmDex->pDexFile, ifieldIdx);

    /*
     * Find the field's class.
     */
    resClass = dvmResolveClass(referrer, pFieldId->classIdx, false);
    assert(resClass != NULL);

    resField = dvmFindInstanceFieldHier(resClass,
        dexStringById(pDvmDex->pDexFile, pFieldId->nameIdx),
        dexStringByTypeIdx(pDvmDex->pDexFile, pFieldId->typeIdx));
        
    assert(resField != NULL);
    dvmDexSetResolvedField(pDvmDex, ifieldIdx, (Field*)resField);
    
    return resField;
}

/*
 * Resolve a static field reference.  The DexFile format doesn't distinguish
 * between static and instance field references, so the "resolved" pointer
 * in the Dex struct will have the wrong type.  We trivially cast it here.
 *
 * Causes the field's class to be initialized.
 */
StaticField* resolveStaticField(const ClassObject* referrer, u4 sfieldIdx)
{
    DvmDex* pDvmDex = referrer->pDvmDex;
    ClassObject* resClass;
    const DexFieldId* pFieldId;
    StaticField* resField;

    pFieldId = dexGetFieldId(pDvmDex->pDexFile, sfieldIdx);

    /*
     * Find the field's class.
     */
    resClass = dvmResolveClass(referrer, pFieldId->classIdx, false);
    assert(resClass != NULL);

    resField = dvmFindStaticFieldHier(resClass,
                dexStringById(pDvmDex->pDexFile, pFieldId->nameIdx),
                dexStringByTypeIdx(pDvmDex->pDexFile, pFieldId->typeIdx));
    assert(resField != NULL);
    
    dvmDexSetResolvedField(pDvmDex, sfieldIdx, (Field*) resField);
    return resField;
}

void populateMethodAccInfo(MethodAccInfo* methodAccInfo) {
    Method* method = methodAccInfo->method;
    methodAccInfo->args = new std::vector<std::vector<ObjectAccInfo*>* >();
    for(int i = 0; i < method->insSize; i++) {
        methodAccInfo->args->push_back(new std::vector<ObjectAccInfo*>());
        methodAccInfo->args->at(i)->push_back(new ObjectAccInfo());
    }
    methodAccInfo->globalClazz = new std::vector<ClazzAccInfo*>();
}

void cloneInterestMap(std::map<u2, std::vector<ObjectAccInfo*>* >* interestRegObjMap, std::map<u2, std::vector<ObjectAccInfo*>* >* result) {
    for(std::map<u2, std::vector<ObjectAccInfo*>* >::iterator it = interestRegObjMap->begin(); it != interestRegObjMap->end(); it++) {
        std::vector<ObjectAccInfo*>* cloneVec = new std::vector<ObjectAccInfo*>();
        cloneVec->insert(cloneVec->begin(), it->second->begin(), it->second->end());
        (*result)[it->first] = cloneVec;
    }
}

/* check if this object or its parent has been flagged as migrating all */
bool isFlagedAll(ObjectAccInfo* objAccInfo) {
    ObjectAccInfo* tmp = objAccInfo;
    do {
        if(tmp->allFlag) {
            return true;
        }
        tmp = tmp->belonging;
    } while(tmp != NULL);
    return false;
}

/* check if the objects in the vector are all flaged as migrating all */
bool isVecFlagedAll(std::vector<ObjectAccInfo*>* objsVector) {
    for(unsigned int i = 0; i < objsVector->size(); i++) {
        if(!isFlagedAll(objsVector->at(i))) {
            return false;
        }
    }
    return true;
}

/* flag all the objects in vector as migrating all */
void flagVecAll(std::vector<ObjectAccInfo*>* objsVector) {
    for(unsigned int i = 0; i < objsVector->size(); i++) {
        objsVector->at(i)->allFlag = true;
    }
}

/* check if the registers of the method are in our interest */
bool methodHasInterest(u2 vsrc1, u2 vdst, std::map<u2, std::vector<ObjectAccInfo*>* >* interestRegObjMap) {
    u4 count = vsrc1 >> 4;
    u2 reg;
    bool hasInterest = false;
    switch (count) {
    case 5:
        reg = vsrc1 & 0x0f;
        if(interestRegObjMap->find(reg) != interestRegObjMap->end() && !isVecFlagedAll((*interestRegObjMap)[reg])) {
            hasInterest = true;
            break;
        }
    case 4:
        reg = vdst >> 12;
        if(interestRegObjMap->find(reg) != interestRegObjMap->end() && !isVecFlagedAll((*interestRegObjMap)[reg])) {
            hasInterest = true;
            break;
        }
    case 3:
        reg = (vdst & 0x0f00) >> 8;
        if(interestRegObjMap->find(reg) != interestRegObjMap->end() && !isVecFlagedAll((*interestRegObjMap)[reg])) {
            hasInterest = true;
            break;
        }
    case 2:
        reg = (vdst & 0x00f0) >> 4;
        if(interestRegObjMap->find(reg) != interestRegObjMap->end() && !isVecFlagedAll((*interestRegObjMap)[reg])) {
            hasInterest = true;
            break;
        }
    case 1:
        reg = vdst & 0x0f;
        if(interestRegObjMap->find(reg) != interestRegObjMap->end() && !isVecFlagedAll((*interestRegObjMap)[reg])) {
            hasInterest = true;
            break;
        }
    default:
        ;
    }
    return hasInterest;
}

/* flag the interest registers of the method as migrating all */
void methodRegsFlagAll(u2 vsrc1, u2 vdst, std::map<u2, std::vector<ObjectAccInfo*>* >* interestRegObjMap) {
    u4 count = vsrc1 >> 4;
    u2 reg;
    switch (count) {
    case 5:
        reg = vsrc1 & 0x0f;
        if(interestRegObjMap->find(reg) != interestRegObjMap->end()) {
            flagVecAll((*interestRegObjMap)[reg]);
        }
    case 4:
        reg = vdst >> 12;
        if(interestRegObjMap->find(reg) != interestRegObjMap->end()) {
            flagVecAll((*interestRegObjMap)[reg]);
        }
    case 3:
        reg = (vdst & 0x0f00) >> 8;
        if(interestRegObjMap->find(reg) != interestRegObjMap->end()) {
            flagVecAll((*interestRegObjMap)[reg]);
        }
    case 2:
        reg = (vdst & 0x00f0) >> 4;
        if(interestRegObjMap->find(reg) != interestRegObjMap->end()) {
            flagVecAll((*interestRegObjMap)[reg]);
        }
    case 1:
        reg = vdst & 0x0f;
        if(interestRegObjMap->find(reg) != interestRegObjMap->end()) {
            flagVecAll((*interestRegObjMap)[reg]);
        }
    default:
        ;
    }
}

/* populate the args info for the method */
void setupMethodArgs(u2 vsrc1, u2 vdst, std::map<u2, std::vector<ObjectAccInfo*>* >* interestRegObjMap, MethodAccInfo* subAccInfo) {
    u4 count = vsrc1 >> 4;
    u2 reg;
    switch (count) {
    case 5:
        reg = vsrc1 & 0x0f;
        if(interestRegObjMap->find(reg) != interestRegObjMap->end()) {
            subAccInfo->args->insert(subAccInfo->args->begin(), (*interestRegObjMap)[reg]);
        } else {
            subAccInfo->args->insert(subAccInfo->args->begin(), new std::vector<ObjectAccInfo*>());
        }
    case 4:
        reg = vdst >> 12;
        if(interestRegObjMap->find(reg) != interestRegObjMap->end()) {
            subAccInfo->args->insert(subAccInfo->args->begin(), (*interestRegObjMap)[reg]);
        } else {
            subAccInfo->args->insert(subAccInfo->args->begin(), new std::vector<ObjectAccInfo*>());
        }
    case 3:
        reg = (vdst & 0x0f00) >> 8;
        if(interestRegObjMap->find(reg) != interestRegObjMap->end()) {
            subAccInfo->args->insert(subAccInfo->args->begin(), (*interestRegObjMap)[reg]);
        } else {
            subAccInfo->args->insert(subAccInfo->args->begin(), new std::vector<ObjectAccInfo*>());
        }
    case 2:
        reg = (vdst & 0x00f0) >> 4;
        if(interestRegObjMap->find(reg) != interestRegObjMap->end()) {
            subAccInfo->args->insert(subAccInfo->args->begin(), (*interestRegObjMap)[reg]);
        } else {
            subAccInfo->args->insert(subAccInfo->args->begin(), new std::vector<ObjectAccInfo*>());
        }
    case 1:
        reg = vdst & 0x0f;
        if(interestRegObjMap->find(reg) != interestRegObjMap->end()) {
            subAccInfo->args->insert(subAccInfo->args->begin(), (*interestRegObjMap)[reg]);
        } else {
            subAccInfo->args->insert(subAccInfo->args->begin(), new std::vector<ObjectAccInfo*>());
        }
    default:
        ;
    }
}

/* check if the registers of the range method are in our interest */
bool rangeMethodHasInterest(u2 vsrc1, u2 vdst, std::map<u2, std::vector<ObjectAccInfo*>* >* interestRegObjMap) {
    bool hasInterest = false;
    for(int i = 0; i < vsrc1; i++) {
        if(interestRegObjMap->find(vdst + i) != interestRegObjMap->end() && !isVecFlagedAll((*interestRegObjMap)[vdst + i])) {
            hasInterest = true;
            break;
        }
    }
    return hasInterest;
}

/* flag the interest registers of the range method as migrating all */
void rangeMethodRegsFlagAll(u2 vsrc1, u2 vdst, std::map<u2, std::vector<ObjectAccInfo*>* >* interestRegObjMap) {
    for(int i = 0; i < vsrc1; i++) {
        if(interestRegObjMap->find(vdst + i) != interestRegObjMap->end()) {
            flagVecAll((*interestRegObjMap)[vdst + i]);
        }
    }
}


/* populate the args info for the method */
void setupRangeMethodArgs(u2 vsrc1, u2 vdst, std::map<u2, std::vector<ObjectAccInfo*>* >* interestRegObjMap, MethodAccInfo* subAccInfo) {
    for(int i = 0; i < vsrc1; i++) {
        if(interestRegObjMap->find(vdst + i) != interestRegObjMap->end()) {
            subAccInfo->args->push_back((*interestRegObjMap)[vdst + i]);
        } else {
            subAccInfo->args->push_back(new std::vector<ObjectAccInfo*>());
        }
    }
}

void handleCatchBranch(const u2* insns, MethodAccInfo* methodAccInfo, std::vector<Method*>* chain, std::vector<int>* insOffsets, std::map<u2, std::vector<ObjectAccInfo*>* >* interestRegObjMap) {
    Method* method = methodAccInfo->method;
    int relPc = insns - method->insns;
    const DexCode* pCode = dvmGetMethodCode(method);
    DexCatchIterator iterator;

    if (dexFindCatchHandler(&iterator, pCode, relPc)) {
        for (;;) {
            DexCatchHandler* handler = dexCatchIteratorNext(&iterator);

            if (handler == NULL) {
                break;
            }
            int catchOffset = handler->address;
            // check if the switch case will lead to an instruction cycle
            bool isCycle = false;
            for(unsigned int i = 0; i < insOffsets->size(); i++) {
                if(catchOffset == insOffsets->at(i)) {
                    isCycle = true;
                }
            }
            if(!isCycle) {
                // parse the branch taken
                const u2* temp = method->insns;
                temp += catchOffset;
                std::vector<int> tempInsOffsets = *insOffsets;
                std::map<u2, std::vector<ObjectAccInfo*>* > tempInterest = *interestRegObjMap;
//                cloneInterestMap(interestRegObjMap, &tempInterest);
                parseInsns(temp, methodAccInfo, chain, &tempInsOffsets, &tempInterest);
                //free(tempInterest);
            }
        }
    }
}

void parseInsns(const u2* insns, MethodAccInfo* methodAccInfo, std::vector<Method*>* chain, std::vector<int>* insOffsets, std::map<u2, std::vector<ObjectAccInfo*>* >* interestRegObjMap) {
    Method* method = methodAccInfo->method;
    DvmDex* methodClassDex = method->clazz->pDvmDex;
    u2 vsrc1, vdst;
    u4 ref;
    Opcode opcode, lastOpcode = OP_UNUSED_79;
    int width, currentOffset;
    for( ; ; lastOpcode = opcode, insns += width) {
        width = dexGetWidthFromInstruction(insns);
        opcode = dexOpcodeFromCodeUnit(*insns);
        currentOffset = insns - method->insns;
        insOffsets->push_back(currentOffset);
        // each instruction might raise an exception, go to the corresponding handler to process
        handleCatchBranch(insns, methodAccInfo, chain, insOffsets, interestRegObjMap);
        if(opcode == OP_IGET || opcode == OP_IGET_WIDE || opcode == OP_IGET_OBJECT || opcode == OP_IGET_BOOLEAN 
            || opcode == OP_IGET_BYTE || opcode == OP_IGET_CHAR || opcode == OP_IGET_SHORT 
            || opcode == OP_IGET_VOLATILE || opcode == OP_IGET_OBJECT_VOLATILE || opcode == OP_IGET_WIDE_VOLATILE) {
            vdst = inst_a(insns);
            vsrc1 = inst_b(insns);
            // check if the source register is in our interest list
            if(interestRegObjMap->find(vsrc1) == interestRegObjMap->end()) {
                // erase to initiate
                interestRegObjMap->erase(vdst);
                continue;
            }
            ref = insns[1];
            unsigned int offset;
            InstField* ifield = (InstField*) dvmDexGetResolvedField(methodClassDex, ref); 
            //ALOGE("methodParser IIIIIIiget from resolved cached");
            if (ifield == NULL) {        
                //ALOGE("methodParser IIIIIiget from resolve");
                ifield = resolveInstField(method->clazz, ref);
                assert(ifield != NULL);
            }
            offset = ifield->byteOffset >> 2;
            
            // set the field of the object as accessed
            std::vector<ObjectAccInfo*>* accVector = (*interestRegObjMap)[vsrc1];
            for(unsigned int i = 0; i < accVector->size(); i++) {
                ObjectAccInfo* objAccInfo = accVector->at(i);
                assert(objAccInfo != NULL);
                // the current size are not big enough, it means that the field is not set by other instruction and its access is to the field of the object
                if(objAccInfo->trackSet.size() < offset + 1) {
                    // resize the vector to accomodate the offset
                    objAccInfo->fieldSet.resize(offset + 1);
                    objAccInfo->trackSet.resize(offset + 1);
                }
                // if the field has not been setup, then set the field
                if(objAccInfo->trackSet[offset] == NULL) {
                    ObjectAccInfo* fieldInfo = new ObjectAccInfo();
                    fieldInfo->belonging = objAccInfo;
                    objAccInfo->fieldSet[offset] = fieldInfo;
                    objAccInfo->trackSet[offset] = new std::vector<ObjectAccInfo*>();
                    objAccInfo->trackSet[offset]->push_back(objAccInfo->fieldSet[offset]);
                }
                // if the object is already set as migrate all, then ignore it
                if(isVecFlagedAll(objAccInfo->trackSet[offset])) {
                    continue;
                }
                if(opcode == OP_IGET_OBJECT || opcode == OP_IGET_OBJECT_VOLATILE) {
                    if(i == 0) {
                        (*interestRegObjMap)[vdst] = new std::vector<ObjectAccInfo*>();
                    }
                    (*interestRegObjMap)[vdst]->insert((*interestRegObjMap)[vdst]->end(), objAccInfo->trackSet[offset]->begin(), objAccInfo->trackSet[offset]->end());
                } else {
                    // erase to set the result not be interest any more
                    interestRegObjMap->erase(vdst);
                }
            }
        } else if(opcode == OP_IPUT_OBJECT || opcode == OP_IPUT_OBJECT_VOLATILE) { // if the dst is in the interest, the src object's field should also be in interest
            vdst = inst_a(insns);
            vsrc1 = inst_b(insns);   
            ref = insns[1];   
            unsigned int offset;
            InstField* ifield = (InstField*) dvmDexGetResolvedField(methodClassDex, ref); 
            //ALOGE("methodParser IIIIIIiput from resolved cached");
            if (ifield == NULL) {        
                //ALOGE("methodParser IIIIIIiput from resolve");
                ifield = resolveInstField(method->clazz, ref);
                assert(ifield != NULL);
            }
            offset = ifield->byteOffset >> 2;
            
            // both src object and dst are not in our interest
            if(interestRegObjMap->find(vdst) == interestRegObjMap->end() && interestRegObjMap->find(vsrc1) == interestRegObjMap->end()) {
                continue;
            } else if(interestRegObjMap->find(vdst) == interestRegObjMap->end() && interestRegObjMap->find(vsrc1) != interestRegObjMap->end()) { 
                // only src object are in interest, in this case, we set the offset to be an arbitrary one to make sure it will not pollute the original data
                std::vector<ObjectAccInfo*>* srcVector = (*interestRegObjMap)[vsrc1];
                for(unsigned int j = 0; j < srcVector->size(); j++) {
                    ObjectAccInfo* interestAccInfo = srcVector->at(j);
                    if(interestAccInfo->trackSet.size() < offset + 1) {
                        interestAccInfo->fieldSet.resize(offset + 1);
                        interestAccInfo->trackSet.resize(offset + 1);
                    }
                    interestAccInfo->trackSet[offset] = new std::vector<ObjectAccInfo*>();
                }
                continue;
            }
            // the dst register is in our interest
            std::vector<ObjectAccInfo*>* dstVector = (*interestRegObjMap)[vdst];
            if(interestRegObjMap->find(vsrc1) == interestRegObjMap->end()) {
                (*interestRegObjMap)[vsrc1] = new std::vector<ObjectAccInfo*>();
                (*interestRegObjMap)[vsrc1]->push_back(new ObjectAccInfo());
            }
                    
            std::vector<ObjectAccInfo*>* srcVector = (*interestRegObjMap)[vsrc1];
            for(unsigned i = 0; i < srcVector->size(); i++) {
                ObjectAccInfo* interestAccInfo = srcVector->at(i);
                if(interestAccInfo->trackSet.size() < offset + 1) {
                    interestAccInfo->fieldSet.resize(offset + 1);
                    interestAccInfo->trackSet.resize(offset + 1);
                }
                interestAccInfo->trackSet[offset] = dstVector;
            }
        } else if(opcode == OP_SGET_VOLATILE || opcode == OP_SGET_WIDE_VOLATILE || opcode == OP_SGET_OBJECT_VOLATILE
            || opcode == OP_SGET || opcode == OP_SGET_WIDE || opcode == OP_SGET_OBJECT || opcode == OP_SGET_BOOLEAN
            || opcode == OP_SGET_BYTE || opcode == OP_SGET_CHAR || opcode == OP_SGET_SHORT) {
            vdst = inst_a(insns);
            ref = insns[1];
            StaticField* sfield = (StaticField*)dvmDexGetResolvedField(methodClassDex, ref);
            //ALOGE("methodParser SSSSSsget from resolved cached");
            if (sfield == NULL) {
                //ALOGE("methodParser SSSSSsget from resolve");
                sfield = resolveStaticField(method->clazz, ref);
                assert(sfield != NULL);
            }
            unsigned int offset = sfield - sfield->clazz->sfields;
            unsigned int i;
            for(i = 0; i < methodAccInfo->globalClazz->size(); i++) {
                if(sfield->clazz == methodAccInfo->globalClazz->at(i)->clazz) {
                    break;
                }
            }
            if(i == methodAccInfo->globalClazz->size()) { // The first time to deal this global class object
                ClazzAccInfo* clazzAccInfo = new ClazzAccInfo();
                clazzAccInfo->clazz = sfield->clazz;
                methodAccInfo->globalClazz->push_back(clazzAccInfo);
            }
            ClazzAccInfo* clazzAccInfo = methodAccInfo->globalClazz->at(i);
            if(clazzAccInfo->trackSet.size() < offset + 1) { // the current size of trackSet vector are not big enough
                clazzAccInfo->fieldSet.resize(offset + 1);
                clazzAccInfo->trackSet.resize(offset + 1);
            }
            // if the flag has not been setup, then set the flag
            if(clazzAccInfo->trackSet[offset] == NULL) {
                ObjectAccInfo* fieldInfo = new ObjectAccInfo();
                fieldInfo->belonging = clazzAccInfo;
                clazzAccInfo->fieldSet[offset] = fieldInfo;
                clazzAccInfo->trackSet[offset] = new std::vector<ObjectAccInfo*>();
                clazzAccInfo->trackSet[offset]->push_back(clazzAccInfo->fieldSet[offset]);
            }
            // if the object is already set as migrate all, then ignore it
            if(isVecFlagedAll(clazzAccInfo->trackSet[offset])) {
                continue;
            }
            // add the destination register into the interest map
            if(opcode == OP_SGET_OBJECT_VOLATILE || opcode == OP_SGET_OBJECT) {
                (*interestRegObjMap)[vdst] = clazzAccInfo->trackSet[offset];
            } else {
                // erase to set the result not be interest any more
                interestRegObjMap->erase(vdst);
            }
        } else if(opcode == OP_SPUT_OBJECT || opcode == OP_SPUT_OBJECT_VOLATILE) {// if the dst is in the interest, the src class'es field should also be in interest
            vdst = inst_aa(insns);
            ref = insns[1];  
            StaticField* sfield = (StaticField*)dvmDexGetResolvedField(methodClassDex, ref);
            //ALOGE("methodParser SSSSSsput from resolved cached");
            if (sfield == NULL) {
                //ALOGE("methodParser SSSSSsput from resolve");
                sfield = resolveStaticField(method->clazz, ref);
                assert(sfield != NULL);
            }
            unsigned int offset = sfield - sfield->clazz->sfields;
            unsigned int i;
            for(i = 0; i < methodAccInfo->globalClazz->size(); i++) {
                if(sfield->clazz == methodAccInfo->globalClazz->at(i)->clazz) {
                    break;
                }
            }
            if(i == methodAccInfo->globalClazz->size()) { // The first time to deal this global class object
                ClazzAccInfo* clazzAccInfo = new ClazzAccInfo();
                clazzAccInfo->clazz = sfield->clazz;
                methodAccInfo->globalClazz->push_back(clazzAccInfo);
            }
            ClazzAccInfo* clazzAccInfo = methodAccInfo->globalClazz->at(i);
            if(clazzAccInfo->trackSet.size() < offset + 1) { // the current size of trackSet vector are not big enough
                clazzAccInfo->fieldSet.resize(offset + 1);
                clazzAccInfo->trackSet.resize(offset + 1);
            }
            // only src clazz are in interest, in this case, we set the offset to be an arbitrary one to make sure it will not pollute the original data
            if(interestRegObjMap->find(vdst) == interestRegObjMap->end()) {
                clazzAccInfo->trackSet[offset] = new std::vector<ObjectAccInfo*>();
                continue;
            }
            // the src clazz and dst register are both in our interest
            clazzAccInfo->trackSet[offset] = (*interestRegObjMap)[vdst];
        } else if(opcode == OP_MOVE || opcode == OP_MOVE_FROM16 || opcode == OP_MOVE_16
            || opcode == OP_MOVE_WIDE || opcode == OP_MOVE_WIDE_FROM16 || opcode == OP_MOVE_WIDE_16
            || opcode == OP_MOVE_OBJECT || opcode == OP_MOVE_OBJECT_FROM16 || opcode == OP_MOVE_OBJECT_16) {
            if(opcode == OP_MOVE || opcode == OP_MOVE_WIDE || opcode == OP_MOVE_OBJECT) {
                vdst = inst_a(insns);
                vsrc1 = inst_b(insns);
            } else if(opcode == OP_MOVE_FROM16 || opcode == OP_MOVE_WIDE_FROM16 || opcode == OP_MOVE_OBJECT_FROM16) {
                vdst = inst_aa(insns);
                vsrc1 = insns[1];
            } else if(opcode == OP_MOVE_16 || opcode == OP_MOVE_WIDE_16 || opcode == OP_MOVE_OBJECT_16) {
                vdst = insns[1];
                vsrc1 = insns[2];
            }
            // check if the source register is in our interest list
            if(interestRegObjMap->find(vsrc1) == interestRegObjMap->end()) {
                // this attribute is not our interest, remove dst register from interest list
                interestRegObjMap->erase(vdst);
            } else {
                // add the destination register into the interest map
                (*interestRegObjMap)[vdst] = (*interestRegObjMap)[vsrc1];
            }
        } else if(opcode == OP_INVOKE_VIRTUAL || opcode == OP_INVOKE_VIRTUAL_RANGE) {
            vsrc1 = inst_aa(insns);      // AA (count) or BA (count + arg 5) 
            ref = insns[1];             // method ref 
            vdst = insns[2];            // 4 regs -or- first reg
            
            // check if the method invocation involves interesting registers
            bool hasInterest;
            if(opcode == OP_INVOKE_VIRTUAL) {
                hasInterest = methodHasInterest(vsrc1, vdst, interestRegObjMap);
            } else {
                hasInterest = rangeMethodHasInterest(vsrc1, vdst, interestRegObjMap);
            }
            if(!hasInterest) {
                continue;
            }
            
            int voffset;
            Method* baseMethod;
            baseMethod = dvmDexGetResolvedMethod(methodClassDex, ref);
            if (baseMethod == NULL) {
                baseMethod = resolveMethod(method->clazz, ref, METHOD_VIRTUAL);
                if(baseMethod == NULL) { // we should have encountered a wrong version method branch
                    return;
                }
            }
            bool isLangObjectClass = baseMethod->clazz == javaLangObject;
            bool isExempt = false;
            for(unsigned int idx = 0; idx < exemptClzs->size(); idx++) {
                if(baseMethod->clazz == exemptClzs->at(idx)) {
                    isExempt = true;
                    break;
                }
            }
            if(isLangObjectClass || isExempt) {
                if(opcode == OP_INVOKE_VIRTUAL) {
                    methodRegsFlagAll(vsrc1, vdst, interestRegObjMap);
                } else {
                    rangeMethodRegsFlagAll(vsrc1, vdst, interestRegObjMap);
                }
                continue;
            }
            //ALOGE("methodParser parse virtual %s.%s", baseMethod->clazz->descriptor, baseMethod->name);
            voffset = baseMethod->methodIndex;
            std::vector<ClassObject*> subclasses;
            findSubClass(baseMethod->clazz, &subclasses);
            // use this vector to store the method which have been parsed since it seems that the method which is not overriden by its subclass will have the same reference
            std::vector<Method*> parsedMethod;
            
            for(unsigned int idx = 0; idx < subclasses.size(); idx++) {
                Method* methodToCall = subclasses[idx]->vtable[voffset];
                assert(methodToCall != NULL);
                bool isCycle = false;
                // check if this method makes an invocation cycle, if true, then set all the parameters as need to be migrate all
                for(unsigned int cidx = 0; cidx < chain->size(); cidx++) {
                    if(methodToCall == chain->at(cidx)) {
                    //ALOGE("methodParser find virtual cycle, methodToCall: %p, name: %s.%s, chain method: %p, name: %s.%s", methodToCall, methodToCall->clazz->descriptor, methodToCall->name, chain->at(cidx), chain->at(cidx)->clazz->descriptor, chain->at(cidx)->name);
                        isCycle = true;
                        break;                    
                    }
                }
                if(isCycle) {
                    if(opcode == OP_INVOKE_VIRTUAL) {
                        methodRegsFlagAll(vsrc1, vdst, interestRegObjMap);
                    } else {
                        rangeMethodRegsFlagAll(vsrc1, vdst, interestRegObjMap);
                    }
                    continue;
                }
                bool alreadyParsed = false;
                for(unsigned int i = 0; i < parsedMethod.size(); i++) {
                    if(methodToCall == parsedMethod[i]) {
                        alreadyParsed = true;
                        break;
                    }
                }
                if(alreadyParsed) {
                    continue;
                } else {
                    parsedMethod.push_back(methodToCall);
                }
                // setup subcall method access info and parse
                MethodAccInfo* subAccInfo = new MethodAccInfo();
                subAccInfo->method = methodToCall;
                subAccInfo->globalClazz = methodAccInfo->globalClazz;
                subAccInfo->args = new std::vector<std::vector<ObjectAccInfo*>* >();
                if(opcode == OP_INVOKE_VIRTUAL) {
                    setupMethodArgs(vsrc1, vdst, interestRegObjMap, subAccInfo);
                } else {
                    setupRangeMethodArgs(vsrc1, vdst, interestRegObjMap, subAccInfo);
                }
                
                chain->push_back(methodToCall);
                parseMethod(subAccInfo, chain);
                if(subAccInfo->returnObjs != NULL) {
                    if(returnInterests == NULL) {
                        returnInterests = subAccInfo->returnObjs;
                    } else {
                        returnInterests->insert(returnInterests->end(), subAccInfo->returnObjs->begin(), subAccInfo->returnObjs->end());
                        free(subAccInfo->returnObjs);
                    }
                }
                free(subAccInfo->args);
                free(subAccInfo);
            }
        } else if(opcode == OP_INVOKE_INTERFACE || opcode == OP_INVOKE_INTERFACE_RANGE) { // see Interp.cpp-dvmInterpFindInterfaceMethod
            vsrc1 = inst_aa(insns);      // AA (count) or BA (count + arg 5) 
            ref = insns[1];             // method ref 
            vdst = insns[2];            // 4 regs -or- first reg
            
            // check if the method invocation involves interesting registers
            bool hasInterest;
            if(opcode == OP_INVOKE_INTERFACE) {
                hasInterest = methodHasInterest(vsrc1, vdst, interestRegObjMap);
            } else {
                hasInterest = rangeMethodHasInterest(vsrc1, vdst, interestRegObjMap);
            }
            if(!hasInterest) {
                continue;
            }
            
            Method* absMethod;
            absMethod = dvmDexGetResolvedMethod(methodClassDex, ref);
            if (absMethod == NULL) {
                absMethod = dvmResolveInterfaceMethod(method->clazz, ref);
                assert(absMethod != NULL);
            }
            assert(dvmIsAbstractMethod(absMethod));
            bool isExempt = false;
            for(unsigned int idx = 0; idx < exemptIfs->size(); idx++) {
                if(absMethod->clazz == exemptIfs->at(idx)) {
                    isExempt = true;
                    break;
                }
            }
            if(isExempt) {
                if(opcode == OP_INVOKE_INTERFACE) {
                    methodRegsFlagAll(vsrc1, vdst, interestRegObjMap);
                } else {
                    rangeMethodRegsFlagAll(vsrc1, vdst, interestRegObjMap);
                }
                continue;
            }
            //ALOGE("methodParser parse interface %s.%s", absMethod->clazz->descriptor, absMethod->name);
            std::vector<ClassObject*> implclasses;
            findImplementClass(absMethod->clazz, &implclasses);
            // use this vector to store the method which have been parsed since it seems that the method which is not overriden by its subclass will have the same reference
            std::vector<Method*> parsedMethod;
            
            for(unsigned int idx = 0; idx < implclasses.size(); idx++) {
                Method* methodToCall;
                int ifIdx;
                for (ifIdx = 0; ifIdx < implclasses[idx]->iftableCount; ifIdx++) {
                    if (implclasses[idx]->iftable[ifIdx].clazz == absMethod->clazz) {
                        break;
                    }
                } 
                int vtableIndex = implclasses[idx]->iftable[ifIdx].methodIndexArray[absMethod->methodIndex];
                methodToCall = implclasses[idx]->vtable[vtableIndex];
                assert(methodToCall != NULL);
                bool isCycle = false;
                // check if this method makes an invocation cycle, if true, then set all the parameters as need to be migrate all
                for(unsigned int idx = 0; idx < chain->size(); idx++) {
                    if(methodToCall == chain->at(idx)) {
                    //ALOGE("methodParser find interface cycle, methodToCall: %p, name: %s.%s, chain method: %p, name: %s.%s", methodToCall, methodToCall->clazz->descriptor, methodToCall->name, chain->at(idx), chain->at(idx)->clazz->descriptor, chain->at(idx)->name);
                        isCycle = true;
                        break;                    
                    }
                }
                if(isCycle) {
                    if(opcode == OP_INVOKE_INTERFACE) {
                        methodRegsFlagAll(vsrc1, vdst, interestRegObjMap);
                    } else {
                        rangeMethodRegsFlagAll(vsrc1, vdst, interestRegObjMap);
                    }
                    continue;
                }
                bool alreadyParsed = false;
                for(unsigned int i = 0; i < parsedMethod.size(); i++) {
                    if(methodToCall == parsedMethod[i]) {
                        alreadyParsed = true;
                        break;
                    }
                }
                if(alreadyParsed) {
                    continue;
                } else {
                    parsedMethod.push_back(methodToCall);
                }
                // setup subcall method access info and parse
                MethodAccInfo* subAccInfo = new MethodAccInfo();
                subAccInfo->method = methodToCall;
                subAccInfo->globalClazz = methodAccInfo->globalClazz;
                subAccInfo->args = new std::vector<std::vector<ObjectAccInfo*>* >();
                if(opcode == OP_INVOKE_INTERFACE) {
                    setupMethodArgs(vsrc1, vdst, interestRegObjMap, subAccInfo);
                } else {
                    setupRangeMethodArgs(vsrc1, vdst, interestRegObjMap, subAccInfo);
                }
                
                chain->push_back(methodToCall);
                parseMethod(subAccInfo, chain);
                if(subAccInfo->returnObjs != NULL) {
                    if(returnInterests == NULL) {
                        returnInterests = subAccInfo->returnObjs;
                    } else {
                        returnInterests->insert(returnInterests->end(), subAccInfo->returnObjs->begin(), subAccInfo->returnObjs->end());
                        free(subAccInfo->returnObjs);
                    }
                }
                free(subAccInfo->args);
                free(subAccInfo);
            }
        } else if(opcode == OP_INVOKE_SUPER || opcode == OP_INVOKE_DIRECT || opcode == OP_INVOKE_STATIC 
            || opcode == OP_INVOKE_SUPER_RANGE || opcode == OP_INVOKE_DIRECT_RANGE || opcode == OP_INVOKE_STATIC_RANGE) {
            vsrc1 = inst_aa(insns);      // AA (count) or BA (count + arg 5) 
            ref = insns[1];             // method ref 
            vdst = insns[2];            // 4 regs -or- first reg
            
            // check if the method invocation involves interesting registers
            bool hasInterest;
            if(opcode == OP_INVOKE_SUPER || opcode == OP_INVOKE_DIRECT || opcode == OP_INVOKE_STATIC) {
                hasInterest = methodHasInterest(vsrc1, vdst, interestRegObjMap);
            } else {
                hasInterest = rangeMethodHasInterest(vsrc1, vdst, interestRegObjMap);
            }
            if(!hasInterest) {
                continue;
            }
            
            Method* methodToCall;
            if(opcode == OP_INVOKE_SUPER || opcode == OP_INVOKE_SUPER_RANGE) {
                Method* baseMethod;
                baseMethod = dvmDexGetResolvedMethod(methodClassDex, ref);
                if (baseMethod == NULL) {
                    baseMethod = resolveMethod(method->clazz, ref, METHOD_VIRTUAL);
                    if(baseMethod == NULL) { // we should have encountered a wrong version method branch
                        return;
                    }
                }
                assert(baseMethod->methodIndex < method->clazz->super->vtableCount);
                methodToCall = method->clazz->super->vtable[baseMethod->methodIndex];
            } else if(opcode == OP_INVOKE_DIRECT || opcode == OP_INVOKE_DIRECT_RANGE) {
                methodToCall = dvmDexGetResolvedMethod(methodClassDex, ref);
                if (methodToCall == NULL) {
                    methodToCall = resolveMethod(method->clazz, ref, METHOD_DIRECT);
                }
            } else {
                methodToCall = dvmDexGetResolvedMethod(methodClassDex, ref);
                if (methodToCall == NULL) {
                    methodToCall = resolveMethod(method->clazz, ref, METHOD_STATIC);
                }
            } 
            if(methodToCall == NULL) { // we should have encountered a wrong version method branch
                return;
            }
            bool isCycle = false;
            // check if this method makes an invocation cycle, if true, then set all the parameters as need to be migrate all
            for(unsigned int idx = 0; idx < chain->size(); idx++) {
                if(methodToCall == chain->at(idx)) {
                    //ALOGE("methodParser find cycle, methodToCall: %p, name: %s.%s, chain method: %p, name: %s.%s", methodToCall, methodToCall->clazz->descriptor, methodToCall->name, chain->at(idx), chain->at(idx)->clazz->descriptor, chain->at(idx)->name);
                    isCycle = true;
                    break;                    
                }
            }
            if(isCycle) {
                if(opcode == OP_INVOKE_SUPER || opcode == OP_INVOKE_DIRECT || opcode == OP_INVOKE_STATIC) {
                    methodRegsFlagAll(vsrc1, vdst, interestRegObjMap);
                } else {
                    rangeMethodRegsFlagAll(vsrc1, vdst, interestRegObjMap);
                }
                continue;
            }
            //ALOGE("methodParser parse superdirectstatic %s.%s", methodToCall->clazz->descriptor, methodToCall->name);
            // setup subcall method access info and parse
            MethodAccInfo* subAccInfo = new MethodAccInfo();
            subAccInfo->method = methodToCall;
            subAccInfo->globalClazz = methodAccInfo->globalClazz;
            subAccInfo->args = new std::vector<std::vector<ObjectAccInfo*>* >();
            if(opcode == OP_INVOKE_SUPER || opcode == OP_INVOKE_DIRECT || opcode == OP_INVOKE_STATIC) {
                setupMethodArgs(vsrc1, vdst, interestRegObjMap, subAccInfo);
            } else {
                setupRangeMethodArgs(vsrc1, vdst, interestRegObjMap, subAccInfo);
            }
                
            chain->push_back(methodToCall);
            parseMethod(subAccInfo, chain);
            returnInterests = subAccInfo->returnObjs;
            free(subAccInfo->args);
            free(subAccInfo);
        } else if(opcode == OP_MOVE_RESULT || opcode == OP_MOVE_RESULT_WIDE || opcode == OP_MOVE_EXCEPTION) {
            vdst = inst_aa(insns);
            interestRegObjMap->erase(vdst);
            if(returnInterests != NULL) {
                free(returnInterests);
                returnInterests = NULL;
            }
        } else if(opcode == OP_MOVE_RESULT_OBJECT) {
            vdst = inst_aa(insns);
            // we only process the move result of a method
            if(lastOpcode == OP_FILLED_NEW_ARRAY || lastOpcode == OP_FILLED_NEW_ARRAY_RANGE) {
                // in this case, we erase the destination register from the interest interest because we have flagged the object it include as all
                interestRegObjMap->erase(vdst);
                continue;
            }
            if(returnInterests != NULL) {
                (*interestRegObjMap)[vdst] = returnInterests;
                returnInterests = NULL;
            } else {
                interestRegObjMap->erase(vdst);
            }
        } else if(opcode == OP_RETURN_VOID || opcode == OP_RETURN || opcode == OP_RETURN_WIDE) {
            // stop the current branch of parsing instruction stream
            return;
        } else if(opcode == OP_RETURN_OBJECT) {
            vsrc1 = inst_aa(insns);
            if(interestRegObjMap->find(vsrc1) != interestRegObjMap->end()) {
                if(methodAccInfo->returnObjs == NULL) {
                    methodAccInfo->returnObjs = new std::vector<ObjectAccInfo*>();
                }
                methodAccInfo->returnObjs->insert(methodAccInfo->returnObjs->end(), (*interestRegObjMap)[vsrc1]->begin(), (*interestRegObjMap)[vsrc1]->end());
            }
            // stop the current branch of parsing instruction stream
            return;
        } else if(opcode == OP_IF_EQ || opcode == OP_IF_NE || opcode == OP_IF_LT
            || opcode == OP_IF_GE || opcode == OP_IF_GT || opcode == OP_IF_LE
            || opcode == OP_IF_EQZ || opcode == OP_IF_NEZ || opcode == OP_IF_LTZ
            || opcode == OP_IF_GEZ || opcode == OP_IF_GTZ || opcode == OP_IF_LEZ) {
            int branchOffset = (s2)insns[1];
            // check if the branch will lead to an instruction cycle
            bool isCycle = false;
            int newOffset = currentOffset + branchOffset;
            for(unsigned int i = 0; i < insOffsets->size(); i++) {
                if(newOffset == insOffsets->at(i)) {
                    isCycle = true;
                }
            }
            if(!isCycle) {
                // parse the branch taken
                const u2* temp = insns;
                temp += branchOffset;
                std::vector<int> tempInsOffsets = *insOffsets;
                std::map<u2, std::vector<ObjectAccInfo*>* > tempInterest = *interestRegObjMap;
                //cloneInterestMap(interestRegObjMap, &tempInterest);
                parseInsns(temp, methodAccInfo, chain, &tempInsOffsets, &tempInterest);
                //free(tempInterest);
            }
            
            // the continuation of the loop will parse the branch not taken
        } else if(opcode == OP_GOTO) {
            vdst = inst_aa(insns);
            width = (s1)vdst;
            // check if the goto will lead to an instruction cycle
            bool isCycle = false;
            int newOffset = currentOffset + width;
            for(unsigned int i = 0; i < insOffsets->size(); i++) {
                if(newOffset == insOffsets->at(i)) {
                    isCycle = true;
                }
            }
            if(isCycle) {
                return;
            }
        } else if(opcode == OP_GOTO_16) {
            s4 offset = (s2) insns[1];
            width = offset;
            // check if the goto will lead to an instruction cycle
            bool isCycle = false;
            int newOffset = currentOffset + width;
            for(unsigned int i = 0; i < insOffsets->size(); i++) {
                if(newOffset == insOffsets->at(i)) {
                    isCycle = true;
                }
            }
            if(isCycle) {
                return;
            }
        } else if(opcode == OP_GOTO_32) {
            s4 offset = insns[1];               // low-order 16 bits
            offset |= ((s4) insns[2]) << 16;    // high-order 16 bits
            width = offset;
            // check if the goto will lead to an instruction cycle
            bool isCycle = false;
            int newOffset = currentOffset + width;
            for(unsigned int i = 0; i < insOffsets->size(); i++) {
                if(newOffset == insOffsets->at(i)) {
                    isCycle = true;
                }
            }
            if(isCycle) {
                return;
            }
        } else if(opcode == OP_PACKED_SWITCH || opcode == OP_SPARSE_SWITCH) {
            s4 offset;
            offset = insns[1] | (((s4) insns[2]) << 16);
            const u2* switchData = insns + offset;       // offset in 16-bit units
            u2 size;
            const s4* entries;

            /*
             * Packed switch data format:
             *  ushort ident = 0x0100 or ident = 0x0200  magic value
             *  ushort size             number of entries in the table
             *  int first_key or int keys[size]          first (and lowest) switch case value
             *  int targets[size]       branch targets, relative to switch opcode
             *
             * Total size is (4+size*2) or (2+size*4) 16-bit code units.
             */
            switchData++; // this is the space the magic value takes
            size = *switchData++;
            assert(size > 0);
            
            if(opcode == OP_PACKED_SWITCH) {
                switchData += 2; // this is the space the first key takes
            } else {
                switchData += 2 * size; // this is the space the keys take
            }

            /* The entries are guaranteed to be aligned on a 32-bit boundary;
             * we can treat them as a native int array.
             */
            entries = (const s4*) switchData;
            assert(((u4)entries & 0x3) == 0);
            for(int idx = 0; idx < size; idx++) {
                s4 offset = s4FromSwitchData(&entries[idx]);
                // check if the switch case will lead to an instruction cycle
                bool isCycle = false;
                int newOffset = currentOffset + offset;
                for(unsigned int i = 0; i < insOffsets->size(); i++) {
                    if(newOffset == insOffsets->at(i)) {
                        isCycle = true;
                    }
                }
                if(!isCycle) {
                    // parse the branch taken
                    const u2* temp = insns;
                    temp += offset;
                    std::vector<int> tempInsOffsets = *insOffsets;
                    std::map<u2, std::vector<ObjectAccInfo*>* > tempInterest = *interestRegObjMap;
                    //cloneInterestMap(interestRegObjMap, &tempInterest);
                    parseInsns(temp, methodAccInfo, chain, &tempInsOffsets, &tempInterest);
                    //free(tempInterest);
                }
            }
        } else if(opcode == OP_INSTANCE_OF || opcode == OP_NEW_ARRAY || opcode == OP_CONST_4 || opcode == OP_NEG_INT || opcode == OP_NOT_INT
            || opcode == OP_NEG_LONG || opcode == OP_NOT_LONG || opcode == OP_NEG_FLOAT
            || opcode == OP_NEG_DOUBLE || opcode == OP_INT_TO_LONG || opcode == OP_INT_TO_FLOAT
            || opcode == OP_INT_TO_DOUBLE || opcode == OP_LONG_TO_INT || opcode == OP_LONG_TO_FLOAT
            || opcode == OP_LONG_TO_DOUBLE || opcode == OP_FLOAT_TO_INT || opcode == OP_FLOAT_TO_LONG
            || opcode == OP_FLOAT_TO_DOUBLE || opcode == OP_DOUBLE_TO_INT || opcode == OP_DOUBLE_TO_LONG
            || opcode == OP_DOUBLE_TO_FLOAT || opcode == OP_INT_TO_BYTE || opcode == OP_INT_TO_CHAR
            || opcode == OP_INT_TO_SHORT || opcode == OP_ADD_INT_2ADDR || opcode == OP_SUB_INT_2ADDR
            || opcode == OP_MUL_INT_2ADDR || opcode == OP_DIV_INT_2ADDR || opcode == OP_REM_INT_2ADDR
            || opcode == OP_AND_INT_2ADDR || opcode == OP_OR_INT_2ADDR || opcode == OP_XOR_INT_2ADDR
            || opcode == OP_SHL_INT_2ADDR || opcode == OP_SHR_INT_2ADDR || opcode == OP_USHR_INT_2ADDR
            || opcode == OP_ADD_LONG_2ADDR || opcode == OP_SUB_LONG_2ADDR || opcode == OP_MUL_LONG_2ADDR
            || opcode == OP_DIV_LONG_2ADDR || opcode == OP_REM_LONG_2ADDR || opcode == OP_AND_LONG_2ADDR
            || opcode == OP_OR_LONG_2ADDR || opcode == OP_XOR_LONG_2ADDR || opcode == OP_SHL_LONG_2ADDR
            || opcode == OP_SHR_LONG_2ADDR || opcode == OP_USHR_LONG_2ADDR || opcode == OP_ADD_FLOAT_2ADDR
            || opcode == OP_SUB_FLOAT_2ADDR || opcode == OP_MUL_FLOAT_2ADDR || opcode == OP_DIV_FLOAT_2ADDR
            || opcode == OP_REM_FLOAT_2ADDR || opcode == OP_ADD_DOUBLE_2ADDR|| opcode == OP_SUB_DOUBLE_2ADDR
            || opcode == OP_MUL_DOUBLE_2ADDR || opcode == OP_DIV_DOUBLE_2ADDR || opcode == OP_REM_DOUBLE_2ADDR
            || opcode == OP_ADD_INT_LIT16 || opcode == OP_RSUB_INT || opcode == OP_MUL_INT_LIT16
            || opcode == OP_DIV_INT_LIT16 || opcode == OP_REM_INT_LIT16 || opcode == OP_AND_INT_LIT16
            || opcode == OP_OR_INT_LIT16 || opcode == OP_XOR_INT_LIT16) {
            vdst = inst_a(insns);
            interestRegObjMap->erase(vdst);
        } else if(opcode == OP_CONST_16 || opcode == OP_CONST || opcode == OP_CONST_HIGH16
            || opcode == OP_CONST_WIDE_16 || opcode == OP_CONST_WIDE_32 || opcode == OP_CONST_WIDE
            || opcode == OP_CONST_WIDE_HIGH16 || opcode == OP_CONST_STRING || opcode == OP_CONST_STRING_JUMBO
            || opcode == OP_NEW_INSTANCE || opcode == OP_CMPL_FLOAT || opcode == OP_CMPG_FLOAT
            || opcode == OP_CMPL_DOUBLE || opcode == OP_CMPG_DOUBLE || opcode == OP_CMP_LONG
            || opcode == OP_ADD_INT || opcode == OP_SUB_INT || opcode == OP_MUL_INT
            || opcode == OP_DIV_INT || opcode == OP_REM_INT || opcode == OP_AND_INT
            || opcode == OP_OR_INT || opcode == OP_XOR_INT || opcode == OP_SHL_INT
            || opcode == OP_SHR_INT || opcode == OP_USHR_INT || opcode == OP_ADD_LONG
            || opcode == OP_SUB_LONG || opcode == OP_MUL_LONG || opcode == OP_DIV_LONG
            || opcode == OP_REM_LONG || opcode == OP_AND_LONG || opcode == OP_OR_LONG
            || opcode == OP_XOR_LONG || opcode == OP_SHL_LONG || opcode == OP_SHR_LONG
            || opcode == OP_USHR_LONG || opcode == OP_ADD_FLOAT || opcode == OP_SUB_FLOAT
            || opcode == OP_MUL_FLOAT || opcode == OP_DIV_FLOAT || opcode == OP_REM_FLOAT
            || opcode == OP_ADD_DOUBLE || opcode == OP_SUB_DOUBLE || opcode == OP_MUL_DOUBLE
            || opcode == OP_DIV_DOUBLE || opcode == OP_REM_DOUBLE || opcode == OP_ADD_INT_LIT8
            || opcode == OP_RSUB_INT_LIT8 || opcode == OP_MUL_INT_LIT8 || opcode == OP_DIV_INT_LIT8
            || opcode == OP_REM_INT_LIT8 || opcode == OP_AND_INT_LIT8 || opcode == OP_OR_INT_LIT8
            || opcode == OP_XOR_INT_LIT8 || opcode == OP_SHL_INT_LIT8 || opcode == OP_SHR_INT_LIT8
            || opcode == OP_USHR_INT_LIT8) {
            vdst = inst_aa(insns);
            interestRegObjMap->erase(vdst);
        } else if(opcode == OP_THROW) {
            return;
        } else if(opcode == OP_CONST_CLASS) {
            // TODO: check if need to to any operation
            vdst = inst_aa(insns);
            interestRegObjMap->erase(vdst);
        } else if(opcode == OP_MONITOR_ENTER || opcode == OP_MONITOR_EXIT) {
            // set the lock of the object as need to be migrated
            vsrc1 = inst_aa(insns);
            // check if the source register is in our interest list
            if(interestRegObjMap->find(vsrc1) == interestRegObjMap->end()) {
                continue;
            }
            // for comet code, this offset is 3 since it has added two more fields before lock field, or it is 1
            unsigned int offset = 3;
                        
            // set the field of the object as accessed
            std::vector<ObjectAccInfo*>* accVector = (*interestRegObjMap)[vsrc1];
            for(unsigned int i = 0; i < accVector->size(); i++) {
                ObjectAccInfo* objAccInfo = accVector->at(i);
                assert(objAccInfo != NULL);
                // the current size are not big enough, it means that the field is not set by other instruction and its access is to the field of the object
                if(objAccInfo->trackSet.size() < offset + 1) {
                    // resize the vector to accomodate the offset
                    objAccInfo->fieldSet.resize(offset + 1);
                    objAccInfo->trackSet.resize(offset + 1);
                }
                // if the field has not been setup, then set the field
                if(objAccInfo->trackSet[offset] == NULL) {
                    ObjectAccInfo* fieldInfo = new ObjectAccInfo();
                    fieldInfo->belonging = objAccInfo;
                    objAccInfo->fieldSet[offset] = fieldInfo;
                    objAccInfo->trackSet[offset] = new std::vector<ObjectAccInfo*>();
                    objAccInfo->trackSet[offset]->push_back(objAccInfo->fieldSet[offset]);
                }
                // if the object is already set as migrate all, then ignore it
                if(isVecFlagedAll(objAccInfo->trackSet[offset])) {
                    continue;
                }
            }
        } else if(opcode == OP_CHECK_CAST || opcode == OP_FILL_ARRAY_DATA
            || opcode == OP_UNUSED_3E || opcode == OP_UNUSED_3F || opcode == OP_UNUSED_40
            || opcode == OP_UNUSED_41 || opcode == OP_UNUSED_42 || opcode == OP_UNUSED_43
            || opcode == OP_UNUSED_73 || opcode == OP_UNUSED_79 || opcode == OP_UNUSED_7A) {
            // do nothing
        } else if(opcode == OP_ARRAY_LENGTH)  {
            vdst = inst_a(insns);
            vsrc1 = inst_b(insns);
            // check if the source register is in our interest list
            if(interestRegObjMap->find(vsrc1) == interestRegObjMap->end()) {
                continue;
            }
            // for comet code, this offset is 4 since it has added two more fields in Object struct, or it is 2
            unsigned int offset = 4;
                        
            // set the field of the object as accessed
            std::vector<ObjectAccInfo*>* accVector = (*interestRegObjMap)[vsrc1];
            for(unsigned int i = 0; i < accVector->size(); i++) {
                ObjectAccInfo* objAccInfo = accVector->at(i);
                assert(objAccInfo != NULL);
                // the current size are not big enough, it means that the field is not set by other instruction and its access is to the field of the object
                if(objAccInfo->trackSet.size() < offset + 1) {
                    // resize the vector to accomodate the offset
                    objAccInfo->fieldSet.resize(offset + 1);
                    objAccInfo->trackSet.resize(offset + 1);
                }
                // if the field has not been setup, then set the field
                if(objAccInfo->trackSet[offset] == NULL) {
                    ObjectAccInfo* fieldInfo = new ObjectAccInfo();
                    fieldInfo->belonging = objAccInfo;
                    objAccInfo->fieldSet[offset] = fieldInfo;
                    objAccInfo->trackSet[offset] = new std::vector<ObjectAccInfo*>();
                    objAccInfo->trackSet[offset]->push_back(objAccInfo->fieldSet[offset]);
                }
            }
            // erase to set the result not be interest any more
            interestRegObjMap->erase(vdst);
        } else if(opcode == OP_FILLED_NEW_ARRAY || opcode == OP_FILLED_NEW_ARRAY_RANGE) {
            u4 arg5;
            //ref = insns[1];             // class ref
            vdst = insns[2];            // first 4 regs -or- range base

            if (opcode == OP_FILLED_NEW_ARRAY_RANGE) {
                vsrc1 = inst_aa(insns);  // #of elements 
                arg5 = -1;              // silence compiler warning
            } else {
                arg5 = inst_a(insns);
                vsrc1 = inst_b(insns);   // #of elements
            }
            if (opcode == OP_FILLED_NEW_ARRAY_RANGE) {
                for (int i = 0; i < vsrc1; i++) {
                    if(interestRegObjMap->find(vdst + i) != interestRegObjMap->end()) {
                        flagVecAll((*interestRegObjMap)[vdst + i]);
                    }
                }
            } else {
                assert(vsrc1 <= 5);
                if (vsrc1 == 5) {
                    if(interestRegObjMap->find(arg5) != interestRegObjMap->end()) {
                        flagVecAll((*interestRegObjMap)[arg5]);
                    }
                    vsrc1--;
                }
                for (int i = 0; i < vsrc1; i++) {
                    if(interestRegObjMap->find(vdst & 0x0f) != interestRegObjMap->end()) {
                        flagVecAll((*interestRegObjMap)[vdst & 0x0f]);
                    }
                    vdst >>= 4;
                }
            }
        } else if(opcode == OP_AGET || opcode == OP_AGET_WIDE || opcode == OP_AGET_OBJECT
            || opcode == OP_AGET_BOOLEAN || opcode == OP_AGET_BYTE || opcode == OP_AGET_CHAR
            || opcode == OP_AGET_SHORT) {
            u2 arrayInfo = insns[1];
            //vdst = inst_aa(insns);
            vsrc1 = arrayInfo & 0xff;
            if(interestRegObjMap->find(vsrc1) != interestRegObjMap->end()) {
                flagVecAll((*interestRegObjMap)[vsrc1]);
            }
            interestRegObjMap->erase(vdst);
        } else if(opcode == OP_APUT_OBJECT) {
            u2 arrayInfo = insns[1];
            vdst = inst_aa(insns);
            vsrc1 = arrayInfo & 0xff;
            if(interestRegObjMap->find(vdst) != interestRegObjMap->end()) {
                // if array register is not in the interest list, add it
                if(interestRegObjMap->find(vsrc1) == interestRegObjMap->end()) {
                    (*interestRegObjMap)[vsrc1] = new std::vector<ObjectAccInfo*>();
                }
                (*interestRegObjMap)[vsrc1]->insert((*interestRegObjMap)[vsrc1]->end(), (*interestRegObjMap)[vdst]->begin(), (*interestRegObjMap)[vdst]->end());
            }
        } else if(opcode == OP_IPUT || opcode == OP_IPUT_WIDE || opcode == OP_IPUT_BOOLEAN 
            || opcode == OP_IPUT_BYTE || opcode == OP_IPUT_CHAR || opcode == OP_IPUT_SHORT 
            || opcode == OP_IPUT_VOLATILE || opcode == OP_IPUT_WIDE_VOLATILE
            || opcode == OP_SPUT_VOLATILE || opcode == OP_SPUT_WIDE_VOLATILE
            || opcode == OP_SPUT || opcode == OP_SPUT_WIDE || opcode == OP_SPUT_BOOLEAN
            || opcode == OP_SPUT_BYTE || opcode == OP_SPUT_CHAR || opcode == OP_SPUT_SHORT
            || opcode == OP_APUT || opcode == OP_APUT_WIDE || opcode == OP_APUT_BOOLEAN
            || opcode == OP_APUT_BYTE || opcode == OP_APUT_CHAR || opcode == OP_APUT_SHORT) {
            // do nothing
        } else {
            ALOGE("methodParser unrecognizable opcode: %d", opcode);
        }
    }
}

void parseMethod(MethodAccInfo* methodAccInfo, std::vector<Method*>* chain) {
    Method* method = methodAccInfo->method;
    ALOGE("methodParser parsing method %s.%s()", method->clazz->descriptor, method->name);
    // an abstract cannot be parsed
    if(dvmIsAbstractMethod(method)) {
        chain->pop_back();
        return;
    }
    // if it is a native method which we can not parse, then we just set all the parameters as need migration
    if(dvmIsNativeMethod(method)) {
        for(int i = 0; i < method->insSize; i++) {
            for(unsigned int j = 0; j < methodAccInfo->args->at(i)->size(); j++) {
                methodAccInfo->args->at(i)->at(j)->allFlag = true;
            }
        }
        chain->pop_back();
        return;
    }
    // declare a map which will contain the list of registers the method should track
    // in each register, we use a vector to track all the possible object this vector might store
    std::map<u2, std::vector<ObjectAccInfo*>* > interestRegObjMap;
    // sets the count to be the number of arguments and initiate them, and initialize interest registers
    DexParameterIterator iterator;
    const char* descriptor;
    dexParameterIteratorInit(&iterator, &method->prototype);
    for(int i = 0; i < method->insSize; i++) {
        if(i == 0 && !dvmIsStaticMethod(method)) {
            interestRegObjMap[method->registersSize - method->insSize + i] = methodAccInfo->args->at(i);
        }
        if(i > 0 || dvmIsStaticMethod(method)) {
            descriptor = dexParameterIteratorNextDescriptor(&iterator);
            if(descriptor == NULL) {
                ALOGE("methodParser find NULL descriptor, insSize: %d, i: %d, method: %s.%s", method->insSize, i, method->clazz->descriptor, method->name);
                break;
            }
            // we only cares object parameter
            if(*descriptor == 'L' || *descriptor == '[') {
                interestRegObjMap[method->registersSize - method->insSize + i] = methodAccInfo->args->at(i);
            }
        }
    }
    const u2* insns = method->insns;
    //u4 insnsSize = dvmGetMethodInsnsSize(method);
    std::vector<int> insOffsets;
    parseInsns(insns, methodAccInfo, chain, &insOffsets, &interestRegObjMap);
    
    chain->pop_back();
}


void findSubClass(ClassObject* clazz, std::vector<ClassObject*>* result) {
    for(unsigned int idx = 0; idx < loadedDex.size(); idx++) {
        DvmDex* pDvmDex;
        pDvmDex = loadedDex[idx];
    
        // iterate the dvm classes and parse each method in the class
        for(unsigned int j = 0; j < pDvmDex->pHeader->classDefsSize; j++) {
            const DexClassDef pClassDef = pDvmDex->pDexFile->pClassDefs[j];
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
                continue;
            }
            // check if it is an interface
            if(dvmIsInterfaceClass(resClass)) {
                continue;
            }
            // check if is subclass
            if(dvmInstanceof(resClass, clazz)) {
                result->push_back(resClass);
            }
        }
    }
    /*for(unsigned int i = 0; i < (*result).size(); i++) {
        ALOGE("findsubclass class: %s", (*result)[i]->descriptor);
    }*/
}

void findImplementClass(ClassObject* clazz, std::vector<ClassObject*>* result) {
    for(unsigned int idx = 0; idx < loadedDex.size(); idx++) {
        DvmDex* pDvmDex;
        pDvmDex = loadedDex[idx];
    
        // iterate the dvm classes and parse each method in the class
        for(unsigned int j = 0; j < pDvmDex->pHeader->classDefsSize; j++) {
            const DexClassDef pClassDef = pDvmDex->pDexFile->pClassDefs[j];
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
                continue;
            }
            // check if it is an interface
            if(dvmIsInterfaceClass(resClass)) {
                continue;
            }
            // check if is subclass
            if(dvmImplements(resClass, clazz)) {
                result->push_back(resClass);
            }
        }
    }
   /* for(unsigned int i = 0; i < (*result).size(); i++) {
        ALOGE("findimplementedclass class: %s", (*result)[i]->descriptor);
    }*/
}

void depthTraverse(ObjectAccInfo* objAccInfo, int depth) {
    if(objAccInfo->allFlag) {
        ALOGE("methodParser depth: %d, allFlag is: %d", depth, objAccInfo->allFlag);
        return;
    }
    for(unsigned int i = 0; i < objAccInfo->fieldSet.size(); i++) {
        ALOGE("methodParser depth: %d, offset: %d, value is: %d", depth, i, objAccInfo->fieldSet[i] != NULL);
        if(objAccInfo->fieldSet[i] != NULL) {
            depthTraverse(objAccInfo->fieldSet[i], depth + 1);
        }
    }
}
