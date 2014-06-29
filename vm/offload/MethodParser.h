#include "Dalvik.h"
#include <vector>
#include <map>
#include <queue>
#include <iostream>
#include <fstream>
#include <string>
#include <set>

/* structure indicates which fields of object have been accessed */
struct ObjectAccInfo {
    // flag indicates that all the attribute of the object should be marked as accessed to assure correctness
    bool allFlag;
    // recursively indicates the fields of the object
    std::vector<ObjectAccInfo*> fieldSet;
    // recursively indicates the current attributes of the object which need to be tracked
    std::vector<std::vector<ObjectAccInfo*>* > trackSet;
    // set for merge to be able to save temporary result
    std::vector<std::vector<ObjectAccInfo*>* > mergeSet;
    // Object which this field belongs to
    ObjectAccInfo* belonging;
    // flag incates that the object can be accessed from an array
    bool inArray;
};

/* structure indicates which fields of object have been accessed */
struct ClazzAccInfo : ObjectAccInfo {
    // indicate the clazz information
    ClassObject* clazz;
};

/* structure indicates which fields of the method arg have been accessed in the method */
struct MethodAccInfo {
    // the method reference to analyze
    Method* method;
    
    // The object access info of the method's arguments
    std::vector<ObjectAccInfo*>* args;
    
    // The object access Info of the global class object
    std::vector<ClazzAccInfo*>* globalClazz;
    
    // objects which represents the possible returns
    std::vector<ObjectAccInfo*>* returnObjs;
    
    // objects which represents the possible returns
    std::vector<ObjectAccInfo*>* curMethodReturns;
};

struct ObjectAccResult {
    // flag indicates that all the attribute of the object should be marked as accessed to assure correctness
    bool allFlag;
    // recursively indicates the fields of the object
    std::vector<ObjectAccResult*> fieldSet;
   
    /* Tracks the neccessity of migrating low field indexes. */
    u4 migrate;

    /* Tracks the dirtiness of high field indexes. */
    u4* highbits;
};

/* structure indicates which fields of object have been accessed */
struct ClazzAccResult : ObjectAccResult {
    // indicate the clazz information
    char* clazz;
};

struct MethodAccResult {
    char* clazzDesc;
    
    char* methodName;
    
    u4 idx;
    
    std::vector<ObjectAccResult*>* args;
    
    std::vector<ClazzAccResult*>* globalClazz;
};


void populateMethodAccInfo(MethodAccInfo* methodAccInfo);
MethodAccInfo* parseMethod(Method* method, std::vector<Method*>* chain);
void findSubClass(ClassObject* clazz, std::vector<ClassObject*>* result);
void findImplementClass(ClassObject* clazz, std::vector<ClassObject*>* result);
void depthTraverse(ObjectAccInfo* objAccInfo, int depth);
void freeMethodAccInfo(MethodAccInfo* methodAccInfo);
void persistMethodInfo(MethodAccInfo* methodAccInfo, const char* fileName);
void retrieveMethodInfo(std::map<char*, MethodAccResult*>* methodAccMap, const char* fileName);
void depthTraverseResult(ObjectAccResult* objAccResult, int depth);
