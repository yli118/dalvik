#include "Dalvik.h"
#include <vector>
#include <map>

/* structure indicates which fields of object have been accessed */
struct ObjectAccInfo {
    // flag indicates that all the attribute of the object should be marked as accessed to assure correctness
    bool allFlag;
    // recursively indicates the fields of the object
    std::vector<ObjectAccInfo*> fieldSet;
    // recursively indicates the current attributes of the object which need to be tracked
    std::vector<std::vector<ObjectAccInfo*>* > trackSet;
    // flag indicate this is a return reference
    bool isReturn;
    // Object which this field belongs to
    ObjectAccInfo* belonging;
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
    std::vector<std::vector<ObjectAccInfo*>* >* args;
    
    // The object access Info of the global class object
    std::vector<ClazzAccInfo*>* globalClazz;
    
    // objects which represents the possible returns
    std::vector<ObjectAccInfo*>* returnObjs;
};

void populateMethodAccInfo(MethodAccInfo* methodAccInfo);
void parseMethod(MethodAccInfo* methodAccInfo, std::vector<Method*>* chain);
void findSubClass(ClassObject* clazz, Object* classLoader, std::vector<ClassObject*>* result);
void findImplementClass(ClassObject* clazz, Object* classLoader, std::vector<ClassObject*>* result);
void depthTraverse(ObjectAccInfo* objAccInfo, int depth);
