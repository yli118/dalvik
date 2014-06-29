
#include "Dalvik.h"
#define LOG_CLASS_LOADING 0

#include "libdex/DexClass.h"
#include "analysis/Optimize.h"

#include <stdlib.h>
#include <stddef.h>
#include <sys/stat.h>

#if LOG_CLASS_LOADING
#include <unistd.h>
#include <pthread.h>
#include <cutils/process_name.h>
#include <sys/types.h>
#endif
#include <string>

#include <libgen.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <zlib.h>

static const char* kDexInJarName = "classes.dex";
bool dexFirstLoad = true;
ClassObject* javaLangObject;
std::vector<ClassObject*>* exemptClzs = new std::vector<ClassObject*>();
std::vector<ClassObject*>* exemptIfs = new std::vector<ClassObject*>();
std::vector<DvmDex*> loadedDex;

/*
 * Open a Jar file.  But we do not try to optimize the dex.
 *
 * If "isBootstrap" is not set, the optimizer/verifier regards this DEX as
 * being part of a different class loader.
 */
int jarFileOpen(const char* fileName, const char* dexOutputName,
    JarFile** ppJarFile, bool isBootstrap)
{
    /*
     * TODO: This function has been duplicated and modified to become
     * dvmRawDexFileOpen() in RawDexFile.c. This should be refactored.
     */

    ZipArchive archive;
    DvmDex* pDvmDex = NULL;
    char* cachedName = NULL;
    bool archiveOpen = false;
    int fd = -1;
    int result = -1;

    /* Even if we're not going to look at the archive, we need to
     * open it so we can stuff it into ppJarFile.
     */
    if (dexZipOpenArchive(fileName, &archive) != 0)
        goto bail;
    archiveOpen = true;

    /* If we fork/exec into dexopt, don't let it inherit the archive's fd.
     */
    dvmSetCloseOnExec(dexZipGetArchiveFd(&archive));
    ZipEntry entry;

    /*
     * Look inside the jar for a "classes.dex".
     */
    entry = dexZipFindEntry(&archive, kDexInJarName);
    if (entry != NULL) {
        cachedName = strdup(dexOutputName);
        ALOGV("dvmJarFileOpen: Checking cache for %s (%s)", fileName, cachedName);
        fd = open(cachedName, O_CREAT|O_RDWR|O_TRUNC, 0777);
        if (fd < 0) {
            ALOGI("Unable to open or create cache for %s (%s)", fileName, cachedName);
            goto bail;
        }
        dexZipExtractEntryToFile(&archive, entry, fd);
    } else {
        ALOGI("Zip is good, but no %s inside", kDexInJarName);
        goto bail;
    }

    /*
     * Map the cached version.  This immediately rewinds the fd, so it
     * doesn't have to be seeked anywhere in particular.
     */
    if (dvmDexFileOpenFromFd(fd, &pDvmDex) != 0) {
        ALOGI("Unable to map %s in %s", kDexInJarName, fileName);
        goto bail;
    }

    ALOGV("Successfully opened '%s' in '%s'", kDexInJarName, fileName);

    *ppJarFile = (JarFile*) calloc(1, sizeof(JarFile));
    (*ppJarFile)->archive = archive;
    (*ppJarFile)->cacheFileName = cachedName;
    (*ppJarFile)->pDvmDex = pDvmDex;
    cachedName = NULL;      // don't free it below
    result = 0;

bail:
    /* clean up, closing the open file */
    if (archiveOpen && result != 0)
        dexZipCloseArchive(&archive);
    free(cachedName);
    if (fd >= 0) {
        close(fd);
    }
    return result;
}


/*
 * Get the filename suffix of the given file (everything after the
 * last "." if any, or "<none>" if there's no apparent suffix). The
 * passed-in buffer will always be '\0' terminated.
 */
static void getFileNameSuffix(const char* fileName, char* suffixBuf, size_t suffixBufLen)
{
    const char* lastDot = strrchr(fileName, '.');

    strlcpy(suffixBuf, (lastDot == NULL) ? "<none>" : (lastDot + 1), suffixBufLen);
}
static void getFileActualName(const char* fileName, char* nameBuf, size_t nameBufLen)
{
    const char* lastSlash = strrchr(fileName, '/');
    const char* lastDot = strrchr(fileName, '.');
    size_t len;
    if(lastDot != NULL && lastSlash != NULL) {
        len = lastDot - lastSlash;
    } else {
        len = nameBufLen;
    }
    if(len > nameBufLen) {
        len = nameBufLen;
    }

    strlcpy(nameBuf, (lastSlash == NULL) ? fileName : (lastSlash + 1), len);
}
/*
 * Prepare a ClassPathEntry struct, which at this point only has a valid
 * filename.  We need to figure out what kind of file it is, and for
 * everything other than directories we need to open it up and see
 * what's inside.
 */
static bool prepareCpe(ClassPathEntry* cpe, bool isBootstrap)
{
    struct stat sb;

    if (stat(cpe->fileName, &sb) < 0) {
        ALOGD("Unable to stat classpath element '%s'", cpe->fileName);
        return false;
    }
    if (S_ISDIR(sb.st_mode)) {
        ALOGE("Directory classpath elements are not supported: %s", cpe->fileName);
        return false;
    }

    char suffix[10];
    getFileNameSuffix(cpe->fileName, suffix, sizeof(suffix));
    char name[20];
    ALOGE("the name is: %s", name);
    getFileActualName(cpe->fileName, name, sizeof(name));
    char newname[80];
    strcpy(newname, "/data/data/edu.utk.offloadtest/");
    strcat(newname, name);
    strcat(newname, ".class.dex");

    if ((strcmp(suffix, "jar") == 0) || (strcmp(suffix, "zip") == 0) ||
            (strcmp(suffix, "apk") == 0)) {
        JarFile* pJarFile = NULL;
        if (jarFileOpen(cpe->fileName, newname, &pJarFile, isBootstrap) == 0) {
            cpe->kind = kCpeJar;
            cpe->ptr = pJarFile;
            return true;
        }
    } else if (strcmp(suffix, "dex") == 0) {
        RawDexFile* pRawDexFile = NULL;
        if (dvmRawDexFileOpen(cpe->fileName, NULL, &pRawDexFile, isBootstrap) == 0) {
            cpe->kind = kCpeDex;
            cpe->ptr = pRawDexFile;
            return true;
        }
    } else {
        ALOGE("Unknown type suffix '%s'", suffix);
    }

    ALOGD("Unable to process classpath element '%s'", cpe->fileName);
    return false;
}
static ClassPathEntry* processClassPath(const char* pathStr, bool isBootstrap)
{
    ClassPathEntry* cpe = NULL;
    char* mangle;
    char* cp;
    const char* end;
    int idx, count;

    assert(pathStr != NULL);

    mangle = strdup(pathStr);

    /*
     * Run through and essentially strtok() the string.  Get a count of
     * the #of elements while we're at it.
     *
     * If the path was constructed strangely (e.g. ":foo::bar:") this will
     * over-allocate, which isn't ideal but is mostly harmless.
     */
    count = 1;
    for (cp = mangle; *cp != '\0'; cp++) {
        if (*cp == ':') {   /* separates two entries */
            count++;
            *cp = '\0';
        }
    }
    end = cp;

    /*
     * Allocate storage.  We over-alloc by one so we can set an "end" marker.
     */
    cpe = (ClassPathEntry*) calloc(count+1, sizeof(ClassPathEntry));

    /*
     * Go through a second time, pulling stuff out.
     */
    cp = mangle;
    idx = 0;
    while (cp < end) {
        if (*cp == '\0') {
            /* leading, trailing, or doubled ':'; ignore it */
        } else {
            if (isBootstrap &&
                    dvmPathToAbsolutePortion(cp) == NULL) {
                ALOGE("Non-absolute bootclasspath entry '%s'", cp);
                free(cpe);
                cpe = NULL;
                goto bail;
            }

            ClassPathEntry tmp;
            tmp.kind = kCpeUnknown;
            tmp.fileName = strdup(cp);
            tmp.ptr = NULL;

            /*
             * Drop an end marker here so DEX loader can walk unfinished
             * list.
             */
            cpe[idx].kind = kCpeLastEntry;
            cpe[idx].fileName = NULL;
            cpe[idx].ptr = NULL;

            if (!prepareCpe(&tmp, isBootstrap)) {
                /* drop from list and continue on */
                free(tmp.fileName);
            } else {
                /* copy over, pointers and all */
                cpe[idx] = tmp;
                idx++;
            }
        }

        cp += strlen(cp) +1;
    }
    assert(idx <= count);
    if (idx == 0) {
        /*
         * There's no way the vm will be doing anything if this is the
         * case, so just bail out (reasonably) gracefully.
         */
        ALOGE("No valid entries found in bootclasspath '%s'", pathStr);
        dvmAbort();
    }

    LOGVV("  (filled %d of %d slots)", idx, count);

    /* put end marker in over-alloc slot */
    cpe[idx].kind = kCpeLastEntry;
    cpe[idx].fileName = NULL;
    cpe[idx].ptr = NULL;

    //dumpClassPath(cpe);

bail:
    free(mangle);
    return cpe;
}

static void makeClassLoader(std::vector<DvmDex*>* dexVector) {
  // This is sort of a hack but much better than what existed before.  We need
  // to create a DexClassLoader that will load from the passed DvmDex object.
  // This involves filling out internal java structures to do our bidding and
  // is thus tied to the specific implementation of
  // dalvik.system.DexClassLoader and dalvik.system.DexFile.  Note that I
  // haven't changed these classes in any way.
  Thread* self = dvmThreadSelf();

  // Load the required classes.
  ClassObject* loaderClazz =
      dvmFindSystemClass("Ldalvik/system/DexClassLoader;");
  ClassObject* classLoaderClazz =
      dvmFindSystemClass("Ljava/lang/ClassLoader;");
  ClassObject* fileClazz = dvmFindSystemClass("Ljava/io/File;");
  ClassObject* fileArrayClazz = dvmFindArrayClassForElement(fileClazz);
  ClassObject* zipClazz = dvmFindSystemClass("Ljava/util/zip/ZipFile;");
  ClassObject* zipArrayClazz = dvmFindArrayClassForElement(zipClazz);
  ClassObject* dexClazz = dvmFindSystemClass("Ldalvik/system/DexFile;");
  ClassObject* dexArrayClazz = dvmFindArrayClassForElement(dexClazz);
  
  // Create the 'magic cookie' for the dex file.
  std::vector<Object*> dexFileVector;
  InstField* fld,* efld;
  for(unsigned int i = 0; i < dexVector->size(); i++) {
      DexOrJar* pDexOrJar = (DexOrJar*)calloc(1, sizeof(DexOrJar));
      pDexOrJar->isDex = true;
      pDexOrJar->okayToFree = false;
      pDexOrJar->pRawDexFile = (RawDexFile*)calloc(1, sizeof(RawDexFile));
      pDexOrJar->pRawDexFile->pDvmDex = (*dexVector)[i];

      // Create and fill in fields of a dex file object.
      Object* dexFile = dvmAllocObject(dexClazz, ALLOC_DEFAULT);
      for(fld = dexClazz->ifields,
          efld = dexClazz->ifields + dexClazz->ifieldCount; fld != efld; ++fld) {
        if(!strcmp("mCookie", fld->name)) {
          dvmSetFieldInt(dexFile, fld->byteOffset, (s4)pDexOrJar);
        }
      }
      dexFileVector.push_back(dexFile);
  }

  // Create and fill in fields of a dex class loader object.
  Object* classLoader = dvmAllocObject(loaderClazz, ALLOC_DEFAULT);

  // We can let the superclass java.lang.ClassLoader load like normal.
  JValue unused;
  Method* loaderConstr = dvmFindDirectMethodByDescriptor(
      classLoaderClazz, "<init>", "()V");
  dvmCallMethod(dvmThreadSelf(), loaderConstr, classLoader, &unused);

  // TODO: Might want to set mFiles, mZips, mLibPaths to something.
  for(fld = loaderClazz->ifields, efld = loaderClazz->ifields +
          loaderClazz->ifieldCount; fld != efld; ++fld) {
    if(!strcmp("mFiles", fld->name)) {
      Object* obj = (Object*)
          dvmAllocArrayByClass(fileArrayClazz, 1, ALLOC_DEFAULT);
      dvmSetFieldObject(classLoader, fld->byteOffset, obj);
      dvmReleaseTrackedAlloc(obj, self);
    } else if(!strcmp("mZips", fld->name)) {
      Object* obj =
          (Object*)dvmAllocArrayByClass(zipArrayClazz, 1, ALLOC_DEFAULT);
      dvmSetFieldObject(classLoader, fld->byteOffset, obj);
      dvmReleaseTrackedAlloc(obj, self);
    } else if(!strcmp("mDexs", fld->name)) {
      ArrayObject* xdex = dvmAllocArrayByClass(dexArrayClazz, dexVector->size(), ALLOC_DEFAULT);
      for(unsigned int i = 0; i < dexVector->size(); i++) {
        dvmSetObjectArrayElement(xdex, i, dexFileVector[i]);
      }
      dvmSetFieldObject(classLoader, fld->byteOffset, (Object*)xdex);
      dvmReleaseTrackedAlloc((Object*)xdex, self);
    }
  }

  for(unsigned int i = 0; i < dexVector->size(); i++) {
    (*dexVector)[i]->classLoader = classLoader;
    dvmReleaseTrackedAlloc(dexFileVector[i], self);
  }
  dvmReleaseTrackedAlloc(classLoader, self);
}

void filterExempt(const char* className, ClassObject* resClass) {
    // filter interface
    if(dvmIsInterfaceClass(resClass)) {
        if(strcmp(className, "Ljava/lang/Iterable;") == 0) {
            exemptIfs->push_back(resClass);
        } else if(strcmp(className, "Ljava/util/Map;") == 0) {
            exemptIfs->push_back(resClass);
        } else if(strcmp(className, "Ljava/util/concurrent/ConcurrentMap;") == 0) {
            exemptIfs->push_back(resClass);
        } else if(strcmp(className, "Ljava/util/NavigableMap;") == 0) {
            exemptIfs->push_back(resClass);
        } else if(strcmp(className, "Ljava/util/concurrent/ConcurrentNavigableMap;") == 0) {
            exemptIfs->push_back(resClass);
        } else if(strcmp(className, "Ljava/util/SortedMap;") == 0) {
            exemptIfs->push_back(resClass);
        } else if(strcmp(className, "Ljavax/script/Bindings;") == 0) {
            exemptIfs->push_back(resClass);
        } else if(strcmp(className, "Ljavax/xml/ws/handler/MessageContext;") == 0) {
            exemptIfs->push_back(resClass);
        } else if(strcmp(className, "Ljavax/xml/ws/handler/LogicalMessageContext;") == 0) {
            exemptIfs->push_back(resClass);
        } else if(strcmp(className, "Ljavax/xml/ws/handler/soap/SOAPMessageContext;") == 0) {
            exemptIfs->push_back(resClass);
        } else if(strcmp(className, "Ljava/util/Collection;") == 0) {
            exemptIfs->push_back(resClass);
        } else if(strcmp(className, "Ljava/util/List;") == 0) {
            exemptIfs->push_back(resClass);
        } else if(strcmp(className, "Ljava/util/Set;") == 0) {
            exemptIfs->push_back(resClass);
        } else if(strcmp(className, "Ljava/util/SortedSet;") == 0) {
            exemptIfs->push_back(resClass);
        } else if(strcmp(className, "Ljava/util/NavigableSet;") == 0) {
            exemptIfs->push_back(resClass);
        } else if(strcmp(className, "Ljava/util/Queue;") == 0) {
            exemptIfs->push_back(resClass);
        } else if(strcmp(className, "Ljava/util/concurrent/BlockingQueue;") == 0) {
            exemptIfs->push_back(resClass);
        } else if(strcmp(className, "Ljava/util/concurrent/TransferQueue;") == 0) {
            exemptIfs->push_back(resClass);
        } else if(strcmp(className, "Ljava/util/Deque;") == 0) {
            exemptIfs->push_back(resClass);
        } else if(strcmp(className, "Ljava/util/concurrent/BlockingDeque;") == 0) {
            exemptIfs->push_back(resClass);
        } else if(strcmp(className, "Ljava/nio/file/DirectoryStream;") == 0) {
            exemptIfs->push_back(resClass);
        } else if(strcmp(className, "Ljava/nio/file/SecureDirectoryStream;") == 0) {
            exemptIfs->push_back(resClass);
        } else if(strcmp(className, "Ljava/nio/file/Path;") == 0) {
            exemptIfs->push_back(resClass);
        } else if(strcmp(className, "Landroid/os/IInterface;") == 0) {
            exemptIfs->push_back(resClass);
        } else if(strcmp(className, "Landroid/view/inputmethod/InputMethodSession;") == 0) {
            exemptIfs->push_back(resClass);
        } else if(strcmp(className, "Landroid/text/method/KeyListener;") == 0) {
            exemptIfs->push_back(resClass);
        } else if(strcmp(className, "Landroid/text/Spanned;") == 0) {
            exemptIfs->push_back(resClass);
        } else if(strncmp(className, "Landroid/os/Parcelable", 22) == 0) {
            exemptIfs->push_back(resClass);
        }
    } else {
        // filter class
        if(strcmp(className, "Ljava/util/AbstractMap;") == 0) {
            exemptClzs->push_back(resClass);
        } else if(strcmp(className, "Ljava/util/AbstractCollection;") == 0) {
            exemptClzs->push_back(resClass);
        } else if(strcmp(className, "Landroid/os/Parcel;") == 0) {
            exemptClzs->push_back(resClass);
        } else if(strcmp(className, "Ljava/lang/AbstractStringBuilder;") == 0) {
            exemptClzs->push_back(resClass);
        } else if(strcmp(className, "Landroid/os/Bundle;") == 0) {
            exemptClzs->push_back(resClass);
        } else if(strcmp(className, "Ljava/io/PrintWriter;") == 0) {
            exemptClzs->push_back(resClass);
        } else {
            for(unsigned int j = 0; j < exemptClzs->size(); j++) {
                if(dvmInstanceof(resClass, exemptClzs->at(j))) {
                    exemptClzs->push_back(resClass);
                    break;
                }
            }
        }
    }
}

void loadApk() {
    if(dexFirstLoad) {
        ClassPathEntry* entry;
        entry = processClassPath("/data/data/jars/core.jar:/data/data/jars/core-junit.jar:/data/data/jars/bouncycastle.jar:/data/data/jars/ext.jar:/data/data/jars/framework.jar:/data/data/jars/framework2.jar:/data/data/jars/android.policy.jar:/data/data/jars/services.jar:/data/data/jars/apache-xml.jar:/data/app/edu.utk.offloadtest-1.apk", false);
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
        makeClassLoader(&loadedDex);    
        for(unsigned int idx = 0; idx < loadedDex.size(); idx++) {
            DvmDex* pDvmDex;
            pDvmDex = loadedDex[idx];
            Object* classLoader = pDvmDex->classLoader;
            for(unsigned int i = 0; i < pDvmDex->pHeader->classDefsSize; i++) {
                const DexClassDef pClassDef = pDvmDex->pDexFile->pClassDefs[i];
                ClassObject* resClass;  // this segment is copied from Resolve.cpp - dvmResolveClass()
                const char* className;
                className = dexStringByTypeIdx(pDvmDex->pDexFile, pClassDef.classIdx);
                if(strncmp(className, "Landroid/support/v4", 19) == 0) {
                    continue;
                }
                /*if(strncmp(className, "Ledu/utk/offloadtest/MainActivity;", 34) != 0) {
                    continue;
                }*/
                if(className[0] != '\0' && className[1] == '\0') {
                    /* primitive type */
                    resClass = dvmFindPrimitiveClass(className[0]);
                } else {
                    //resClass = dvmFindClassNoInit(className, classLoader);
                    resClass = dvmDefineClass(pDvmDex, className, classLoader);
                    if(strcmp(className, "Ljava/lang/Object;") == 0 && javaLangObject == NULL) {
                        javaLangObject = resClass;
                    }
                    filterExempt(className, resClass);
                }
            }
        }
        dexFirstLoad = false;
    }
    for(unsigned int idx = 0; idx < loadedDex.size(); idx++) {
        DvmDex* pDvmDex;
        pDvmDex = loadedDex[idx];
        Object* classLoader = pDvmDex->classLoader;
        ALOGE("classLoader is: %p, and pDvmDex is: %p", classLoader, pDvmDex);
        for(unsigned int i = 0; i < pDvmDex->pHeader->classDefsSize; i++) {
            const DexClassDef pClassDef = pDvmDex->pDexFile->pClassDefs[i];
            ClassObject* resClass;  // this segment is copied from Resolve.cpp - dvmResolveClass()
            const char* className;
            className = dexStringByTypeIdx(pDvmDex->pDexFile, pClassDef.classIdx);
            if(strncmp(className, "Landroid/support/v4", 19) == 0) {
                continue;
            }
            if(strncmp(className, "Ledu/utk/offloadtest/MainActivity;", 34) != 0) {
                continue;
            }
            if(className[0] != '\0' && className[1] == '\0') {
                /* primitive type */
                resClass = dvmFindPrimitiveClass(className[0]);
            } else {
                resClass = dvmFindClassNoInit(className, classLoader);
                //resClass = dvmDefineClass(pDvmDex, className, classLoader);
            }
            // check if it is an interface
            if(dvmIsInterfaceClass(resClass)) {
                continue;
            }
            // traverse and parse every method in the class, see Object.cpp - findMethodInListByDescriptor
            Method* methods = resClass->virtualMethods;
            size_t methodCount = resClass->virtualMethodCount;
            size_t j;
            for(j = 0; j < methodCount; j++) {
                Method* method = &methods[j];
                if(strncmp(method->name, "matrixTest", 10) == 0) {
                    MethodAccInfo* methodAccInfo = new MethodAccInfo();
                    methodAccInfo->method = method;
                    populateMethodAccInfo(methodAccInfo);
                    std::vector<Method*>* chain = new std::vector<Method*>();
                    chain->push_back(method);
                    parseMethod(methodAccInfo, chain);
                    assert(chain->empty());
     for(unsigned int i = 0; i < methodAccInfo->args->size(); i++) {
        ALOGE("methodParser: for arg %d: ", i);
        if(methodAccInfo->args->at(i)->size() != 0) {
            depthTraverse(methodAccInfo->args->at(i)->at(0), 1);
        }
        /*if(methodAccInfo->args->at(i)->size() == 0) {
            continue;
        }
        bool allflag = methodAccInfo->args->at(i)->at(0)->allFlag;
        ALOGE("methodParser: for arg %d: , allFlag: %d", i, allflag);
        for(unsigned int j = 0; j < methodAccInfo->args->at(i)->at(0)->fieldSet.size(); j++) {
            bool jflag = (methodAccInfo->args->at(i)->at(0)->fieldSet[j] != NULL);
            ALOGE("methodParser offset %d value is: %d", j, jflag || allflag);
            if(jflag) {
                ObjectAccInfo* oai = methodAccInfo->args->at(i)->at(0)->fieldSet[j];
                bool oaiallflag = oai->allFlag;
                for(unsigned int k = 0; k < oai->fieldSet.size(); k++) {
                    bool kflag = (oai->fieldSet[k] != NULL || allflag || oaiallflag);
                    ALOGE("methodParser nested offset %d value is: %d", k, kflag);
                }
            }
        }*/
    }
    /*ALOGE("methodParser: for global clazz %d: ", methodAccInfo->globalClazz->size());
    for(unsigned int i = 0; i < methodAccInfo->globalClazz->size(); i++) {
        ALOGE("methodParser: for clazz %d: and %s: ", i, methodAccInfo->globalClazz->at(i)->clazz->descriptor);
        for(unsigned int j = 0; j < methodAccInfo->globalClazz->at(i)->fieldSet.size(); j++) {
            bool jflag = (methodAccInfo->globalClazz->at(i)->fieldSet[j] != NULL);
            ALOGE("methodParser offset %d value is: %d", j, jflag);
            if(jflag) {
                ObjectAccInfo* oai = methodAccInfo->globalClazz->at(i)->fieldSet[j];
                for(unsigned int k = 0; k < oai->fieldSet.size(); k++) {
                    bool kflag = (oai->fieldSet[k] != NULL);
                    ALOGE("methodParser nested offset %d value is: %d", k, kflag);
                }
            }
        }
    }*/
                }
            }
        }
    }
}
