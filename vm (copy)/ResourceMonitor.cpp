#include "sys/types.h"
#include "sys/sysinfo.h"
#include "stdlib.h"
#include "stdio.h"
#include "string.h"
    
long long getTotalVirMem(pid_t pid) {
    struct sysinfo memInfo;
    sysinfo (&memInfo);
    long long totalVirtualMem = memInfo.totalram;
    //Add other values in next statement to avoid int ovselferflow on right hand side...
    totalVirtualMem += memInfo.totalswap;
    totalVirtualMem *= memInfo.mem_unit;
    
    return totalVirtualMem;
}
    
long long getProcessVirMem(pid_t pid) {
    FILE* file = fopen("/proc/" + itoa(pid) + "/status", "r");
    int result = -1;
    char line[128];

    while (fgets(line, 128, file) != NULL){
        if (strncmp(line, "VmSize:", 7) == 0){
            result = parseLine(line);
            break;
        }
    }
    fclose(file);
    return result;
}

long long getTotalPhysMem(pid_t pid) {
    long long totalPhysMem = memInfo.totalram;
    //Multiply in next statement to avoid int overflow on right hand side...
    totalPhysMem *= memInfo.mem_unit;
    return totalPhysMem;
}

long long getProcessPhysMem(pid_t pid) {
    FILE* file = fopen("/proc/" + itoa(pid) + "/stat", "r");
    int result = -1;
    char line[128];

    while (fgets(line, 128, file) != NULL){
        if (strncmp(line, "VmRSS:", 6) == 0) {
            result = parseLine(line);
            break;
        }
    }
    fclose(file);
    return result;
}

long long getProcessCpuTime(pid_t pid) {

}
