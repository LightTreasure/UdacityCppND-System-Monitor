#include <algorithm>
#include <iostream>
#include <math.h>
#include <thread>
#include <chrono>
#include <iterator>
#include <string>
#include <stdlib.h>
#include <stdio.h>
#include <vector>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <time.h>
#include <unistd.h>
#include "constants.h"
#include "util.h"

class ProcessParser{
private:
    public:
    static std::string getCmd(std::string pid);
    static std::vector<std::string> getPidList();
    static std::string getVmSize(std::string pid);
    static std::string getCpuPercent(std::string pid);
    static std::string getProcUpTime(std::string pid);
    static std::string getProcUser(std::string pid);
    static long int getSysUpTime();
    static bool isPidExisting(std::string pid);
    static std::string getSysKernelVersion();
    static std::string getOSName();
    static int getNumberOfCores();
    static std::vector<std::string> getSysCpuPercent(std::string coreNumber = "");
    static std::string PrintCpuStats(std::vector<std::string> values1, std::vector<std::string>values2);
    static float getSysRamPercent();
    static int getTotalNumberOfProcesses();
    static int getNumberOfRunningProcesses();
    static int getTotalThreads();
};

std::string ProcessParser::getCmd(std::string pid)
{
    std::ifstream stream;
    std::string cmd;

    std::string fullpath = Path::basePath() + pid + Path::cmdPath();
    Util::getStream(fullpath, stream);

    // This file is just one line representing the cmd; read it.
    std::getline(stream, cmd);

    return cmd;
}

std::string ProcessParser::getVmSize(std::string pid)
{
    std::ifstream stream;
    std::string line;
    std::string vmsize;

    std::string fullpath = Path::basePath() + pid + Path::statusPath();
    Util::getStream(fullpath, stream);

    // This file has a lot of information, one of which is VmSize
    // We will read each line until we get to the row with VmSize.
    while (std::getline(stream, line)) {
        if (line.substr(0, 7) == "VmSize:") {
            vmsize = line.substr(10);

            // remove " kB" from the string
            vmsize = vmsize.substr(0,vmsize.length() - 2);

            // convert to MB
            vmsize = to_string(stof(vmsize)/1024.0);
            break;
        }
    }
    return vmsize;
}

std::string ProcessParser::getCpuPercent(std::string pid)
{
    std::ifstream stream;
    std::string line;
    std::string vmsize;

    std::string fullpath = Path::basePath() + pid + "/" + Path::statPath();
    Util::getStream(fullpath, stream);

    // This file has a lot of information separated by space: ' '
    // Thie fields we are interested in are:
    // utime (field 14) - time spent by this process in user mode
    // stime (field 15) - time spent by this process in kernel mode
    // cutime (field 16) - time spent by this process' children in user mode, while this process waits on them
    // cstime (field 17) - time spent by this process' children in kernel mode, while this process waits on them
    // starttime (field 22) - time this process started since boot
    // NOTE: All the above times are expressed in clock ticks, so we get sysconf(_SC_CLK_TCK) to get time per clock tick
    float utime, stime, cutime, cstime, starttime;
    float tickstosec = 1.0/sysconf(_SC_CLK_TCK); 
    int fieldnum = 1;
    while (std::getline(stream, line, ' ')) 
    {
        switch (fieldnum)
        {
            case 14:
                utime = stof(line);
                break;
            case 15:
                stime = stof(line);
                break;
            case 16:
                cutime = stof(line);
                break;
            case 17:
                cstime = stof(line);
                break;
            case 22:
                starttime = stof(line);
                break;
        }
        fieldnum++;
    }

    // Add all the process cpu time together (in seconds)
    float processcputime = (utime+stime+cutime+cstime) * tickstosec;

    // Get the time the process has been running (in seconds)
    float runtime = ProcessParser::getSysUpTime() - (starttime * tickstosec);

    // The CPU percent of this process is the ratio of time this process
    // has been running on the CPU vs the total time this process has been running
    float cpupercent = (processcputime / runtime) * 100;

    return to_string(cpupercent);
}

long int ProcessParser::getSysUpTime() {
    std::ifstream stream;
    std::string line;
    std::string uptimestring;

    std::string fullpath = Path::basePath() + Path::upTimePath();
    Util::getStream(fullpath, stream);

    // This file is just two numbers. The first number is the system up time in seconds.
    std::getline(stream, line, ' ');
    uptimestring = line;

    return stol(uptimestring);
}

std::string ProcessParser::getProcUpTime(std::string pid)
{
    std::ifstream stream;
    std::string line;
    std::string uptime;

    std::string fullpath = Path::basePath() + pid + "/" + Path::statPath();
    Util::getStream(fullpath, stream);

    // This file has a lot of information separated by space: ' '
    // filed number 14 is up time, which we will read.
    int fieldnum = 1;
    while (std::getline(stream, line, ' ')) 
    {
        if (fieldnum == 14) {
            uptime = line;
            break;
        }
        fieldnum++;
    }

    return uptime;
}

std::string ProcessParser::getProcUser(std::string pid)
{
    std::ifstream stream;
    std::string line;
    std::string targetuid;

    // First, open the status file of this pid to get the uid of this process
    std::string fullpath = Path::basePath() + pid + Path::statusPath();
    Util::getStream(fullpath, stream);

    // This file has a lot of information, one of which is uid
    // We will read each line until we get to the row with uid info.
    while (std::getline(stream, line)) {
        if (line.substr(0, 4) == "Uid:") {
            targetuid = line.substr(5);
            targetuid = targetuid.substr(0, targetuid.find('\t'));
            break;
        }
    }
    
    stream.close();

    // Now that we have the uid, read /etc/passwd to get the username of this uid
    Util::getStream(Path::etcpasswdPath(), stream);

    // Each line in thie file describes a user, with fields delimited by ':'
    // the 1st field is username, and the 3rd field is uid
    while (std::getline(stream, line)) {
        std::stringstream ssl(line);
        std::string field;
        std::string uid, username;
        int fieldnum = 1;
        while (std::getline(ssl,field,':')) {
            switch (fieldnum) {
                case 1:
                    username = field;
                    break;
                case 3:
                    uid = field;
                    if (uid == targetuid) {
                        return username;
                    }
                    break;
            }
            fieldnum++;
        }
    }
}


std::vector<std::string> ProcessParser::getPidList()
{
    std::vector<std::string> pidlist;

    DIR* proc;
    struct dirent* ent;

    // Try opening /proc/
    if ((proc = opendir(Path::basePath().c_str()))!= NULL) {
        // Go through each entry in the directory
        while ((ent = readdir(proc)) != NULL) {
            std::string entname(ent->d_name);

            // Check if the entry is comprised entirely of digits or not:
            if (entname.find_first_not_of("0123456789") == string::npos) {
                // this is a purely numerical string. It's a pid.
                pidlist.push_back(entname);
            }
        }
    }

    if (closedir(proc) != 0)
    {
        throw std::runtime_error(std::strerror(errno));
    }

    return pidlist;
}

bool ProcessParser::isPidExisting(std::string targetpid) {
    std::vector<std::string> curpidlist = getPidList();

    for (std::string pid : curpidlist) {
        if (pid == targetpid){
            return true;
        }
    }
    return false;
}

std::string ProcessParser::getSysKernelVersion() {
    std::ifstream stream;
    std::string line;
    std::string kernelversion;
    std::string buildversion;

    std::string fullpath = Path::basePath() + Path::versionPath();
    Util::getStream(fullpath, stream);

    // This file contains a single line delimited with space ' '
    int fieldnum = 1;
    while (std::getline(stream, line, ' ')) {
        switch (fieldnum) {
            case 3:
                kernelversion = line;
                break;
            case 4:
                buildversion = line;
                break;
        }
        fieldnum++;
    }

    return (kernelversion + buildversion);
}

std::string ProcessParser::getOSName()
{
    std::ifstream stream;
    std::string line;
    std::string OSVersion;

    std::string fullpath = Path::basePath() + Path::versionPath();
    Util::getStream(fullpath, stream);

    

    // This file contains a single line delimited with space ' '
    int fieldnum = 1;
    while (std::getline(stream, line, ' ')) {
        
        switch (fieldnum) {
            case 9:
                OSVersion += line + " ";
                break;
            case 10:
                OSVersion += line;
                break;
        }
        fieldnum++;
    }

    

    // Remove extra parentheses (one at the beginning, two at the end) 
    OSVersion.erase(0,1);
    OSVersion.erase(OSVersion.length()-2,2);
    return OSVersion;
}

int ProcessParser::getNumberOfCores()
{
    std::ifstream stream;
    std::string line;
    int numcores = 0;

    std::string fullpath = Path::basePath() + Path::cpuInfoPath();
    Util::getStream(fullpath, stream);

    // This file is organized into information blocks about each cpu 
    // One of the lines gives information about the no. of cores on that cpu
    // We just add the numbers on these lines up
    while (std::getline(stream, line)) {
        if (line.substr(0, 11) == "cpu cores	:") {
            numcores ++; //= std::stoi(line.substr(12));
        }
    }
    return numcores;
}

std::vector<std::string> ProcessParser::getSysCpuPercent(std::string coreNumber)
{
    std::ifstream stream;
    std::string line;
    std::vector<std::string> result;

    if (coreNumber == "") {
        coreNumber = " ";
    }

    std::string cpunum = "cpu" + coreNumber;

    std::string fullpath = Path::basePath() + Path::statPath();
    Util::getStream(fullpath, stream);

    while (std::getline(stream, line)) {
        if (line.substr(0, 4) == cpunum) {
            std::stringstream ss(line);

            std::string tok;
            while(std::getline(ss, tok, ' '))
            {
                if (tok != "")
                {
                    result.push_back(tok);
                }
            }
        }
    }

    return result;
}

float getSysActiveCpuTime(vector<string> values)
{
    return (stof(values[S_USER]) +
            stof(values[S_NICE]) +
            stof(values[S_SYSTEM]) +
            stof(values[S_IRQ]) +
            stof(values[S_SOFTIRQ]) +
            stof(values[S_STEAL]) +
            stof(values[S_GUEST]) +
            stof(values[S_GUEST_NICE]));
}

float getSysIdleCpuTime(vector<string>values)
{
    return (stof(values[S_IDLE]) + stof(values[S_IOWAIT]));
}

std::string ProcessParser::PrintCpuStats(std::vector<std::string> values1, std::vector<std::string>values2)
{
    float activeTime = getSysActiveCpuTime(values2) - getSysActiveCpuTime(values1);
    float idleTime = getSysIdleCpuTime(values2) - getSysIdleCpuTime(values1);
    float totalTime = activeTime + idleTime;
    float result = 100.0*(activeTime / totalTime);
    return to_string(result);
}

float ProcessParser::getSysRamPercent()
{
    std::ifstream stream;
    std::string line;
    std::string memavailabletitle = "MemAvailable:";
    float memavailable;
    std::string memfreetitle = "MemFree:";
    float memfree;
    std::string bufferstitle = "Buffers:";
    float buffers;

    std::string fullpath = Path::basePath() + Path::memInfoPath();
    Util::getStream(fullpath, stream);

    while (std::getline(stream, line)) {
        if (line.compare(0,memavailabletitle.size(), memavailabletitle) == 0)
        {
            std::string val = line.substr(memavailabletitle.size()+1);
            val = val.substr(0,val.size()-3);
            memavailable = stof(val);
        }

        if (line.compare(0,memfreetitle.size(), memfreetitle) == 0)
        {
            std::string val = line.substr(memfreetitle.size()+1);
            val = val.substr(0,val.size()-3);
            memfree = stof(val);
        }

        if (line.compare(0,bufferstitle.size(), bufferstitle) == 0)
        {
            std::string val = line.substr(bufferstitle.size()+1);
            val = val.substr(0,val.size()-3);
            buffers = stof(val);
        }
    }

    return (100.0*(1-(memfree/(memavailable - buffers))));
}

int ProcessParser::getTotalNumberOfProcesses()
{
    std::ifstream stream;
    std::string line;
    int numprocesses = 0;

    std::string fullpath = Path::basePath() + Path::statPath();
    Util::getStream(fullpath, stream);

    while (std::getline(stream, line)) {
        if (line.substr(0, 9) == "processes") {
            numprocesses = std::stoi(line.substr(10));
        }
    }
    return numprocesses;
}

int ProcessParser::getNumberOfRunningProcesses()
{
    std::ifstream stream;
    std::string line;
    int numrunningprocesses = 0;

    std::string fullpath = Path::basePath() + Path::statPath();
    Util::getStream(fullpath, stream);

    while (std::getline(stream, line)) {
        if (line.substr(0, 13) == "procs_running") {
            numrunningprocesses = std::stoi(line.substr(14));
        }
    }
    return numrunningprocesses;
}

int ProcessParser::getTotalThreads()
{
    std::vector<std::string> pidlist = getPidList();
    
    int numthreads = 0;

    for (auto pid: pidlist)
    {
        std::ifstream stream;
        std::string line;
        std::string fullpath = Path::basePath() + pid + Path::statusPath();
        Util::getStream(fullpath, stream);

        while (std::getline(stream, line)) {
            if (line.substr(0, 8) == "Threads:") {
                numthreads += std::stoi(line.substr(9));
            }
        }
    }

    return numthreads;
}