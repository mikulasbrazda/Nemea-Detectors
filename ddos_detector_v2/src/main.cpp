/**
 * @file main.cpp
 * @brief This file contains the implementation of the main function, which serves as the entry point of the program.
 * The main function initializes the module_info structure, parses program arguments, and starts the module interfaces.
 * 
 * This file also contains several utility functions used in the program, such as:
 * - isFloat: Checks if a string represents a valid floating-point number.
 * - growth_function: Defines an exponential growth function.
 * - convertSensitivityToMultiplier: Converts a sensitivity value to a multiplier using the growth function.
 * - setTimeManagerMode: Sets the mode of the TimeManager.
 * - convertDurationToSeconds: Converts a duration string to the corresponding number of seconds.
 * - isValidIPAddress: Checks if a string represents a valid IP address.
 * - ipToUInt: Converts an IP address string to an unsigned integer.
 * - cidrToMask: Converts a CIDR prefix to a subnet mask.
 * - ipToBinary: Converts an IP address string to its binary representation.
 * - parseLine: Parses a line of input and extracts the IP address, prefix, and sensitivity.
 * - readFromFile: Reads data from a file and returns it as an optional value.
 * 
 * This file also includes the definition of fields used in unirec templates and the module_info structure.
 * 
 * @author Mikuláš Brázda
 * @date 15.05.2024
 */

#include <iostream>
#include "CountMinSketch.h"
#include <map>
#include "binCountSketchValue.h"
#include <array>
#include "adaptiveCusum.h"
#include <atomic>
#include <mutex>    
#include <thread>
#include "ddosDetector.h"
#include <arpa/inet.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <signal.h>
#include <getopt.h>
#include <inttypes.h>
#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include "fields.h"
#include <unirec/ur_time.h>
#include <timeManager.h>
#include <unistd.h>
#include <filesystem>
#include <vector>
#include <optional>
#include <regex>
#include <fstream>
#include <sstream>
#include "trie.h"


// Took from https://stackoverflow.com/questions/447206/c-isfloat-function
bool isFloat(std::string myString ) {
    std::istringstream iss(myString);
    float f;
    iss >> std::noskipws >> f; // noskipws considers leading whitespace invalid
    // Check the entire string was consumed and if either failbit or badbit is set
    return iss.eof() && !iss.fail(); 
}

// Define the exponential growth function
float growth_function(float x, float a, float b) {
    return a * std::pow(b, x);
}

/**
 * Converts the sensitivity value to a multiplier.
 * 
 * @param sensitivity The sensitivity value to be converted.
 * @return The multiplier value.
 */
float convertSensitivityToMultiplier(float sensitivity) {
    const float a = 100;
    const float b = 0.015;   
    return growth_function(sensitivity, a, b);
}

/**
 * @brief Sets the mode of the TimeManager.
 * 
 * This function sets the mode of the TimeManager based on the provided mode string.
 * The mode can be either "online" or "offline".
 * 
 * @param mode The mode string indicating the desired mode.
 * @return True if the mode was set successfully, false otherwise.
 */
bool setTimeManagerMode(const char* mode) {
    if (strcmp(mode, "online") == 0) {
        TimeManager::setMode(TimeManager::Mode::Online);
    } else if (strcmp(mode, "offline") == 0) {
        TimeManager::setMode(TimeManager::Mode::Offline);
    } else {
        return false;
    }
    return true;
}

/**
 * Converts a duration string to the equivalent number of seconds.
 * The duration string should be in the format "<number><unit>", where <number> is a floating-point number and <unit> is one of the following: 's' for seconds, 'm' for minutes, 'h' for hours, or 'd' for days.
 * 
 * @param duration The duration string to convert.
 * @return The equivalent number of seconds as an integer. Returns -1 if the duration string is invalid.
 */
int convertDurationToSeconds(const std::string& duration) {
    
    // Get the number part of the duration string
    std::string number = duration.substr(0, duration.size() - 1);
    char unit = duration.back(); // Last character is the unit (s, h, or d)
    if (not isFloat(number)) {
        return -1;
    }
    float durationInSeconds = std::stof(number);
    switch (unit) {
        case 's': // Seconds
            break; // durationInSeconds is already in seconds
        case 'm': // Minutes
            durationInSeconds *= 60; // Convert minutes to seconds
            break;
        case 'h': // Hours
            durationInSeconds *= 3600; // Convert hours to seconds
            break;
        case 'd': // Days
            durationInSeconds *= 86400; // Convert days to seconds
            break;
        default: // Invalid format
            return -1;
    }

    return static_cast<int>(std::ceil(durationInSeconds));
}

/**
 * @brief Checks if the given IP address is valid.
 * 
 * This function validates whether the provided IP address is valid or not.
 * It uses the `inet_pton` function to convert the IP address from string format to network address structure.
 * 
 * @param ip The IP address to be validated.
 * @return true if the IP address is valid, false otherwise.
 */
bool isValidIPAddress(const std::string& ip) {
    struct in_addr inAddr;
    return inet_pton(AF_INET, ip.c_str(), &inAddr) == 1;
}

/**
 * Converts an IP address string to an unsigned integer.
 *
 * @param ip The IP address string to convert.
 * @return The unsigned integer representation of the IP address.
 */
unsigned int ipToUInt(const std::string& ip) {
    struct in_addr inAddr;
    inet_pton(AF_INET, ip.c_str(), &inAddr);
    return ntohl(inAddr.s_addr);
}

/**
 * Converts a CIDR (Classless Inter-Domain Routing) notation to a subnet mask.
 * 
 * @param cidr The CIDR value representing the subnet mask.
 * @return The subnet mask as an unsigned integer.
 */
unsigned int cidrToMask(int cidr) {
    return cidr == 0 ? 0 : ~0u << (32 - cidr);
}

/**
 * Converts an IP address to binary representation.
 *
 * @param ip The IP address to convert.
 * @param mask The number of bits to include in the binary representation.
 * @return The binary representation of the IP address.
 * @throws std::invalid_argument if the IP address format is invalid.
 */
std::string ipToBinary(const std::string& ip, int mask) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) {
        throw std::invalid_argument("Invalid IP address format");
    }
    std::string binary = std::bitset<32>(ntohl(addr.s_addr)).to_string();
    return binary.substr(0, mask);  // Only use the first 'mask' bits
}

/**
 * Parses a line of input and extracts the IP address, prefix, and sensitivity.
 * 
 * @param line The line of input to parse.
 * @param record A reference to a std::pair<std::string, float> object where the parsed values will be stored.
 * @return True if the line was successfully parsed, false otherwise.
 */
bool parseLine(const std::string& line, std::pair<std::string, float>& record) {
    std::regex lineRegex(R"(^(\d+\.\d+\.\d+\.\d+)(?:/(\d+))?\s*(\d*(?:\.\d+)?)$)");
    std::smatch matches;

    if (std::regex_match(line, matches, lineRegex)) {
        if (matches.size() == 4 || matches.size() == 5) { // Full match + 3 or 4 groups
            std::string ip = matches[1].str();
            std::string prefixStr = matches[2].str();
            std::string sensitivityStr = matches[3].str();

            int prefix = prefixStr.empty() ? 32 : std::stoi(prefixStr);
            if (prefix < 0 || prefix > 32) {
                std::cerr << "Invalid CIDR prefix in line: " << line << std::endl;
                return false;
            }

            if (!isValidIPAddress(ip)) {
                std::cerr << "Invalid IP address in line: " << line << std::endl;
                return false;
            }

            record.first = ipToBinary(ip, prefix);

            float sensitivity = 0.5; // default value of multiplier is aprox 1.63
            // check if sensitivityStr is a valid float
            if (isFloat(sensitivityStr)) {
                sensitivity = std::stof(sensitivityStr);
            } 
            record.second = convertSensitivityToMultiplier(sensitivity);
            return true;
        }
    }

    std::cerr << "Line format incorrect: " << line << std::endl;
    return false;
}

/**
 * Reads data from a file and returns it as an optional value.
 * 
 * @tparam T The type of data to read from the file.
 * @param filePath The path to the file to read from.
 * @return An optional value containing the data read from the file, or an empty optional if the file cannot be opened or the data cannot be parsed.
 */
template<typename T>
std::optional<T> readFromFile(const std::string& filePath) {
    T result;
    std::ifstream file(filePath);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filePath << std::endl;
        return std::nullopt; // Return an empty optional to indicate failure
    }
    
    std::string line;
    while (std::getline(file, line)) {
        std::pair<std::string, float> record;
        if (parseLine(line, record)) {
            if constexpr (std::is_same_v<T, Trie<float>>) {
                result.insert(record.first, record.second);
            } else {
                result.insert(record.first);
            }
        } else {
            return std::nullopt;
        }
    }
    
    return result;
}


/**
 * Definition of fields used in unirec templates (for both input and output interfaces) in this example basic flow from flow_meter
 */
/*This module functions as a filter of flows forwarded by flow_meter, I need all fields written below to be forwarded to the next module.*/
UR_FIELDS ( 
  ipaddr DST_IP,
  ipaddr SRC_IP,
  uint64 BYTES,
  time TIME_LAST,
  uint32 PACKETS,
  double TH_BYTES,
  double TH_PACKETS,
  double TH_ENTROPY,
  double TH_RECV_SENT_BYTES,
  double TH_RECV_SENT_FLOWS,
  double SH_BYTES,
  double SH_PACKETS,
  double SH_ENTROPY,
  double SH_RECV_SENT_BYTES,
  double SH_RECV_SENT_FLOWS,
  uint32 CUSUM_ID,
  bytes SRC_IPS
)

trap_module_info_t *module_info = NULL;

/**
 * Definition of basic module information - module name, module description, number of input and output interfaces
 */
#define MODULE_BASIC_INFO(BASIC) \
  BASIC("DDoS detection module", \
        "This module serves as an example of module implementation in TRAP platform. It receives UniRec" \
        "with flow from different module (flowmeter). It is a filter, it resends all flows initiated on" \
        "a port and on an address.", 2, 1)
  //BASIC(char *, char *, int, int)

/**
 * Definition of module parameters - every parameter has short_opt, long_opt, description,
 * flag whether an argument is required or it is optional and argument type which is NULL
 * in case the parameter does not need argument.
 * Module parameter argument types: int8, int16, int32, int64, uint8, uint16, uint32, uint64, float, string
 */
#define MODULE_PARAMS(PARAM) \
  PARAM('m', "mode", "Mode valid values are online / offline", required_argument, "char *") \
  PARAM('f', "subnetfile", "File with subnets to protect", required_argument, "string") \
  PARAM('l', "learning", "How long should detector learn", required_argument, "string") \
  PARAM('w', "whitelist", "File with whitelist. Subnetfile is always whitelisted. (default only subnetfile) ", required_argument, "string") \
  PARAM('q', "quantile", "Quantile for the cusum thresholds (default 0.5)", required_argument, "float") \
  PARAM('s', "span", "Span for the CUSUM EWMA (default 16)", required_argument, "int") \
  PARAM('d', "dsketchwidth", "Width of the destination IP sketch (default 1024)", required_argument, "int") \
  PARAM('k', "ssketchwidth", "Width of the source IP sketch (default 32768)", required_argument, "int") \
  PARAM('n', "topn", "Number of topN source IP adresses communicated with the destination IP (default 5)", required_argument, "int") \
  PARAM('t', "interval", "Interval between alerts for the same CUSUM (default 300)", required_argument, "int") \
    //PARAM(char, char *, char *, no_argument  or  required_argument, char *)
/**
 * To define positional parameter ("param" instead of "-m param" or "--mult param"), use the following definition:
 * PARAM('-', "", "Parameter description", required_argument, "string")
 * There can by any argument type mentioned few lines before.
 * This parameter will be listed in Additional parameters in module help output
 */


static int stop = 0;

size_t check_false_positives_seconds = 60;
size_t window_length_seconds = 5;
/**
 * Function to handle SIGTERM and SIGINT signals (used to stop the module)
 */
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1)

int main(int argc, char** argv) {

    /* **** TRAP initialization **** */

    /*
        * Macro allocates and initializes module_info structure according to MODULE_BASIC_INFO and MODULE_PARAMS
        * definitions on the lines 69 and 77 of this file. It also creates a string with short_opt letters for getopt
        * function called "module_getopt_string" and long_options field for getopt_long function in variable "long_options"
        */
    INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
    /*
        * Let TRAP library parse program arguments, extract its parameters and initialize module interfaces
        */
    TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);

    /*
        * Register signal handler.
        */
    TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

    /*
        * Parse program arguments defined by MODULE_PARAMS macro with getopt() function (getopt_long() if available)
        * This macro is defined in config.h file generated by configure script
        */
    signed char opt;
    int ret;
    int lerningSecs = 0;
    int timeBetweenAlerts = 300;
    bool lFlag = false;
    bool fFlag = false;
    bool mFlag = false; 
    float quantile = 0.75;
    float alpha = 0.0769;
    int n = 5;
    float c = 0.5;
    uint32_t span = 60;
    std::string spanStr, nStr;
    
    std::optional<Trie<float>> protectedPrefixes;
    std::optional<Trie<>> whitelistedPrefixes;
        // Define the outer array size
    constexpr size_t outerSizeDstIPs = 3;
    // Define the inner array size
    constexpr size_t innerSizeDstIPs = 1024;
    // Define the outer array size
    constexpr size_t outerSizeSrcIPs = 3;
    // Define the inner array size
    constexpr size_t innerSizeSrcIPs = 32768;

    while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1) {
        switch (opt) {
        case 'm':
            if (not setTimeManagerMode(optarg)) {
                fprintf(stderr, "Invalid mode.\n");
                FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
                TRAP_DEFAULT_FINALIZATION();
                return -1;
            }
            mFlag = true;
            break;
        case 'f':
            if (not std::filesystem::exists(optarg)) {
                fprintf(stderr, "File %s does not exist.\n", optarg);
                FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
                TRAP_DEFAULT_FINALIZATION();
                return -1;	
            }
            protectedPrefixes = readFromFile<Trie<float>>(optarg);
            if (not protectedPrefixes) {
                fprintf(stderr, "Error during parsing file %s\n", optarg);
                FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
                TRAP_DEFAULT_FINALIZATION();
                return -1;
            } 
            if (protectedPrefixes->empty()) {
                fprintf(stderr, "No valid prefixes in file %s\n", optarg);
                FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
                TRAP_DEFAULT_FINALIZATION();
                return -1;
            }
            fFlag = true;
            break;
        case 'l':
            lerningSecs = convertDurationToSeconds(optarg);
            if (lerningSecs == -1) {
                fprintf(stderr, "Invalid duration.\n");
                FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
                TRAP_DEFAULT_FINALIZATION();
                return -1;
            }
            break;
        case 'w':
            if (not std::filesystem::exists(optarg)) {
                fprintf(stderr, "File %s does not exist.\n", optarg);
                FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
                TRAP_DEFAULT_FINALIZATION();
                return -1;	
            }
            whitelistedPrefixes = readFromFile<Trie<>>(optarg);
            if (not whitelistedPrefixes) {
                fprintf(stderr, "Error during parsing file %s\n", optarg);
                FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
                TRAP_DEFAULT_FINALIZATION();
                return -1;
            } 
            break;
        case 'q':
            if (not isFloat(optarg)) {
                fprintf(stderr, "Invalid quantile.\n");
                FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
                TRAP_DEFAULT_FINALIZATION();
                return -1;
            }
            quantile = std::stof(optarg);
            break;
        case 's':
            spanStr = optarg;
            if (not std::all_of(spanStr.begin(), spanStr.end(), ::isdigit)) {
                fprintf(stderr, "Invalid span.\n");
                FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
                TRAP_DEFAULT_FINALIZATION();
                return -1;
            }
            span = std::stoi(spanStr);
            alpha = 1.0f / (span + 1.0f);
            break;

        case 'n':
            nStr = optarg;
            if (not std::all_of(nStr.begin(), nStr.end(), ::isdigit))
            {
                fprintf(stderr, "Invalid topN.\n");
                FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
                TRAP_DEFAULT_FINALIZATION();
                return -1;
            }
            n = std::stoi(nStr);
            break;
        case 't':
            timeBetweenAlerts = convertDurationToSeconds(optarg);
        default:
            fprintf(stderr, "Invalid argument %c.\n", opt);    
            FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
            TRAP_DEFAULT_FINALIZATION();
            return -1;
        }
    }
    if (not mFlag or not fFlag) {
        fprintf(stderr, "-m | --mode and -f | --file are required arguments.\n");
        FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
        TRAP_DEFAULT_FINALIZATION();
        return -1;
    }
    if (lerningSecs == 0 and not std::filesystem::exists("thresholds.csv")) {
        fprintf(stderr, "Learning time is required for the first run. (use -l | --learning)\n");
        FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
        TRAP_DEFAULT_FINALIZATION();
        return -1;    
    }

   /* **** Create UniRec templates **** */
   ur_template_t *in_tmplt = ur_create_input_template(0, "DST_IP,SRC_IP,BYTES,TIME_LAST,PACKETS", NULL);
   if (in_tmplt == NULL){
      fprintf(stderr, "Error: Input template could not be created.\n");
      return -1;
   }

   ur_template_t *out_tmplt = ur_create_bidirectional_template(1,0,"DST_IP,TH_BYTES,TH_PACKETS,TH_ENTROPY,"\
   "TH_RECV_SENT_BYTES, TH_RECV_SENT_FLOWS,SH_BYTES,SH_PACKETS,SH_ENTROPY,"
    "SH_RECV_SENT_BYTES,SH_RECV_SENT_FLOWS,CUSUM_ID,SRC_IPS", NULL);
   if (out_tmplt == NULL){
      ur_free_template(in_tmplt);
      fprintf(stderr, "Error: Output template could not be created.\n");
      return -1;
   }

    ret = trap_ifcctl(TRAPIFC_INPUT, 1, TRAPCTL_SETTIMEOUT, TRAP_NO_WAIT);
    if (ret != TRAP_E_OK) {
        fprintf(stderr, "Error: trap_ifccl failed\n");
        ur_free_template(in_tmplt);
        ur_free_template(out_tmplt);
        return -1;
    }

    netflowRecord_t record;
    ddosDetector detector(protectedPrefixes.value(), whitelistedPrefixes, 
                                lerningSecs, quantile, alpha, span, c,
                                outerSizeDstIPs, innerSizeDstIPs, 
                                outerSizeSrcIPs, innerSizeSrcIPs,
                                n, timeBetweenAlerts);
    bool first = true;
    timePoint currIntervalStart, falsePositiveCheckStart;
    uint32_t windowID = 0;
    while (!stop) {
        const void *in_rec0, *in_rec1;
        void *out_rec;
        uint16_t in_rec0_size, in_rec1_size;

 
        ret = TRAP_RECEIVE(0, in_rec0, in_rec0_size, in_tmplt);

        // Handle possible errors
        TRAP_DEFAULT_RECV_ERROR_HANDLING(ret, continue, break)
        // Check size of received data
        if (in_rec0_size < ur_rec_fixlen_size(in_tmplt)) {
            if (in_rec0_size <= 1) {
                break; // End of data (used for testing purposes)
            } else {
                fprintf(stderr, "Error: data with wrong size received (expected size: >= %hu, received size: %hu)\n",
                        ur_rec_fixlen_size(in_tmplt), in_rec0_size);
                break;
            }
        }

        ip_addr_t* ip = &ur_get(in_tmplt, in_rec0, F_DST_IP);

        if (ip_is4(ip)) {
            record.dstAddr = ip->ui32[2];
        } else {
            continue;
        }
        ip = &ur_get(in_tmplt, in_rec0, F_SRC_IP);
        
        if (ip_is4(ip)) {
            record.srcAddr = ip->ui32[2];
        } else {
            continue;
        }

        ur_time_t time_end;
        record.bytes = ur_get(in_tmplt, in_rec0, F_BYTES);
        record.packets = ur_get(in_tmplt, in_rec0, F_PACKETS);
        time_end = ur_get(in_tmplt, in_rec0, F_TIME_LAST);
        
        timePoint prevTime;

        TimeManager::update(TimeManager::urTimeToTimePoint(time_end));
        timePoint currTime = TimeManager::now();
      
        std::string strIP = inet_ntoa((in_addr)record.srcAddr);
        strIP = inet_ntoa((in_addr)record.dstAddr);
        if (first) {
            first = false;
            detector.runDetectorThread();
            currIntervalStart = currTime;
            windowID++;
            #ifdef DEBUG
            std::cout << windowID <<". Interval starts at: " << TimeManager::timePointToString(currIntervalStart) << std::endl;  
            #endif
        } else {
            if (windowID > 1) {
                detector.processCurrentFlow(record);
            }
            if (currTime >= currIntervalStart + std::chrono::seconds(window_length_seconds)) {
                if (windowID > 1) {
                    detector.notifyWorker();
                }
                currIntervalStart = currTime;
                windowID++;
                #ifdef DEBUG
                std::cout << windowID << ". Interval starts at: " << TimeManager::timePointToString(currIntervalStart) << std::endl;
                #endif
            }
        }
        dos_alert_t alert;
        if (detector.getAlert(alert)) {

            char* srcIPs = new char[alert.srcIPs.size()*4];
            int idx = 0;
            alert.dstIP = htonl(alert.dstIP);
            for (auto ip : alert.srcIPs) {
                memcpy(srcIPs + idx, &ip, 4);
                idx += 4;
            }

            out_rec = ur_create_record(out_tmplt, alert.srcIPs.size()*4);
            ur_set(out_tmplt, out_rec, F_DST_IP, ip_from_int(alert.dstIP));
            ur_set(out_tmplt, out_rec, F_TH_BYTES, alert.thresholdBytes);
            ur_set(out_tmplt, out_rec, F_TH_PACKETS, alert.thresholdPackets);
            ur_set(out_tmplt, out_rec, F_TH_ENTROPY, alert.thresholdEntropy);
            ur_set(out_tmplt, out_rec, F_TH_RECV_SENT_BYTES, alert.thresholdBytesReceivedToSent);
            ur_set(out_tmplt, out_rec, F_TH_RECV_SENT_FLOWS, alert.thresholdFlowsReceivedToSent);
            ur_set(out_tmplt, out_rec, F_SH_BYTES, alert.measuredBytes);
            ur_set(out_tmplt, out_rec, F_SH_PACKETS, alert.measuredPackets);
            ur_set(out_tmplt, out_rec, F_SH_ENTROPY, alert.measuredEntropy);
            ur_set(out_tmplt, out_rec, F_SH_RECV_SENT_BYTES, alert.measuredBytesReceivedToSent);
            ur_set(out_tmplt, out_rec, F_SH_RECV_SENT_FLOWS, alert.measuredFlowsReceivedToSent);
            ur_set(out_tmplt, out_rec, F_CUSUM_ID, alert.cusumID);
            ur_set_var(out_tmplt, out_rec, F_SRC_IPS, srcIPs, alert.srcIPs.size()*4);
            ret = trap_send(0, out_rec, ur_rec_size(out_tmplt, out_rec));
            delete[] srcIPs;
            TRAP_DEFAULT_SEND_ERROR_HANDLING(ret, continue, break);
        }

        if (currTime > falsePositiveCheckStart + std::chrono::seconds(check_false_positives_seconds)) {
            falsePositiveCheckStart = currTime;
            // Receive data from input interface 1.
            // Block if data are not available immediately (unless a timeout is set using trap_ifcctl)
            ret = TRAP_RECEIVE(1, in_rec1, in_rec1_size, out_tmplt);
            TRAP_DEFAULT_RECV_ERROR_HANDLING(ret, continue, continue);
    
            if (in_rec1_size < ur_rec_size(out_tmplt, in_rec1)) {
                if (in_rec1_size <= 1) {
                    continue; // End of data (used for testing purposes)
                } else {
                    fprintf(stderr, "Error: data with wrong size received (expected size: >= %hu, received size: %hu)\n",
                            ur_rec_size(out_tmplt, in_rec1), in_rec1_size);
                    break;
                }
            }
            dos_alert_t false_positive_alert;
            // set the new thresholds to values measured in the false positive alert
            false_positive_alert.measuredBytes = ur_get(out_tmplt, in_rec1, F_SH_BYTES);
            false_positive_alert.measuredPackets = ur_get(out_tmplt, in_rec1, F_SH_PACKETS);
            false_positive_alert.measuredEntropy = ur_get(out_tmplt, in_rec1, F_SH_ENTROPY);
            false_positive_alert.measuredBytesReceivedToSent = ur_get(out_tmplt, in_rec1, F_SH_RECV_SENT_BYTES);
            false_positive_alert.measuredFlowsReceivedToSent = ur_get(out_tmplt, in_rec1, F_SH_RECV_SENT_FLOWS);
            false_positive_alert.cusumID = ur_get(out_tmplt, in_rec1, F_CUSUM_ID);
            false_positive_alert.dstIP = ur_get(in_tmplt, in_rec1, F_DST_IP).ui32[2];
            detector.pushFalsePositive(false_positive_alert);
        }
    }
    /* **** Cleanup **** */

    // Do all necessary cleanup in libtrap before exiting
    TRAP_DEFAULT_FINALIZATION();

    // Release allocated memory for module_info structure
    FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

    // Free unirec templates and output record
    ur_free_template(in_tmplt);
    ur_free_template(out_tmplt);
    ur_finalize();

    return 0;
}
